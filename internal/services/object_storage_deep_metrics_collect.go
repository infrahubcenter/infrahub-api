package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
)

// objectStorageDeepListMaxPages bounds the bounded-listing fallback (used
// when CloudWatch is unavailable/not applicable) to at most this many
// ListObjectsV2 pages -- at up to 1,000 keys per page, that's a hard cap of
// 20,000 keys inspected per deep cycle, regardless of how large the real
// bucket is. This is a deliberate, fixed, documented limit (plan
// constraint: "no unbounded bucket scans, ever") -- if the cap is hit
// before the listing finishes, the result is marked Partial and the
// returned count/size are a real but honest UNDERCOUNT, never presented as
// the bucket's true total.
const objectStorageDeepListMaxPages = 20

// objectStorageCloudWatchLookback is how far back CollectObjectStorageDeepMetrics
// looks for AWS/S3 storage metrics. Those metrics (BucketSizeBytes,
// NumberOfObjects) are published once per day, with a well-documented
// real-world publication delay of roughly 24-48h -- so "now" almost never
// has a fresh data point, and a 2-day window is the minimum that reliably
// contains the most recently published one. This is NOT a real-time
// number: callers must treat it (and present it) as "as of the last daily
// CloudWatch publication," never as current-second accuracy.
const objectStorageCloudWatchLookback = 2 * 24 * time.Hour

// CollectObjectStorageDeepMetrics runs one deep-cycle collection for a
// standalone object storage bucket: the bucket security-facts snapshot
// (versioning/encryption/public-access/object-lock) for every provider,
// plus best-effort object count/size (and, for AWS S3 only, request/4xx/5xx
// counts) via CloudWatch or a bounded ListObjectsV2 fallback.
//
// Every one of the four security-fact probes below is fully independent:
// each gets its own slice of conn's timeout budget, and a single probe's
// failure sets ONLY that field to "UNKNOWN" (result.Warning records why)
// -- it never aborts the others or the whole cycle. This mirrors both the
// plan's explicit failure-isolation requirement and Phase 2's own
// established "one probe worth of timeout budget per fact, be honest about
// what you don't know" discipline (s3_client.go's single-retry-attempt
// client, CollectObjectStorageMetrics's single HeadBucket call).
//
// The returned error is non-nil only for a totally fatal, cycle-wide
// failure (e.g. building the S3 client itself failed) -- a partial
// collection where some but not all sub-probes failed returns a nil error
// with Partial=true and Warning describing what went wrong, exactly like
// CollectDirectDeepMetrics's own DeepMetricsResult.Partial/Warning shape.
func CollectObjectStorageDeepMetrics(ctx context.Context, conn ObjectStorageConnection) (ObjectStorageDeepMetricsResult, error) {
	result := ObjectStorageDeepMetricsResult{
		VersioningStatus: "UNKNOWN", EncryptionStatus: "UNKNOWN", PublicAccess: "UNKNOWN", ObjectLockStatus: "UNKNOWN",
	}

	timeout := conn.CommandTimeout
	if timeout <= 0 {
		timeout = conn.ConnectTimeout
	}

	client, err := newS3Client(conn)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrObjectStorageConnection, err)
	}

	// ctx's own parent deadline (set by the caller -- ObjectStorageDeepMetricsService.
	// CollectDeep derives it from OBJECT_STORAGE_CONNECTION_TIMEOUT) is the
	// hard backstop for the WHOLE cycle, but that alone isn't enough: this
	// cycle makes up to five sequential security-fact calls (versioning,
	// encryption, public-access -- which can cost a second
	// GetBucketPolicyStatus call -- and object-lock) before ever reaching
	// object-count collection, and without also capping each individual
	// probe's OWN local timeout, a single hanging call could consume the
	// ENTIRE remaining budget and starve every fact after it of any chance
	// to even attempt its own call -- exactly the failure mode Phase 2 fixed
	// for the fast cycle's two sequential HeadBucket attempts. probeTimeout
	// gives each of those five calls a bounded slice instead; the
	// CloudWatch/bounded-listing phase that follows still gets the fuller
	// `timeout` value (object count/size collection is already separately
	// bounded by its own 20-page cap, and legitimately benefits from more
	// time per call against a real bucket) -- ctx's own remaining deadline
	// still clamps it either way.
	probeTimeout := timeout / 6
	if probeTimeout <= 0 {
		probeTimeout = timeout
	}

	var warnings []string
	addWarning := func(fact string, err error) {
		warnings = append(warnings, fact+": "+classifyObjectStorageError(err).Error())
	}

	// --- Versioning ---
	func() {
		vctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		out, err := client.GetBucketVersioning(vctx, &s3.GetBucketVersioningInput{Bucket: &conn.Bucket})
		if err != nil {
			addWarning("versioning", err)
			return
		}
		switch out.Status {
		case s3types.BucketVersioningStatusEnabled:
			result.VersioningStatus = "ENABLED"
		default:
			// Suspended, or empty (never configured) -- both are a real,
			// known fact ("not currently enabled"), never an unknown.
			result.VersioningStatus = "DISABLED"
		}
	}()

	// --- Encryption ---
	func() {
		ectx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		_, err := client.GetBucketEncryption(ectx, &s3.GetBucketEncryptionInput{Bucket: &conn.Bucket})
		if err != nil {
			// ServerSideEncryptionConfigurationNotFoundError means the
			// bucket genuinely has no default encryption configured -- a
			// real, known fact, not a probe failure.
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError" {
				result.EncryptionStatus = "DISABLED"
				return
			}
			addWarning("encryption", err)
			return
		}
		result.EncryptionStatus = "ENABLED"
	}()

	// --- Public access ---
	func() {
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		pabOut, pabErr := client.GetPublicAccessBlock(pctx, &s3.GetPublicAccessBlockInput{Bucket: &conn.Bucket})
		if pabErr == nil && pabOut.PublicAccessBlockConfiguration != nil {
			cfg := pabOut.PublicAccessBlockConfiguration
			if boolPtrTrue(cfg.BlockPublicAcls) && boolPtrTrue(cfg.BlockPublicPolicy) && boolPtrTrue(cfg.IgnorePublicAcls) && boolPtrTrue(cfg.RestrictPublicBuckets) {
				// All four block settings on is a definitive, authoritative
				// PRIVATE answer -- no need for the fallback call below.
				result.PublicAccess = "PRIVATE"
				return
			}
		}
		// GetPublicAccessBlock either isn't available (commonly returns
		// NoSuchPublicAccessBlockConfiguration when never configured) or
		// didn't give a definitive PRIVATE verdict -- fall back to
		// GetBucketPolicyStatus, S3's other public-access signal, per the
		// plan's explicit two-call fallback chain. Only if BOTH calls fail
		// (or return no definitive answer) does this stay UNKNOWN.
		sctx, cancel2 := context.WithTimeout(ctx, probeTimeout)
		defer cancel2()
		statusOut, statusErr := client.GetBucketPolicyStatus(sctx, &s3.GetBucketPolicyStatusInput{Bucket: &conn.Bucket})
		if statusErr != nil {
			// Report whichever call actually carries a meaningful error --
			// prefer the PublicAccessBlock error if that's the one that
			// failed outright (a real permission/config problem) over the
			// PolicyStatus fallback's own failure.
			if pabErr != nil {
				addWarning("public_access", pabErr)
			} else {
				addWarning("public_access", statusErr)
			}
			return
		}
		if statusOut.PolicyStatus != nil && statusOut.PolicyStatus.IsPublic != nil {
			if *statusOut.PolicyStatus.IsPublic {
				result.PublicAccess = "PUBLIC"
			} else {
				result.PublicAccess = "PRIVATE"
			}
		}
	}()

	// --- Object Lock ---
	func() {
		octx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		out, err := client.GetObjectLockConfiguration(octx, &s3.GetObjectLockConfigurationInput{Bucket: &conn.Bucket})
		if err != nil {
			// ObjectLockConfigurationNotFoundError means Object Lock was
			// never enabled for this bucket (it can only be enabled at
			// bucket creation) -- a real, known fact, not a probe failure.
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ObjectLockConfigurationNotFoundError" {
				result.ObjectLockStatus = "DISABLED"
				return
			}
			addWarning("object_lock", err)
			return
		}
		if out.ObjectLockConfiguration != nil && out.ObjectLockConfiguration.ObjectLockEnabled == s3types.ObjectLockEnabledEnabled {
			result.ObjectLockStatus = "ENABLED"
		} else {
			result.ObjectLockStatus = "DISABLED"
		}
	}()

	// --- Object count / size / requests ---
	// AWS S3 tries CloudWatch first (cheap, no bucket scan); every provider
	// (including AWS S3 when CloudWatch is denied/unavailable) falls back
	// to the bounded ListObjectsV2 fallback -- never an unbounded scan.
	cloudWatchOK := false
	if conn.Provider == "AWS_S3" {
		if err := collectCloudWatchBucketMetrics(ctx, conn, &result, timeout); err != nil {
			// Raw text, not classifyObjectStorageError -- this is a plain
			// diagnostic note (CloudWatch access denied, no datapoints yet,
			// etc), not a connection-status outcome to classify.
			warnings = append(warnings, "cloudwatch: "+err.Error())
		} else {
			cloudWatchOK = true
		}
	}
	if !cloudWatchOK {
		if err := collectBoundedListingMetrics(ctx, client, conn, &result, timeout); err != nil {
			warnings = append(warnings, "bucket_scan: "+err.Error())
		}
	}

	if len(warnings) > 0 {
		result.Partial = true
		result.Warning = strings.Join(warnings, "; ")
	}
	return result, nil
}

func boolPtrTrue(v *bool) bool {
	return v != nil && *v
}

// collectCloudWatchBucketMetrics fetches AWS/S3's daily BucketSizeBytes/
// NumberOfObjects storage metrics, plus (best-effort, since request
// metrics require an opt-in per-bucket configuration most buckets never
// enable) request/4xx/5xx counts. Returns an error only when the storage
// metrics themselves could not be retrieved at all (e.g. cloudwatch:
// GetMetricData denied) -- the caller then falls back to bounded listing.
// A missing/empty request-metrics result is NOT an error: it's the
// legitimately common case of a bucket that never had request metrics
// enabled, so RequestCount/Error4xxCount/Error5xxCount are simply left nil.
func collectCloudWatchBucketMetrics(ctx context.Context, conn ObjectStorageConnection, result *ObjectStorageDeepMetricsResult, timeout time.Duration) error {
	cwClient, err := newCloudWatchClient(conn)
	if err != nil {
		return err
	}

	end := time.Now()
	start := end.Add(-objectStorageCloudWatchLookback)
	period := int32(86400) // daily granularity -- these are AWS/S3 storage metrics, not real-time.

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	storageOut, err := cwClient.GetMetricData(cctx, &cloudwatch.GetMetricDataInput{
		StartTime: &start, EndTime: &end,
		MetricDataQueries: []cwtypes.MetricDataQuery{
			cloudWatchS3Query("size", "BucketSizeBytes", conn.Bucket, "StandardStorage", period),
			cloudWatchS3Query("count", "NumberOfObjects", conn.Bucket, "AllStorageTypes", period),
		},
	})
	if err != nil {
		return err
	}
	for _, r := range storageOut.MetricDataResults {
		if len(r.Values) == 0 {
			continue
		}
		v := int64(r.Values[0])
		switch aws.ToString(r.Id) {
		case "size":
			result.TotalSizeBytes = &v
		case "count":
			result.ObjectCount = &v
		}
	}
	if result.TotalSizeBytes == nil && result.ObjectCount == nil {
		return errors.New("no CloudWatch datapoints returned for BucketSizeBytes/NumberOfObjects (metrics may not have published yet, or access is denied)")
	}

	// Best-effort request/error metrics -- request metrics must be
	// explicitly enabled per-bucket (with a filter id, conventionally
	// "EntireBucket" for a whole-bucket configuration) and are NOT enabled
	// by default, so any error or empty result here is expected and never
	// escalated to the caller.
	rctx, rcancel := context.WithTimeout(ctx, timeout)
	defer rcancel()
	requestOut, err := cwClient.GetMetricData(rctx, &cloudwatch.GetMetricDataInput{
		StartTime: &start, EndTime: &end,
		MetricDataQueries: []cwtypes.MetricDataQuery{
			cloudWatchS3RequestQuery("requests", "AllRequests", conn.Bucket, period),
			cloudWatchS3RequestQuery("err4xx", "4xxErrors", conn.Bucket, period),
			cloudWatchS3RequestQuery("err5xx", "5xxErrors", conn.Bucket, period),
		},
	})
	if err != nil {
		return nil //nolint:nilerr // request metrics are optional; only the storage metrics above are load-bearing.
	}
	for _, r := range requestOut.MetricDataResults {
		if len(r.Values) == 0 {
			continue
		}
		v := int64(r.Values[0])
		switch aws.ToString(r.Id) {
		case "requests":
			result.RequestCount = &v
		case "err4xx":
			result.Error4xxCount = &v
		case "err5xx":
			result.Error5xxCount = &v
		}
	}
	return nil
}

func cloudWatchS3Query(id, metricName, bucket, storageType string, period int32) cwtypes.MetricDataQuery {
	return cwtypes.MetricDataQuery{
		Id: aws.String(id),
		MetricStat: &cwtypes.MetricStat{
			Metric: &cwtypes.Metric{
				Namespace: aws.String("AWS/S3"), MetricName: aws.String(metricName),
				Dimensions: []cwtypes.Dimension{
					{Name: aws.String("BucketName"), Value: aws.String(bucket)},
					{Name: aws.String("StorageType"), Value: aws.String(storageType)},
				},
			},
			Period: aws.Int32(period), Stat: aws.String("Average"),
		},
	}
}

func cloudWatchS3RequestQuery(id, metricName, bucket string, period int32) cwtypes.MetricDataQuery {
	return cwtypes.MetricDataQuery{
		Id: aws.String(id),
		MetricStat: &cwtypes.MetricStat{
			Metric: &cwtypes.Metric{
				Namespace: aws.String("AWS/S3"), MetricName: aws.String(metricName),
				Dimensions: []cwtypes.Dimension{
					{Name: aws.String("BucketName"), Value: aws.String(bucket)},
					// "EntireBucket" is the conventional FilterId an Admin
					// uses when enabling request metrics for a whole bucket
					// (rather than a specific prefix) -- if no such filter
					// was ever configured, CloudWatch simply returns no
					// data points for this query, which this function's
					// caller already treats as "not available," never an
					// error.
					{Name: aws.String("FilterId"), Value: aws.String("EntireBucket")},
				},
			},
			Period: aws.Int32(period), Stat: aws.String("Sum"),
		},
	}
}

// collectBoundedListingMetrics estimates object count/size via a
// page-capped ListObjectsV2 walk -- the only path to any count/size number
// at all for DIGITALOCEAN_SPACES/MINIO/S3_COMPATIBLE (no CloudWatch
// equivalent exists there), and AWS S3's own fallback when CloudWatch is
// unavailable. Capped at objectStorageDeepListMaxPages pages; if the cap is
// hit before the bucket is fully listed, the returned counts are marked
// Partial=true and are a real but honest UNDERCOUNT -- never presented as
// the bucket's true total. Never lists more than that fixed number of
// pages under any circumstances.
func collectBoundedListingMetrics(ctx context.Context, client *s3.Client, conn ObjectStorageConnection, result *ObjectStorageDeepMetricsResult, timeout time.Duration) error {
	var count, size int64
	var token *string
	for page := 0; page < objectStorageDeepListMaxPages; page++ {
		lctx, cancel := context.WithTimeout(ctx, timeout)
		out, err := client.ListObjectsV2(lctx, &s3.ListObjectsV2Input{Bucket: &conn.Bucket, ContinuationToken: token})
		cancel()
		if err != nil {
			if page > 0 {
				// Keep whatever was collected across earlier successful
				// pages -- a real, honest partial count -- rather than
				// discarding it because a later page failed.
				result.ObjectCount = &count
				result.TotalSizeBytes = &size
				result.Partial = true
			}
			return err
		}
		for _, obj := range out.Contents {
			count++
			if obj.Size != nil {
				size += *obj.Size
			}
		}
		if out.IsTruncated == nil || !*out.IsTruncated || out.NextContinuationToken == nil {
			result.ObjectCount = &count
			result.TotalSizeBytes = &size
			return nil
		}
		token = out.NextContinuationToken
	}
	// Cap hit before reaching the end of the bucket.
	result.ObjectCount = &count
	result.TotalSizeBytes = &size
	result.Partial = true
	return fmt.Errorf("bounded listing hit its %d-page cap before reaching the end of the bucket -- object_count/total_size_bytes are an undercount", objectStorageDeepListMaxPages)
}
