package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// ObjectStorageDeepMetricsService collects the expensive, less-frequent
// dimensions for a standalone object storage bucket: the security-facts
// snapshot (versioning/encryption/public-access/object-lock), bucket
// object-count/size (CloudWatch or bounded-listing), storage growth, and
// error-rate -- then syncs the four OBJECT_STORAGE_* recommendation types
// from that evidence. Deliberately separate from ObjectStorageMetricsService
// (the fast/common cycle) -- a slow or failing deep cycle never touches
// connection_status/health_status, which remain the fast cycle's exclusive
// responsibility (mirrors DatabaseDeepMetricsService's own separation
// exactly).
type ObjectStorageDeepMetricsService struct {
	store                   *repository.Store
	credentials             *StandaloneObjectStorageCredentialService
	fastCache               *ObjectStorageMetricsCache
	deepCache               *ObjectStorageDeepMetricsCache
	connectTimeout          time.Duration
	growthWarningPercent    float64
	errorRateWarningPercent float64
	publicAccessSeverity    string
	limiter                 *ObjectStorageConnectionLimiter
}

// NewObjectStorageDeepMetricsService creates an ObjectStorageDeepMetricsService.
// fastCache is the SAME *ObjectStorageMetricsCache the fast-cycle
// ObjectStorageMetricsService writes to (not a second, separate cache) --
// CollectDeep merges its own freshly observed object_count/total_size_bytes
// into it (see ObjectStorageMetricsCache.MergeBucketMetrics) so
// GET .../growth and the dashboard's Objects/Size columns reflect this
// deep cycle's result immediately, without waiting for the next fast tick.
func NewObjectStorageDeepMetricsService(
	store *repository.Store, credentials *StandaloneObjectStorageCredentialService,
	fastCache *ObjectStorageMetricsCache, deepCache *ObjectStorageDeepMetricsCache,
	connectTimeout time.Duration, growthWarningPercent, errorRateWarningPercent float64, publicAccessSeverity string,
) *ObjectStorageDeepMetricsService {
	return &ObjectStorageDeepMetricsService{
		store: store, credentials: credentials, fastCache: fastCache, deepCache: deepCache,
		connectTimeout: connectTimeout, growthWarningPercent: growthWarningPercent,
		errorRateWarningPercent: errorRateWarningPercent, publicAccessSeverity: publicAccessSeverity,
	}
}

// SetConnectionLimiter wires in the shared
// OBJECT_STORAGE_MONITOR_MAX_CONNECTIONS cap -- the SAME limiter instance
// ObjectStorageMetricsService uses, per plan ("deep and fast cycles should
// share one connection cap").
func (s *ObjectStorageDeepMetricsService) SetConnectionLimiter(l *ObjectStorageConnectionLimiter) {
	s.limiter = l
}

// CollectDeep runs one deep-metrics cycle for a single standalone object
// storage bucket. The whole cycle (S3 client calls plus the CloudWatch
// calls the AWS_S3 path adds) is bounded by the shared connectTimeout
// budget, mirroring Phase 2's "one probe worth of timeout budget per fact"
// discipline. Never fails the whole cycle just because one sub-collection
// is unavailable -- see CollectObjectStorageDeepMetrics's own
// failure-isolation guarantee.
func (s *ObjectStorageDeepMetricsService) CollectDeep(ctx context.Context, os generated.ObjectStorage) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.connectTimeout)
	defer cancel()

	hasKey, err := s.credentials.HasSecretKey(ctx, os.ID)
	if err != nil || !hasKey {
		recordObjectStorageMonitoringFailure(ctx, s.store, os.ID, "DEEP", "no credential configured")
		return nil
	}
	secretAccessKey, err := s.credentials.GetSecretKey(ctx, os.ID)
	if err != nil {
		recordObjectStorageMonitoringFailure(ctx, s.store, os.ID, "DEEP", "failed to decrypt credential")
		return nil
	}

	if s.limiter != nil {
		if err := s.limiter.Acquire(ctx); err != nil {
			return nil
		}
		defer s.limiter.Release()
	}

	conn := ObjectStorageConnection{
		Provider: os.Provider, Endpoint: pgutil.TextOrEmpty(os.Endpoint), Region: pgutil.TextOrEmpty(os.Region),
		Bucket: os.Bucket, BasePath: pgutil.TextOrEmpty(os.BasePath), AccessKeyID: pgutil.TextOrEmpty(os.AccessKeyID),
		SecretAccessKey: secretAccessKey, TLSEnabled: os.TlsEnabled, TLSSkipVerify: os.TlsSkipVerify,
		ConnectTimeout: s.connectTimeout, CommandTimeout: s.connectTimeout,
	}

	result, deepErr := CollectObjectStorageDeepMetrics(ctx, conn)
	if deepErr != nil {
		recordObjectStorageMonitoringFailure(ctx, s.store, os.ID, "DEEP", deepErr.Error())
		return nil
	}

	metricsStatus := "COMPLETE"
	if result.Partial || result.Warning != "" {
		metricsStatus = "PARTIAL"
	}

	// Persist the bucket-metrics half (object_count/total_size_bytes/
	// request_count/error_4xx/5xx) onto the SAME shared table the fast
	// cycle writes reachable/latency/error_count to (migration 026's
	// "kept structurally separate at the Go-struct level even though they
	// share a table" design). This row's own reachable/latency/error_count
	// columns stay NULL -- this cycle never re-probes those -- and
	// health_status carries forward the object storage's current,
	// already-known health rather than fabricating a new, independent
	// verdict this cycle never actually computed.
	capturedAt := time.Now()
	_, err = s.store.CreateObjectStorageMetric(ctx, generated.CreateObjectStorageMetricParams{
		ObjectStorageID: os.ID, CapturedAt: pgutil.Timestamptz(capturedAt),
		ObjectCount: int8FromPtr(result.ObjectCount), TotalSizeBytes: int8FromPtr(result.TotalSizeBytes),
		RequestCount: int8FromPtr(result.RequestCount), Error4xxCount: int8FromPtr(result.Error4xxCount), Error5xxCount: int8FromPtr(result.Error5xxCount),
		HealthStatus: os.HealthStatus, MetricsStatus: metricsStatus, MetricDetails: []byte("{}"),
	})
	if err != nil {
		return fmt.Errorf("store object storage bucket metrics: %w", err)
	}

	// Merge into the fast cycle's own cache (never touching
	// BucketReachable/latency/error_count/health, which remain the fast
	// cycle's exclusive responsibility) so GET .../growth and the
	// dashboard's Objects/Size columns reflect this result immediately.
	s.fastCache.MergeBucketMetrics(os.ID, result.ObjectCount, result.TotalSizeBytes, nil)

	// Sync the security-facts snapshot onto object_storages itself so the
	// fast dashboard/detail GET (and GET .../security) never needs to join
	// object_storage_deep_metrics.
	_, _ = s.store.UpdateObjectStorageSecurityFacts(ctx, generated.UpdateObjectStorageSecurityFactsParams{
		ID: os.ID, VersioningStatus: result.VersioningStatus, EncryptionStatus: result.EncryptionStatus,
		PublicAccess: result.PublicAccess, ObjectLockStatus: result.ObjectLockStatus,
	})

	growthBytesPerDay, growthPercent, growthOK := s.computeGrowth(ctx, os.ID, result.TotalSizeBytes)
	errorRatePercent, errorRateOK := s.computeErrorRatePercent(ctx, os.ID, result)

	var growthParam, growthPercentParam, errorRateParam pgtype.Float8
	if growthOK {
		growthParam = pgtype.Float8{Float64: growthBytesPerDay, Valid: true}
		growthPercentParam = pgtype.Float8{Float64: growthPercent, Valid: true}
	}
	if errorRateOK {
		errorRateParam = pgtype.Float8{Float64: errorRatePercent, Valid: true}
	}

	details := map[string]any{}
	if result.Warning != "" {
		details["warning"] = result.Warning
	}
	detailsJSON, _ := json.Marshal(details)

	deepRow, err := s.store.CreateObjectStorageDeepMetric(ctx, generated.CreateObjectStorageDeepMetricParams{
		ObjectStorageID: os.ID, VersioningStatus: pgutil.Text(result.VersioningStatus), EncryptionStatus: pgutil.Text(result.EncryptionStatus),
		PublicAccess: pgutil.Text(result.PublicAccess), ObjectLockStatus: pgutil.Text(result.ObjectLockStatus),
		GrowthBytesPerDay: growthParam, GrowthPercent: growthPercentParam, ErrorRatePercent: errorRateParam,
		Partial: result.Partial, MetricsStatus: metricsStatus, Details: detailsJSON,
	})
	if err != nil {
		return fmt.Errorf("store object storage deep metric: %w", err)
	}

	s.deepCache.Set(os.ID, ObjectStorageDeepMetricsSample{
		VersioningStatus: result.VersioningStatus, EncryptionStatus: result.EncryptionStatus,
		PublicAccess: result.PublicAccess, ObjectLockStatus: result.ObjectLockStatus,
		ObjectCount: result.ObjectCount, TotalSizeBytes: result.TotalSizeBytes,
		GrowthBytesPerDay: pgutil.Float8Ptr(growthParam), GrowthPercent: pgutil.Float8Ptr(growthPercentParam),
		ErrorRatePercent: pgutil.Float8Ptr(errorRateParam), Partial: result.Partial, MetricsStatus: metricsStatus,
	}, deepRow.CapturedAt.Time)

	s.syncRecommendations(ctx, os, result, growthPercent, growthOK, errorRatePercent, errorRateOK)
	recordObjectStorageMonitoringSuccess(ctx, s.store, os.ID, "DEEP", time.Since(start))
	return nil
}

// computeGrowth reuses the exact ComputeGrowthRate pure function
// (database_performance_math.go) -- no new growth math. Only reports a
// rate when GetObjectStorageSizeHistorySince returns genuinely ≥2 samples
// spanning ≥1 hour within the last 7 days (ComputeGrowthRate's own
// requirement) -- absence of enough history means "don't report a rate,"
// never a fabricated one. growthPercent mirrors
// DatabaseDeepMetricsService.syncRecommendations's exact threshold math
// ((bytesPerDay * 7 / currentSize) * 100) -- projected growth over the
// next 7 days as a percentage of the CURRENT size. If currentSize is
// unknown (this cycle's own count/size collection failed entirely), the
// rate is still reported (legitimate on its own, e.g. for GET .../growth)
// but growthPercent is 0 (a real "no honest percent basis," which the
// growth-recommendation threshold comparison never breaches).
func (s *ObjectStorageDeepMetricsService) computeGrowth(ctx context.Context, objectStorageID uuid.UUID, currentSize *int64) (bytesPerDay, percent float64, ok bool) {
	rows, err := s.store.GetObjectStorageSizeHistorySince(ctx, generated.GetObjectStorageSizeHistorySinceParams{
		ObjectStorageID: objectStorageID, CapturedAt: pgutil.Timestamptz(time.Now().Add(-7 * 24 * time.Hour)),
	})
	if err != nil || len(rows) < 2 {
		return 0, 0, false
	}
	samples := make([]SizeSample, 0, len(rows))
	for _, r := range rows {
		if !r.TotalSizeBytes.Valid {
			continue
		}
		samples = append(samples, SizeSample{CapturedAtUnix: r.CapturedAt.Time.Unix(), SizeBytes: r.TotalSizeBytes.Int64})
	}
	rate, rateOK := ComputeGrowthRate(samples)
	if !rateOK {
		return 0, 0, false
	}
	if currentSize == nil || *currentSize <= 0 {
		return rate, 0, true
	}
	return rate, (rate * 7 / float64(*currentSize)) * 100, true
}

// computeErrorRatePercent prefers CloudWatch-provided request/4xx/5xx
// counts (AWS_S3 with request metrics enabled -- a real, published rate
// over this cycle's lookback window) and falls back to the fast cycle's
// own recent HeadBucket reachability history (the fraction of probes that
// failed over the last hour) when CloudWatch didn't provide one -- a real,
// observed rate either way, never fabricated, and never computed from zero
// samples.
func (s *ObjectStorageDeepMetricsService) computeErrorRatePercent(ctx context.Context, objectStorageID uuid.UUID, result ObjectStorageDeepMetricsResult) (float64, bool) {
	if result.RequestCount != nil && *result.RequestCount > 0 {
		var errorCount int64
		if result.Error4xxCount != nil {
			errorCount += *result.Error4xxCount
		}
		if result.Error5xxCount != nil {
			errorCount += *result.Error5xxCount
		}
		return float64(errorCount) / float64(*result.RequestCount) * 100, true
	}

	now := time.Now()
	rows, err := s.store.ListObjectStorageMetricsSince(ctx, generated.ListObjectStorageMetricsSinceParams{
		ObjectStorageID: objectStorageID, CapturedAt: pgutil.Timestamptz(now.Add(-1 * time.Hour)), CapturedAt_2: pgutil.Timestamptz(now), Limit: maxObjectStorageHistoryPointsForErrorRate,
	})
	if err != nil || len(rows) == 0 {
		return 0, false
	}
	var total, failed int
	for _, r := range rows {
		if !r.Reachable.Valid {
			continue
		}
		total++
		if !r.Reachable.Bool {
			failed++
		}
	}
	if total == 0 {
		return 0, false
	}
	return float64(failed) / float64(total) * 100, true
}

// normalizeRecommendationSeverity maps OBJECT_STORAGE_PUBLIC_ACCESS_SEVERITY
// (config.go, plan decision #4's own wording: "WARNING or CRITICAL per
// configured policy") onto recommendations.severity's ACTUAL CHECK-
// constrained vocabulary (LOW/MEDIUM/HIGH/CRITICAL -- migration 016) --
// decision #4's wording borrows the alert-rule severity vocabulary (INFO/
// WARNING/CRITICAL), which is a different scale than the recommendations
// table this value is actually written to. Passing a raw "WARNING"
// straight into that column would violate the CHECK constraint and make
// every public-access upsert silently fail (UpsertRecommendationBySource's
// error is swallowed by upsertObjectStorageRecommendation, mirroring every
// other recommendation helper in this codebase) -- normalizing here, once,
// is far safer than relying on every caller/config value to already match.
func normalizeRecommendationSeverity(configured string) string {
	switch configured {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return configured
	default: // "WARNING", "INFO", or anything else unrecognized.
		return "HIGH"
	}
}

// maxObjectStorageHistoryPointsForErrorRate bounds the fast-cycle-history
// fallback query -- same order of magnitude as every other bounded
// history read in this codebase (e.g. maxObjectStorageHistoryPoints in
// object_storage_metrics.go), never an unbounded scan of the metrics table.
const maxObjectStorageHistoryPointsForErrorRate = 500

// syncRecommendations creates/resolves the four deep-cycle recommendation
// types from real, just-collected evidence -- mirrors
// DatabaseDeepMetricsService.syncRecommendations's exact upsert/resolve-
// per-condition pattern, deduplicated via the same source_type/source_id
// unique index every other recommendation in this project uses.
//
// Every condition below only ever upserts on POSITIVE evidence and only
// ever resolves when the opposite positive evidence is available --
// result.PublicAccess/EncryptionStatus == "UNKNOWN" touches neither
// recommendation (never inferred from absent evidence), and the growth/
// error-rate recommendations are only upserted OR resolved when growthOK/
// errorRateOK is true (absence of history/error data means "don't
// recommend," never "assume healthy" or "assume unhealthy").
func (s *ObjectStorageDeepMetricsService) syncRecommendations(
	ctx context.Context, os generated.ObjectStorage, result ObjectStorageDeepMetricsResult,
	growthPercent float64, growthOK bool, errorRatePercent float64, errorRateOK bool,
) {
	resourceID := os.ResourceID

	switch result.PublicAccess {
	case "PUBLIC":
		upsertObjectStorageRecommendation(ctx, s.store, resourceID, os.ID, "object_storage_public_access", "OBJECT_STORAGE_PUBLIC_ACCESS", normalizeRecommendationSeverity(s.publicAccessSeverity),
			fmt.Sprintf("%s bucket %q allows public access", os.Provider, os.Bucket))
	case "PRIVATE":
		resolveObjectStorageRecommendation(ctx, s.store, "object_storage_public_access", os.ID)
	}

	switch result.EncryptionStatus {
	case "DISABLED":
		upsertObjectStorageRecommendation(ctx, s.store, resourceID, os.ID, "object_storage_encryption_disabled", "OBJECT_STORAGE_ENCRYPTION_DISABLED", "HIGH",
			fmt.Sprintf("%s bucket %q has server-side encryption disabled", os.Provider, os.Bucket))
	case "ENABLED":
		resolveObjectStorageRecommendation(ctx, s.store, "object_storage_encryption_disabled", os.ID)
	}

	if growthOK {
		if growthPercent > s.growthWarningPercent {
			upsertObjectStorageRecommendation(ctx, s.store, resourceID, os.ID, "object_storage_high_growth", "OBJECT_STORAGE_HIGH_GROWTH", "MEDIUM",
				fmt.Sprintf("%s bucket %q is projected to grow %.1f%% over the next 7 days at the current rate", os.Provider, os.Bucket, growthPercent))
		} else {
			resolveObjectStorageRecommendation(ctx, s.store, "object_storage_high_growth", os.ID)
		}
	}

	if errorRateOK {
		if errorRatePercent > s.errorRateWarningPercent {
			upsertObjectStorageRecommendation(ctx, s.store, resourceID, os.ID, "object_storage_high_error_rate", "OBJECT_STORAGE_HIGH_ERROR_RATE", "MEDIUM",
				fmt.Sprintf("%s bucket %q request error rate is %.1f%%", os.Provider, os.Bucket, errorRatePercent))
		} else {
			resolveObjectStorageRecommendation(ctx, s.store, "object_storage_high_error_rate", os.ID)
		}
	}
}
