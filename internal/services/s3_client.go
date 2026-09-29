package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// newS3Client builds the one AWS SDK v2 S3 client shape every provider
// (AWS_S3, DIGITALOCEAN_SPACES, MINIO, S3_COMPATIBLE) uses -- they all
// speak the same S3 API, so the only per-provider differences are
// path-style addressing and a custom endpoint, both expressed as
// s3.Options overrides rather than four separate client implementations
// (plan decision #1).
func newS3Client(conn ObjectStorageConnection) (*s3.Client, error) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(conn.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(conn.AccessKeyID, conn.SecretAccessKey, "")),
		// This client always has an explicit access key/secret/region from
		// the caller, so it must never fall back to the EC2 instance
		// metadata service (IMDS) or auto-probe "am I running on EC2" --
		// besides being pointless here, on a non-EC2 host (every dev
		// machine, most production hosts) that probe is a real network
		// call that can hang for seconds before timing out, which would
		// otherwise make every test-connection/metrics-collection request
		// against a DigitalOcean Spaces/MinIO/generic S3-compatible bucket
		// pay an unpredictable IMDS-timeout tax for no reason.
		config.WithEC2IMDSClientEnableState(imds.ClientDisabled),
		config.WithDefaultsMode(aws.DefaultsModeStandard),
		// A single attempt, no SDK-level retry/backoff: every caller here
		// (TestObjectStorageConnection, CollectObjectStorageMetrics) already
		// wraps the call in its own explicit ConnectTimeout/CommandTimeout
		// and is itself re-run on a fixed interval by the caller (a manual
		// retry click, or the next scheduler cycle) -- the SDK's own
		// standard retryer would otherwise keep retrying a genuinely
		// unreachable/misconfigured endpoint with backoff until that
		// timeout is exhausted on every single probe, which both makes a
		// "down" bucket look far slower to report than it is and -- for
		// the fast metrics cycle specifically -- can starve the
		// collection's own subsequent DB write of any time budget at all.
		config.WithRetryMaxAttempts(1),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		// AWS S3 itself resolves virtual-hosted-style addressing correctly
		// without help; every other provider (DigitalOcean Spaces, MinIO,
		// generic S3-compatible) is far more reliably reached path-style,
		// especially when Endpoint is a bare host:port with no DNS wildcard
		// certificate for <bucket>.<endpoint>.
		if conn.Provider != "AWS_S3" {
			o.UsePathStyle = true
		}
		if conn.Endpoint != "" {
			o.BaseEndpoint = aws.String(conn.Endpoint)
		}
		// TLSSkipVerify is an explicit, per-instance Admin opt-in (mirrors
		// direct_database_adapter.go's redisOptions/postgresConnString use
		// of the same flag) -- needed for a self-signed-cert MinIO/Spaces
		// endpoint in development, never the default.
		if conn.TLSSkipVerify {
			o.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // admin-controlled, explicit opt-in per instance
				},
			}
		}
	})
	return client, nil
}

// newCloudWatchClient builds a CloudWatch client for the same credentials/
// region as newS3Client -- used only for AWS_S3 (spec §10: CloudWatch
// bucket-size/object-count/request metrics are an AWS-specific signal;
// DigitalOcean Spaces/MinIO/generic S3-compatible have no CloudWatch
// equivalent and always use the bounded-listing fallback instead). Unlike
// newS3Client, this never needs UsePathStyle/BaseEndpoint overrides --
// CloudWatch itself is always reached via its own regional AWS endpoint,
// never the target bucket's endpoint -- but shares the same "no IMDS probe,
// single attempt, no SDK retry/backoff" timeout-budget discipline, for
// exactly the same reason (Phase 2's empirically-observed single-call
// timeout-budget starvation bug).
func newCloudWatchClient(conn ObjectStorageConnection) (*cloudwatch.Client, error) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(conn.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(conn.AccessKeyID, conn.SecretAccessKey, "")),
		config.WithEC2IMDSClientEnableState(imds.ClientDisabled),
		config.WithDefaultsMode(aws.DefaultsModeStandard),
		config.WithRetryMaxAttempts(1),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return cloudwatch.NewFromConfig(cfg), nil
}
