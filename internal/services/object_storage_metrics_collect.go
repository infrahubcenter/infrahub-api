package services

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// CollectObjectStorageMetrics runs one fast-cycle metrics collection for a
// standalone object storage bucket: a single HeadBucket call only -- never
// ListObjectsV2 or any other bucket-listing API. Object count/size
// collection is explicitly Phase 3's deep-cycle responsibility and must
// never be pulled forward into this fast cycle.
//
// Measures round-trip latency around the HeadBucket call itself and always
// returns a result -- BucketReachable/ErrorCount reflect exactly what was
// observed, even on failure (a real "false"/"1", never a fabricated
// value) -- alongside a classified error the caller can use for its own
// connection-status bookkeeping (via ObjectStorageConnectionStatusFromError).
func CollectObjectStorageMetrics(ctx context.Context, conn ObjectStorageConnection) (ObjectStorageMetricsResult, error) {
	timeout := conn.CommandTimeout
	if timeout <= 0 {
		timeout = conn.ConnectTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := newS3Client(conn)
	if err != nil {
		classified := fmt.Errorf("%w: %v", ErrObjectStorageConnection, err)
		return ObjectStorageMetricsResult{}, classified
	}

	start := time.Now()
	_, headErr := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &conn.Bucket})
	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

	reachable := headErr == nil
	errorCount := int64(0)
	if headErr != nil {
		errorCount = 1
	}
	result := ObjectStorageMetricsResult{
		BucketReachable:  &reachable,
		RequestLatencyMs: &latencyMs,
		ErrorCount:       &errorCount,
	}
	return result, classifyObjectStorageError(headErr)
}
