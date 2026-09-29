package services

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// Reuses fakeS3Server/testConn from object_storage_adapter_test.go (Phase
// 1) rather than duplicating the in-process fake-S3 setup.

func TestCollectObjectStorageMetrics_Success(t *testing.T) {
	srv := fakeS3Server(t, http.StatusOK, "")
	result, err := CollectObjectStorageMetrics(context.Background(), testConn(t, srv.URL))
	if err != nil {
		t.Fatalf("CollectObjectStorageMetrics: %v", err)
	}
	if result.BucketReachable == nil || !*result.BucketReachable {
		t.Errorf("BucketReachable = %v, want true", result.BucketReachable)
	}
	if result.RequestLatencyMs == nil {
		t.Errorf("RequestLatencyMs = nil, want a measured round-trip latency")
	} else if *result.RequestLatencyMs < 0 {
		t.Errorf("RequestLatencyMs = %v, want >= 0", *result.RequestLatencyMs)
	}
	if result.ErrorCount == nil || *result.ErrorCount != 0 {
		t.Errorf("ErrorCount = %v, want 0", result.ErrorCount)
	}
}

func TestCollectObjectStorageMetrics_Failure_StillReturnsObservedResult(t *testing.T) {
	// A HeadBucket failure must still yield a real, collected result
	// (BucketReachable=false, ErrorCount=1 -- observed, not fabricated),
	// alongside the classified error for the caller's own connection-status
	// bookkeeping.
	srv := fakeS3Server(t, http.StatusForbidden, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
	result, err := CollectObjectStorageMetrics(context.Background(), testConn(t, srv.URL))
	if !errors.Is(err, ErrObjectStorageAccessDenied) {
		t.Errorf("err = %v, want wrapping ErrObjectStorageAccessDenied", err)
	}
	if result.BucketReachable == nil || *result.BucketReachable {
		t.Errorf("BucketReachable = %v, want false", result.BucketReachable)
	}
	if result.ErrorCount == nil || *result.ErrorCount != 1 {
		t.Errorf("ErrorCount = %v, want 1", result.ErrorCount)
	}
	if result.RequestLatencyMs == nil {
		t.Errorf("RequestLatencyMs = nil, want a measured round-trip latency even on failure")
	}
}

func TestComputeObjectStorageHealth(t *testing.T) {
	cases := []struct {
		status ObjectStorageConnectionStatus
		want   HealthStatus
	}{
		{ObjectStorageStatusConnected, HealthHealthy},
		{ObjectStorageStatusUnknown, HealthUnknown},
		{ObjectStorageStatusAuthFailed, HealthCritical},
		{ObjectStorageStatusAccessDenied, HealthCritical},
		{ObjectStorageStatusNotFound, HealthCritical},
		{ObjectStorageStatusTimeout, HealthCritical},
		{ObjectStorageStatusTLSError, HealthCritical},
		{ObjectStorageStatusUnavailable, HealthCritical},
	}
	for _, c := range cases {
		if got := ComputeObjectStorageHealth(c.status); got != c.want {
			t.Errorf("ComputeObjectStorageHealth(%v) = %v, want %v", c.status, got, c.want)
		}
	}
}
