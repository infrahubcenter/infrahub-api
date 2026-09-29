package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// ObjectStorageMetricsService collects one fast-cycle snapshot for one
// standalone object storage bucket: decrypt its monitoring credential,
// run a single HeadBucket probe (never ListObjectsV2 -- that's Phase 3's
// deep-cycle responsibility), persist, cache, and update the bucket's own
// connection_status/health_status/last_metrics_at. Mirrors
// DatabaseMetricsService's fast-cycle shape, scoped down to object
// storage's much smaller fast-cycle field set (no rate/threshold math --
// there is nothing cumulative to rate-compute from a HeadBucket probe).
type ObjectStorageMetricsService struct {
	store          *repository.Store
	credentials    *StandaloneObjectStorageCredentialService
	cache          *ObjectStorageMetricsCache
	connectTimeout time.Duration // OBJECT_STORAGE_CONNECTION_TIMEOUT, used for both the connect and command phase
	connLimiter    *ObjectStorageConnectionLimiter
}

// NewObjectStorageMetricsService creates an ObjectStorageMetricsService.
func NewObjectStorageMetricsService(
	store *repository.Store, credentials *StandaloneObjectStorageCredentialService, cache *ObjectStorageMetricsCache, connectTimeout time.Duration,
) *ObjectStorageMetricsService {
	return &ObjectStorageMetricsService{store: store, credentials: credentials, cache: cache, connectTimeout: connectTimeout}
}

// SetConnectionLimiter wires in the shared
// OBJECT_STORAGE_MONITOR_MAX_CONNECTIONS cap.
func (s *ObjectStorageMetricsService) SetConnectionLimiter(l *ObjectStorageConnectionLimiter) {
	s.connLimiter = l
}

// CollectOne runs one fast metrics-collection cycle for a single
// standalone object storage bucket. The whole cycle is bounded by
// OBJECT_STORAGE_CONNECTION_TIMEOUT.
func (s *ObjectStorageMetricsService) CollectOne(ctx context.Context, os generated.ObjectStorage) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.connectTimeout)
	defer cancel()

	hasKey, err := s.credentials.HasSecretKey(ctx, os.ID)
	if err != nil || !hasKey {
		s.recordUnavailable(ctx, os.ID, ObjectStorageStatusUnknown, "no credential configured")
		return nil
	}
	secretAccessKey, err := s.credentials.GetSecretKey(ctx, os.ID)
	if err != nil {
		s.recordUnavailable(ctx, os.ID, ObjectStorageStatusUnknown, "failed to decrypt credential")
		return nil
	}

	if s.connLimiter != nil {
		if err := s.connLimiter.Acquire(ctx); err != nil {
			return nil
		}
		defer s.connLimiter.Release()
	}

	conn := ObjectStorageConnection{
		Provider: os.Provider, Endpoint: pgutil.TextOrEmpty(os.Endpoint), Region: pgutil.TextOrEmpty(os.Region),
		Bucket: os.Bucket, BasePath: pgutil.TextOrEmpty(os.BasePath), AccessKeyID: pgutil.TextOrEmpty(os.AccessKeyID),
		SecretAccessKey: secretAccessKey, TLSEnabled: os.TlsEnabled, TLSSkipVerify: os.TlsSkipVerify,
		ConnectTimeout: s.connectTimeout, CommandTimeout: s.connectTimeout,
	}

	// A single HeadBucket probe drives both the fast-cycle metrics sample
	// AND the bucket's 8-value connection_status classification (via
	// ObjectStorageConnectionStatusFromError on the same result), mirroring
	// DatabaseMetricsService.CollectOne's single-call shape exactly.
	// Earlier revisions called TestObjectStorageConnection AND
	// CollectObjectStorageMetrics as two separate HeadBucket attempts under
	// one shared connectTimeout budget; against a genuinely unreachable
	// endpoint the AWS SDK's own retry/backoff can consume an entire
	// configured timeout on a SINGLE call (observed empirically: a single
	// HeadBucket against an unreachable fixture endpoint took the full
	// configured timeout), so two sequential attempts under one shared
	// deadline reliably starved the DB write below of any time budget at
	// all. One probe, reused for both outputs, avoids that entirely.
	result, metricsErr := CollectObjectStorageMetrics(ctx, conn)
	connStatus := ObjectStorageConnectionStatusFromError(metricsErr)
	health := ComputeObjectStorageHealth(connStatus)
	_, _ = s.store.UpdateObjectStorageConnectionStatus(ctx, generated.UpdateObjectStorageConnectionStatusParams{
		ID: os.ID, ConnectionStatus: string(connStatus), HealthStatus: string(health),
	})

	metricsStatus := "COMPLETE"
	if metricsErr != nil {
		metricsStatus = "FAILED"
	}

	capturedAt := time.Now()
	_, err = s.store.CreateObjectStorageMetric(ctx, generated.CreateObjectStorageMetricParams{
		ObjectStorageID: os.ID, CapturedAt: pgutil.Timestamptz(capturedAt),
		Reachable: pgutil.BoolFromPtr(result.BucketReachable), LatencyMs: float8FromPtr(result.RequestLatencyMs), ErrorCount: int4FromPtr(result.ErrorCount),
		HealthStatus: string(health), MetricsStatus: metricsStatus, MetricDetails: []byte("{}"),
	})
	if err != nil {
		return fmt.Errorf("store object storage metric: %w", err)
	}

	// Preserve whatever object_count/total_size_bytes/requests_per_min the
	// deep cycle (Step 17 Phase 3) most recently observed -- this fast
	// cycle's own result never carries those fields (see
	// ObjectStorageMetricsResult's doc comment), and a naive full-replace
	// cache.Set here would otherwise wipe them back to nil on every single
	// fast tick (default every 60s), starving GET .../growth and the
	// dashboard's Objects/Size columns down to "never collected" between
	// deep cycles (default every 5m).
	sample := ObjectStorageMetricsSample{
		BucketReachable: result.BucketReachable, RequestLatencyMs: result.RequestLatencyMs, ErrorCount: result.ErrorCount,
		HealthStatus: health, MetricsStatus: metricsStatus,
	}
	if prev, ok := s.cache.Get(os.ID); ok {
		sample.ObjectCount, sample.TotalSizeBytes, sample.RequestsPerMin = prev.Snapshot.ObjectCount, prev.Snapshot.TotalSizeBytes, prev.Snapshot.RequestsPerMin
	}
	s.cache.Set(os.ID, sample, capturedAt)

	if metricsErr != nil {
		recordObjectStorageMonitoringFailure(ctx, s.store, os.ID, "FAST", metricsErr.Error())
	} else {
		recordObjectStorageMonitoringSuccess(ctx, s.store, os.ID, "FAST", time.Since(start))
	}
	return nil
}

// recordUnavailable persists a FAILED metric snapshot and
// connection/health status when a cycle can't even attempt a connection
// (missing/undecryptable credential) -- mirrors
// DatabaseMetricsService.recordUnavailable exactly.
func (s *ObjectStorageMetricsService) recordUnavailable(ctx context.Context, objectStorageID uuid.UUID, status ObjectStorageConnectionStatus, reason string) {
	defer recordObjectStorageMonitoringFailure(ctx, s.store, objectStorageID, "FAST", reason)
	health := ComputeObjectStorageHealth(status)
	_, _ = s.store.UpdateObjectStorageConnectionStatus(ctx, generated.UpdateObjectStorageConnectionStatusParams{
		ID: objectStorageID, ConnectionStatus: string(status), HealthStatus: string(health),
	})
	capturedAt := time.Now()
	_, err := s.store.CreateObjectStorageMetric(ctx, generated.CreateObjectStorageMetricParams{
		ObjectStorageID: objectStorageID, CapturedAt: pgutil.Timestamptz(capturedAt), HealthStatus: string(health), MetricsStatus: "FAILED", MetricDetails: []byte("{}"),
	})
	if err == nil {
		sample := ObjectStorageMetricsSample{HealthStatus: health, MetricsStatus: "FAILED"}
		if prev, ok := s.cache.Get(objectStorageID); ok {
			sample.ObjectCount, sample.TotalSizeBytes, sample.RequestsPerMin = prev.Snapshot.ObjectCount, prev.Snapshot.TotalSizeBytes, prev.Snapshot.RequestsPerMin
		}
		s.cache.Set(objectStorageID, sample, capturedAt)
	}
}
