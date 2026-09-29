-- +goose Up

-- Step 17 Phase 3: object_storage_deep_metrics needs a persisted,
-- queryable error-rate-percent value so the alert engine's
-- MetricObjectStorageErrorRatePercent lookup (alert_metric_lookup.go) can
-- read an already-collected value on its own evaluation cadence, rather
-- than the deep-metrics collector's in-memory error-rate computation
-- (CloudWatch 4xx/5xx over request_count when available, else a recent
-- fast-cycle HeadBucket-failure-rate fallback) being thrown away after
-- only driving the OBJECT_STORAGE_HIGH_ERROR_RATE recommendation sync.
-- Migration 026 didn't anticipate this column because Phase 1/2 never
-- computed an error rate at all -- this is new functionality Phase 3
-- introduces, not a name/value mismatch to backfill.
ALTER TABLE object_storage_deep_metrics ADD COLUMN error_rate_percent double precision;

-- +goose Down

ALTER TABLE object_storage_deep_metrics DROP COLUMN error_rate_percent;
