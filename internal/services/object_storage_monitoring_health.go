package services

import (
	"context"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// recordObjectStorageMonitoringSuccess/recordObjectStorageMonitoringFailure
// implement collector self-observability for object storage: every fast
// (tier="FAST") collection attempt updates object_storage_monitoring_health,
// success or failure, so an Admin can see the *collector* is stuck without
// that ever being confused with the *bucket* being unreachable --
// connection_status/health_status on object_storages already cover that,
// independently. Mirrors recordMonitoringSuccess/recordMonitoringFailure
// (database_monitoring_health.go) exactly. Errors here are swallowed
// (best-effort observability, never allowed to fail the collection cycle
// itself).
func recordObjectStorageMonitoringSuccess(ctx context.Context, store *repository.Store, objectStorageID uuid.UUID, tier string, duration time.Duration) {
	_ = store.RecordObjectStorageMonitoringSuccess(ctx, generated.RecordObjectStorageMonitoringSuccessParams{
		ObjectStorageID: objectStorageID, Tier: tier, LastDurationMs: pgutil.Int4(int32(duration.Milliseconds())),
	})
}

func recordObjectStorageMonitoringFailure(ctx context.Context, store *repository.Store, objectStorageID uuid.UUID, tier, reason string) {
	_ = store.RecordObjectStorageMonitoringFailure(ctx, generated.RecordObjectStorageMonitoringFailureParams{
		ObjectStorageID: objectStorageID, Tier: tier, LastError: pgutil.Text(reason),
	})
}

// upsertObjectStorageRecommendation/resolveObjectStorageRecommendation are
// the object-storage-flavored wrappers around Step 7's exact
// UpsertRecommendationBySource/ResolveRecommendationBySource queries --
// mirrors upsertDatabaseRecommendation/resolveDatabaseRecommendation
// (this same file's Database counterpart) exactly, used by
// ObjectStorageDeepMetricsService.syncRecommendations, keyed by
// source_type + the object storage's own row ID for natural dedup.
func upsertObjectStorageRecommendation(ctx context.Context, store *repository.Store, resourceID, objectStorageID uuid.UUID, sourceType, recType, severity, title string) {
	_, _ = store.UpsertRecommendationBySource(ctx, generated.UpsertRecommendationBySourceParams{
		ResourceID: resourceID, Type: recType, Severity: severity, Title: title,
		Metadata: []byte("{}"), SourceType: pgutil.Text(sourceType), SourceID: pgutil.NullUUID(&objectStorageID),
	})
}

func resolveObjectStorageRecommendation(ctx context.Context, store *repository.Store, sourceType string, objectStorageID uuid.UUID) {
	_ = store.ResolveRecommendationBySource(ctx, generated.ResolveRecommendationBySourceParams{
		SourceType: pgutil.Text(sourceType), SourceID: pgutil.NullUUID(&objectStorageID),
	})
}
