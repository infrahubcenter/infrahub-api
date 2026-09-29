package services

import (
	"context"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// recordMonitoringSuccess/recordMonitoringFailure implement collector
// self-observability: every fast (tier="FAST") and deep (tier="DEEP")
// collection attempt updates standalone_database_monitoring_health,
// success or failure, so an Admin can see a *collector* is stuck without
// that ever being confused with the *database* being unreachable --
// connection_status/health_status already cover that, independently.
// Errors here are swallowed (best-effort observability, never allowed to
// fail the collection cycle itself).
func recordMonitoringSuccess(ctx context.Context, store *repository.Store, databaseID uuid.UUID, tier string, duration time.Duration) {
	_ = store.RecordStandaloneDatabaseMonitoringSuccess(ctx, generated.RecordStandaloneDatabaseMonitoringSuccessParams{
		DatabaseID: databaseID, Tier: tier, LastDurationMs: pgutil.Int4(int32(duration.Milliseconds())),
	})
}

func recordMonitoringFailure(ctx context.Context, store *repository.Store, databaseID uuid.UUID, tier, reason string) {
	_ = store.RecordStandaloneDatabaseMonitoringFailure(ctx, generated.RecordStandaloneDatabaseMonitoringFailureParams{
		DatabaseID: databaseID, Tier: tier, LastError: pgutil.Text(reason),
	})
}

// upsertDatabaseRecommendation/resolveDatabaseRecommendation are the
// shared, database-flavored wrappers around Step 7's exact
// UpsertRecommendationBySource/ResolveRecommendationBySource queries --
// used by both the fast and deep metrics services, keyed by
// source_type + the database's own row ID for natural dedup.
func upsertDatabaseRecommendation(ctx context.Context, store *repository.Store, resourceID, databaseID uuid.UUID, sourceType, recType, severity, title string) {
	_, _ = store.UpsertRecommendationBySource(ctx, generated.UpsertRecommendationBySourceParams{
		ResourceID: resourceID, Type: recType, Severity: severity, Title: title,
		Metadata: []byte("{}"), SourceType: pgutil.Text(sourceType), SourceID: pgutil.NullUUID(&databaseID),
	})
}

func resolveDatabaseRecommendation(ctx context.Context, store *repository.Store, sourceType string, databaseID uuid.UUID) {
	_ = store.ResolveRecommendationBySource(ctx, generated.ResolveRecommendationBySourceParams{
		SourceType: pgutil.Text(sourceType), SourceID: pgutil.NullUUID(&databaseID),
	})
}
