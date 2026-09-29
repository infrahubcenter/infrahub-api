package services

import (
	"context"
	"log/slog"
	"time"

	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

const objectStorageRetentionInterval = 24 * time.Hour

// ObjectStorageRetentionService periodically deletes object_storage_metrics
// rows older than their configured retention. Only fast-cycle metrics
// history is ever touched -- never object_storages configuration,
// standalone_object_storage_credentials, object_storage_deep_metrics (a
// later phase's own retention concern), or audit_logs. Mirrors
// DatabaseRetentionService, scoped to object storage's single metrics
// table (no separate query-metrics-style table exists for object
// storage).
type ObjectStorageRetentionService struct {
	store     *repository.Store
	retention time.Duration
	logger    *slog.Logger
}

// NewObjectStorageRetentionService creates an ObjectStorageRetentionService.
func NewObjectStorageRetentionService(store *repository.Store, retentionDays int32, logger *slog.Logger) *ObjectStorageRetentionService {
	if logger == nil {
		logger = slog.Default()
	}
	days := retentionDays
	if days < 1 {
		days = 1
	}
	return &ObjectStorageRetentionService{store: store, retention: time.Duration(days) * 24 * time.Hour, logger: logger}
}

// Run ticks every objectStorageRetentionInterval and blocks until ctx is
// cancelled.
func (r *ObjectStorageRetentionService) Run(ctx context.Context) {
	ticker := time.NewTicker(objectStorageRetentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Cleanup(ctx)
		}
	}
}

// Cleanup runs one retention pass immediately. Never deletes
// object_storages, standalone_object_storage_credentials, or audit_logs.
func (r *ObjectStorageRetentionService) Cleanup(ctx context.Context) {
	cutoff := pgutil.Timestamptz(time.Now().Add(-r.retention))
	if deleted, err := r.store.DeleteObjectStorageMetricsBefore(ctx, cutoff); err != nil {
		r.logger.Error("object storage retention: cleanup failed", "table", "object_storage_metrics", "error", err)
	} else {
		r.logger.Info("object storage retention: cleanup completed", "table", "object_storage_metrics", "retention", r.retention, "deleted", deleted)
	}
}
