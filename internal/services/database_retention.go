package services

import (
	"context"
	"log/slog"
	"time"

	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

const databaseRetentionInterval = 24 * time.Hour

// DatabaseRetentionService periodically deletes standalone_database_metrics/
// standalone_database_deep_metrics/standalone_database_query_metrics rows
// older than their configured retention. Only metrics history is ever
// touched -- never audit_logs, database configuration, or operation
// history.
type DatabaseRetentionService struct {
	store                *repository.Store
	retention            time.Duration
	queryMetricRetention time.Duration
	logger               *slog.Logger
}

// NewDatabaseRetentionService creates a DatabaseRetentionService.
// queryMetricRetentionDays governs standalone_database_query_metrics
// specifically ("query metrics can be high-volume, do not retain
// indefinitely") -- deliberately a separate, potentially shorter window
// from the common/deep metrics retention.
func NewDatabaseRetentionService(store *repository.Store, retentionDays, queryMetricRetentionDays int32, logger *slog.Logger) *DatabaseRetentionService {
	if logger == nil {
		logger = slog.Default()
	}
	days := retentionDays
	if days < 1 {
		days = 1
	}
	queryDays := queryMetricRetentionDays
	if queryDays < 1 {
		queryDays = 1
	}
	return &DatabaseRetentionService{
		store: store, retention: time.Duration(days) * 24 * time.Hour,
		queryMetricRetention: time.Duration(queryDays) * 24 * time.Hour, logger: logger,
	}
}

// Run ticks every databaseRetentionInterval and blocks until ctx is
// cancelled.
func (r *DatabaseRetentionService) Run(ctx context.Context) {
	ticker := time.NewTicker(databaseRetentionInterval)
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

// Cleanup runs one retention pass immediately across every metrics
// history table. Never deletes databases, standalone_database_credentials,
// or audit_logs.
func (r *DatabaseRetentionService) Cleanup(ctx context.Context) {
	cutoff := pgutil.Timestamptz(time.Now().Add(-r.retention))
	if deleted, err := r.store.DeleteStandaloneDatabaseMetricsBefore(ctx, cutoff); err != nil {
		r.logger.Error("database retention: cleanup failed", "table", "standalone_database_metrics", "error", err)
	} else {
		r.logger.Info("database retention: cleanup completed", "table", "standalone_database_metrics", "retention", r.retention, "deleted", deleted)
	}

	if deleted, err := r.store.DeleteStandaloneDatabaseDeepMetricsBefore(ctx, cutoff); err != nil {
		r.logger.Error("database retention: cleanup failed", "table", "standalone_database_deep_metrics", "error", err)
	} else {
		r.logger.Info("database retention: cleanup completed", "table", "standalone_database_deep_metrics", "retention", r.retention, "deleted", deleted)
	}

	queryCutoff := pgutil.Timestamptz(time.Now().Add(-r.queryMetricRetention))
	if deleted, err := r.store.DeleteStandaloneDatabaseQueryMetricsBefore(ctx, queryCutoff); err != nil {
		r.logger.Error("database retention: cleanup failed", "table", "standalone_database_query_metrics", "error", err)
	} else {
		r.logger.Info("database retention: cleanup completed", "table", "standalone_database_query_metrics", "retention", r.queryMetricRetention, "deleted", deleted)
	}
}
