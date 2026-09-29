package services

import (
	"context"
	"log/slog"
	"time"

	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// dockerRetentionInterval mirrors retentionInterval (Step 6 spec §52):
// cleanup runs once a day, never on every metrics cycle.
const dockerRetentionInterval = 24 * time.Hour

// DockerRetentionService periodically deletes container-metric history
// older than the configured retention window. Only
// docker_container_metric_snapshots is ever touched -- never audit_logs,
// operations, operation_logs, or the inventory tables themselves (those
// soft-delete via removed_at, not a retention window).
type DockerRetentionService struct {
	store     *repository.Store
	retention time.Duration
	logger    *slog.Logger
}

// NewDockerRetentionService creates a DockerRetentionService.
// retentionDays comes from DOCKER_METRICS_RETENTION_DAYS.
func NewDockerRetentionService(store *repository.Store, retentionDays int32, logger *slog.Logger) *DockerRetentionService {
	if logger == nil {
		logger = slog.Default()
	}
	days := retentionDays
	if days < 1 {
		days = 1
	}
	return &DockerRetentionService{store: store, retention: time.Duration(days) * 24 * time.Hour, logger: logger}
}

// Run ticks every dockerRetentionInterval and blocks until ctx is
// cancelled. Deliberately does not clean up immediately on start, same
// rationale as RetentionService.Run: an unattended deletion the moment
// the server restarts would be a surprising side effect.
func (r *DockerRetentionService) Run(ctx context.Context) {
	ticker := time.NewTicker(dockerRetentionInterval)
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

// Cleanup runs one retention pass immediately -- exported so it can be
// invoked directly in tests without waiting a full interval.
func (r *DockerRetentionService) Cleanup(ctx context.Context) {
	cutoff := pgutil.Timestamptz(time.Now().Add(-r.retention))
	if err := r.store.DeleteOldDockerContainerMetricSnapshots(ctx, cutoff); err != nil {
		r.logger.Error("docker retention: cleanup failed", "table", "docker_container_metric_snapshots", "error", err)
		return
	}
	r.logger.Info("docker retention: cleanup completed", "retention", r.retention, "cutoff", cutoff.Time)
}
