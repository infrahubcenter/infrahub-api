package services

import (
	"context"
	"log/slog"
	"time"

	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// dockerHostLogRetentionInterval mirrors dockerLogRetentionInterval:
// cleanup runs once a day, never on every capture cycle.
const dockerHostLogRetentionInterval = 24 * time.Hour

// DockerHostLogRetentionService periodically deletes captured Docker Host
// container log lines older than the configured retention window. A
// dedicated service (not folded into DockerLogRetentionService) so each
// retention policy keeps its own single-table discipline -- see
// DockerLogRetentionService's own doc comment on why that separation
// matters (archiving included).
type DockerHostLogRetentionService struct {
	store     *repository.Store
	retention time.Duration
	archiver  LogArchiver
	logger    *slog.Logger
}

// NewDockerHostLogRetentionService creates a DockerHostLogRetentionService.
// retentionDays comes from DOCKER_LOG_RETENTION_DAYS (shared with the
// VM-hosted Docker capture path -- same policy, same concept, just a
// second table). archiver is LOG_ARCHIVE_BACKEND's resolved
// implementation -- see log_archive.go.
func NewDockerHostLogRetentionService(store *repository.Store, retentionDays int32, archiver LogArchiver, logger *slog.Logger) *DockerHostLogRetentionService {
	if logger == nil {
		logger = slog.Default()
	}
	days := retentionDays
	if days < 1 {
		days = 1
	}
	return &DockerHostLogRetentionService{store: store, retention: time.Duration(days) * 24 * time.Hour, archiver: archiver, logger: logger}
}

// Run ticks every dockerHostLogRetentionInterval and blocks until ctx is
// cancelled.
func (r *DockerHostLogRetentionService) Run(ctx context.Context) {
	ticker := time.NewTicker(dockerHostLogRetentionInterval)
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
// invoked directly in tests without waiting a full interval. See
// DockerLogRetentionService.Cleanup's own doc comment for the
// archive-before-delete, skip-on-archive-failure discipline.
func (r *DockerHostLogRetentionService) Cleanup(ctx context.Context) {
	cutoff := pgutil.Timestamptz(time.Now().Add(-r.retention))

	rows, err := r.store.ListDockerHostContainerLogLinesOlderThan(ctx, cutoff)
	if err != nil {
		r.logger.Error("docker host log retention: failed to list rows to archive", "table", "docker_host_container_log_lines", "error", err)
		return
	}
	if len(rows) > 0 {
		lines := make([]ArchivedLogLine, len(rows))
		for i, row := range rows {
			lines[i] = ArchivedLogLine{ID: row.ID.String(), ParentID: row.DockerHostContainerSightingID.String(), LoggedAt: row.LoggedAt.Time, Line: row.Line}
		}
		if err := r.archiver.Archive(ctx, "docker_host_container_log_lines", lines); err != nil {
			r.logger.Error("docker host log retention: archive failed, skipping delete this cycle", "table", "docker_host_container_log_lines", "error", err)
			return
		}
	}

	if err := r.store.DeleteOldDockerHostContainerLogLines(ctx, cutoff); err != nil {
		r.logger.Error("docker host log retention: cleanup failed", "table", "docker_host_container_log_lines", "error", err)
		return
	}
	r.logger.Info("docker host log retention: cleanup completed", "retention", r.retention, "cutoff", cutoff.Time, "archived", len(rows))
}
