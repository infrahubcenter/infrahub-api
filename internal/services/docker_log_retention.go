package services

import (
	"context"
	"log/slog"
	"time"

	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// dockerLogRetentionInterval mirrors dockerRetentionInterval: cleanup runs
// once a day, never on every capture cycle.
const dockerLogRetentionInterval = 24 * time.Hour

// DockerLogRetentionService periodically deletes captured Docker container
// log lines older than the configured retention window. A dedicated
// service (not folded into DockerRetentionService) so each retention
// policy keeps its own single-table discipline -- see
// DockerRetentionService's own doc comment on why that separation matters.
type DockerLogRetentionService struct {
	store     *repository.Store
	retention time.Duration
	archiver  LogArchiver
	logger    *slog.Logger
}

// NewDockerLogRetentionService creates a DockerLogRetentionService.
// retentionDays comes from DOCKER_LOG_RETENTION_DAYS. archiver is
// LOG_ARCHIVE_BACKEND's resolved implementation (see log_archive.go) --
// pass a noopLogArchiver (NewLogArchiver's own default for "none") to
// keep the pre-archive behavior of "just delete" unchanged.
func NewDockerLogRetentionService(store *repository.Store, retentionDays int32, archiver LogArchiver, logger *slog.Logger) *DockerLogRetentionService {
	if logger == nil {
		logger = slog.Default()
	}
	days := retentionDays
	if days < 1 {
		days = 1
	}
	return &DockerLogRetentionService{store: store, retention: time.Duration(days) * 24 * time.Hour, archiver: archiver, logger: logger}
}

// Run ticks every dockerLogRetentionInterval and blocks until ctx is
// cancelled.
func (r *DockerLogRetentionService) Run(ctx context.Context) {
	ticker := time.NewTicker(dockerLogRetentionInterval)
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
// invoked directly in tests without waiting a full interval. Archives
// (see log_archive.go) every row about to be deleted BEFORE deleting it
// -- if archiving is configured and fails, the delete is skipped for
// this cycle entirely (tried again on the next one) rather than deleting
// rows an operator asked to have preserved.
func (r *DockerLogRetentionService) Cleanup(ctx context.Context) {
	cutoff := pgutil.Timestamptz(time.Now().Add(-r.retention))

	rows, err := r.store.ListDockerLogLinesOlderThan(ctx, cutoff)
	if err != nil {
		r.logger.Error("docker log retention: failed to list rows to archive", "table", "docker_container_log_lines", "error", err)
		return
	}
	if len(rows) > 0 {
		lines := make([]ArchivedLogLine, len(rows))
		for i, row := range rows {
			lines[i] = ArchivedLogLine{ID: row.ID.String(), ParentID: row.DockerContainerID.String(), LoggedAt: row.LoggedAt.Time, Line: row.Line}
		}
		if err := r.archiver.Archive(ctx, "docker_container_log_lines", lines); err != nil {
			r.logger.Error("docker log retention: archive failed, skipping delete this cycle", "table", "docker_container_log_lines", "error", err)
			return
		}
	}

	if err := r.store.DeleteOldDockerLogLines(ctx, cutoff); err != nil {
		r.logger.Error("docker log retention: cleanup failed", "table", "docker_container_log_lines", "error", err)
		return
	}
	r.logger.Info("docker log retention: cleanup completed", "retention", r.retention, "cutoff", cutoff.Time, "archived", len(rows))
}
