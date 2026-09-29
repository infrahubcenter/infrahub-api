package services

import (
	"context"
	"log/slog"
	"time"

	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// k8sLogRetentionInterval mirrors dockerLogRetentionInterval: cleanup runs
// once a day.
const k8sLogRetentionInterval = 24 * time.Hour

// K8sLogRetentionService periodically deletes captured Kubernetes pod log
// lines older than the configured retention window. Mirrors
// DockerLogRetentionService exactly, archiving included.
type K8sLogRetentionService struct {
	store     *repository.Store
	retention time.Duration
	archiver  LogArchiver
	logger    *slog.Logger
}

// NewK8sLogRetentionService creates a K8sLogRetentionService.
// retentionDays comes from K8S_LOG_RETENTION_DAYS. archiver is
// LOG_ARCHIVE_BACKEND's resolved implementation -- see log_archive.go
// and DockerLogRetentionService's own doc comment.
func NewK8sLogRetentionService(store *repository.Store, retentionDays int32, archiver LogArchiver, logger *slog.Logger) *K8sLogRetentionService {
	if logger == nil {
		logger = slog.Default()
	}
	days := retentionDays
	if days < 1 {
		days = 1
	}
	return &K8sLogRetentionService{store: store, retention: time.Duration(days) * 24 * time.Hour, archiver: archiver, logger: logger}
}

// Run ticks every k8sLogRetentionInterval and blocks until ctx is
// cancelled.
func (r *K8sLogRetentionService) Run(ctx context.Context) {
	ticker := time.NewTicker(k8sLogRetentionInterval)
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
func (r *K8sLogRetentionService) Cleanup(ctx context.Context) {
	cutoff := pgutil.Timestamptz(time.Now().Add(-r.retention))

	rows, err := r.store.ListK8sPodLogLinesOlderThan(ctx, cutoff)
	if err != nil {
		r.logger.Error("k8s log retention: failed to list rows to archive", "table", "k8s_pod_log_lines", "error", err)
		return
	}
	if len(rows) > 0 {
		lines := make([]ArchivedLogLine, len(rows))
		for i, row := range rows {
			lines[i] = ArchivedLogLine{ID: row.ID.String(), ParentID: row.K8sPodID.String(), LoggedAt: row.LoggedAt.Time, Line: row.Line}
		}
		if err := r.archiver.Archive(ctx, "k8s_pod_log_lines", lines); err != nil {
			r.logger.Error("k8s log retention: archive failed, skipping delete this cycle", "table", "k8s_pod_log_lines", "error", err)
			return
		}
	}

	if err := r.store.DeleteOldK8sPodLogLines(ctx, cutoff); err != nil {
		r.logger.Error("k8s log retention: cleanup failed", "table", "k8s_pod_log_lines", "error", err)
		return
	}
	r.logger.Info("k8s log retention: cleanup completed", "retention", r.retention, "cutoff", cutoff.Time, "archived", len(rows))
}
