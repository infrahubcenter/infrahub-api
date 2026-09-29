package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// retentionInterval is how often the cleanup job runs (Step 6 spec §52:
// "every 24 hours... do not run cleanup on every monitoring cycle").
const retentionInterval = 24 * time.Hour

// RetentionService periodically deletes monitoring history older than the
// configured retention window. Only monitoring_snapshots, vm_filesystems,
// vm_network_snapshots, and vm_monitoring_runs are ever touched -- never
// audit_logs, operations, or operation_logs (spec §51), which have no
// retention policy of their own yet.
type RetentionService struct {
	store     *repository.Store
	retention time.Duration
	logger    *slog.Logger
}

// NewRetentionService creates a RetentionService. retentionDays comes
// from VM_MONITOR_RETENTION_DAYS.
func NewRetentionService(store *repository.Store, retentionDays int32, logger *slog.Logger) *RetentionService {
	if logger == nil {
		logger = slog.Default()
	}
	days := retentionDays
	if days < 1 {
		days = 1
	}
	return &RetentionService{store: store, retention: time.Duration(days) * 24 * time.Hour, logger: logger}
}

// Run ticks every retentionInterval and blocks until ctx is cancelled.
// Deliberately does NOT clean up immediately on start (unlike
// MonitoringScheduler.Run, which does run an initial cycle right away):
// an unattended deletion the moment the server restarts would be a
// surprising side effect of an operational action, whereas monitoring
// collection benefits from running promptly so newly-enabled VMs get
// data quickly.
func (r *RetentionService) Run(ctx context.Context) {
	ticker := time.NewTicker(retentionInterval)
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
func (r *RetentionService) Cleanup(ctx context.Context) {
	cutoff := pgutil.Timestamptz(time.Now().Add(-r.retention))

	deletions := []struct {
		name string
		run  func(context.Context, pgtype.Timestamptz) error
	}{
		{"monitoring_snapshots", r.store.DeleteOldMonitoringSnapshots},
		{"vm_filesystems", r.store.DeleteOldVMFilesystems},
		{"vm_network_snapshots", r.store.DeleteOldVMNetworkSnapshots},
		{"vm_monitoring_runs", r.store.DeleteOldVMMonitoringRuns},
	}
	for _, d := range deletions {
		if err := d.run(ctx, cutoff); err != nil {
			r.logger.Error("monitoring retention: cleanup failed", "table", d.name, "error", err)
			continue
		}
	}
	r.logger.Info("monitoring retention: cleanup completed", "retention", r.retention, "cutoff", cutoff.Time)
}
