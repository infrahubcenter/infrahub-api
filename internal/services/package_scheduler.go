package services

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/repository"
)

// ErrPackageScanInProgress mirrors ErrMonitoringInProgress (Step 6): a
// scan for the same VM (scheduled or manual) is already running (spec
// §23: overlapping scans are always skipped, never queued).
var ErrPackageScanInProgress = errors.New("a package scan is already running for this VM")

// ErrPackageScanRateLimited mirrors Step 6's ErrMonitoringRateLimited.
var ErrPackageScanRateLimited = errors.New("a package scan or refresh was triggered too recently for this VM; please wait before retrying")

// minManualPackageScanInterval debounces manual scan/refresh triggers per
// VM, the same way Step 6 debounces manual monitoring collection --
// package operations are heavier (a full apt-get update/dnf check-update
// round trip), so the window is longer.
const minManualPackageScanInterval = 30 * time.Second

// PackageScanScheduler is the background package-scan loop (Step 7 spec
// §22-23): structurally identical to Step 6's MonitoringScheduler --
// fixed worker pool draining a job channel, per-VM overlap guard, graceful
// shutdown -- run on a much longer interval (PACKAGE_SCAN_INTERVAL,
// default 6h, vs monitoring's 60s) since package inventories change far
// less often than CPU/RAM (spec §21/§58).
type PackageScanScheduler struct {
	store     *repository.Store
	packages  *PackageService
	osUpdates *OSUpdateService // optional; set via SetOSUpdateService
	interval  time.Duration
	workers   int32
	logger    *slog.Logger

	jobs              chan uuid.UUID
	inFlight          sync.Map // uuid.UUID -> struct{}{}
	lastManualTrigger sync.Map // uuid.UUID -> time.Time
	wg                sync.WaitGroup
}

// NewPackageScanScheduler creates a PackageScanScheduler.
func NewPackageScanScheduler(store *repository.Store, packages *PackageService, interval time.Duration, workers int32, logger *slog.Logger) *PackageScanScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PackageScanScheduler{store: store, packages: packages, interval: interval, workers: workers, logger: logger}
}

// SetOSUpdateService wires OS/kernel/reboot detection (Step 9) into this
// same scheduler's cadence -- spec §67's explicit "do not create another
// independent package scan scheduler just for Update Center; after
// package scan, update detection can be refreshed." A scan cycle that
// hasn't called this (osUpdates is nil) simply skips the OS-update step,
// exactly as before Step 9 existed.
func (s *PackageScanScheduler) SetOSUpdateService(osUpdates *OSUpdateService) {
	s.osUpdates = osUpdates
}

// Run starts the worker pool and ticking dispatcher, blocking until ctx
// is cancelled and every launched goroutine has returned.
func (s *PackageScanScheduler) Run(ctx context.Context) {
	s.jobs = make(chan uuid.UUID, 64)

	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	s.wg.Add(1)
	go s.dispatch(ctx)

	s.wg.Wait()
	s.logger.Info("package scan scheduler stopped")
}

func (s *PackageScanScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("package scan scheduler started", "interval", s.interval, "workers", s.workers)
	s.enqueueCycle(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.enqueueCycle(ctx)
		}
	}
}

func (s *PackageScanScheduler) enqueueCycle(ctx context.Context) {
	vms, err := s.store.ListPackageScanEnabledVMs(ctx)
	if err != nil {
		s.logger.Error("package scan: failed to list scan-eligible VMs", "error", err)
		return
	}
	for _, vm := range vms {
		select {
		case s.jobs <- vm.ResourceID:
		case <-ctx.Done():
			return
		}
	}
}

func (s *PackageScanScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for resourceID := range s.jobs {
		s.scan(ctx, resourceID)
	}
}

func (s *PackageScanScheduler) scan(ctx context.Context, resourceID uuid.UUID) {
	if _, loaded := s.inFlight.LoadOrStore(resourceID, struct{}{}); loaded {
		s.logger.Warn("package scan: skipping cycle, previous scan still running", "resource_id", resourceID)
		return
	}
	defer s.inFlight.Delete(resourceID)

	start := time.Now()
	result, err := s.packages.Scan(ctx, resourceID)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("package scan: failed", "resource_id", resourceID, "error", err, "duration_ms", duration.Milliseconds())
		return
	}
	s.logger.Info("package scan: completed",
		"resource_id", resourceID, "status", result.Status, "package_manager", result.PackageManager,
		"package_count", result.PackageCount, "update_count", result.UpdateCount, "duration_ms", duration.Milliseconds())

	s.runOSUpdateScan(ctx, resourceID)
}

// runOSUpdateScan is a best-effort, independently-logged follow-up to a
// package scan (spec §67's "after package scan: update detection can be
// refreshed") -- its outcome never affects the package scan's own
// result, and it's skipped entirely if no OSUpdateService was wired in
// (SetOSUpdateService).
func (s *PackageScanScheduler) runOSUpdateScan(ctx context.Context, resourceID uuid.UUID) {
	if s.osUpdates == nil {
		return
	}
	start := time.Now()
	result, err := s.osUpdates.Scan(ctx, resourceID)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("os update scan: failed", "resource_id", resourceID, "error", err, "duration_ms", duration.Milliseconds())
		return
	}
	s.logger.Info("os update scan: completed",
		"resource_id", resourceID, "status", result.Status, "os_status", result.OSStatus,
		"reboot_status", result.RebootStatus, "duration_ms", duration.Milliseconds())
}

// ScanNow runs one immediate, out-of-band full scan -- the admin's
// [Scan Packages] button. Shares the overlap guard with the scheduler.
func (s *PackageScanScheduler) ScanNow(ctx context.Context, resourceID uuid.UUID) (PackageScanResult, error) {
	if last, ok := s.lastManualTrigger.Load(resourceID); ok {
		if elapsed := time.Since(last.(time.Time)); elapsed < minManualPackageScanInterval {
			return PackageScanResult{}, ErrPackageScanRateLimited
		}
	}
	if _, loaded := s.inFlight.LoadOrStore(resourceID, struct{}{}); loaded {
		return PackageScanResult{}, ErrPackageScanInProgress
	}
	defer s.inFlight.Delete(resourceID)
	s.lastManualTrigger.Store(resourceID, time.Now())

	return s.packages.Scan(ctx, resourceID)
}

// RefreshNow runs one immediate metadata refresh + update check, without
// re-listing installed packages -- the admin's "Refresh metadata" action
// (spec §29's separate POST .../packages/refresh). Shares the same
// overlap guard and debounce as ScanNow (a refresh is still a real SSH
// round-trip against the VM).
func (s *PackageScanScheduler) RefreshNow(ctx context.Context, resourceID uuid.UUID) (PackageScanResult, error) {
	if last, ok := s.lastManualTrigger.Load(resourceID); ok {
		if elapsed := time.Since(last.(time.Time)); elapsed < minManualPackageScanInterval {
			return PackageScanResult{}, ErrPackageScanRateLimited
		}
	}
	if _, loaded := s.inFlight.LoadOrStore(resourceID, struct{}{}); loaded {
		return PackageScanResult{}, ErrPackageScanInProgress
	}
	defer s.inFlight.Delete(resourceID)
	s.lastManualTrigger.Store(resourceID, time.Now())

	return s.packages.RefreshUpdates(ctx, resourceID)
}
