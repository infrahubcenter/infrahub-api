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

// ErrDockerScanInProgress mirrors ErrPackageScanInProgress (Step 7): a
// scan for the same VM (scheduled or manual) is already running --
// overlapping scans are always skipped, never queued.
var ErrDockerScanInProgress = errors.New("a Docker scan is already running for this VM")

// ErrDockerScanRateLimited mirrors ErrPackageScanRateLimited.
var ErrDockerScanRateLimited = errors.New("a Docker scan was triggered too recently for this VM; please wait before retrying")

// minManualDockerScanInterval debounces manual scan triggers per VM --
// a full inventory scan is a handful of SSH round trips (version, info,
// inspect x4), so this mirrors package scanning's debounce window rather
// than monitoring's much shorter one.
const minManualDockerScanInterval = 30 * time.Second

// DockerDiscoveryScheduler is the background Docker inventory-scan loop
// (spec §7/§8): structurally identical to PackageScanScheduler (Step 7)
// and MonitoringScheduler (Step 6) -- fixed worker pool draining a job
// channel, per-VM overlap guard, graceful shutdown -- run on
// DOCKER_SCAN_INTERVAL (default 10m), independent of and never combined
// with DockerMetricsScheduler's much shorter cadence.
type DockerDiscoveryScheduler struct {
	store    *repository.Store
	docker   *DockerDiscoveryService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs              chan uuid.UUID
	inFlight          sync.Map // uuid.UUID -> struct{}{}
	lastManualTrigger sync.Map // uuid.UUID -> time.Time
	wg                sync.WaitGroup
}

// NewDockerDiscoveryScheduler creates a DockerDiscoveryScheduler.
func NewDockerDiscoveryScheduler(store *repository.Store, docker *DockerDiscoveryService, interval time.Duration, workers int32, logger *slog.Logger) *DockerDiscoveryScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DockerDiscoveryScheduler{store: store, docker: docker, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher, blocking until ctx
// is cancelled and every launched goroutine has actually returned.
func (s *DockerDiscoveryScheduler) Run(ctx context.Context) {
	s.jobs = make(chan uuid.UUID, 64)

	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	s.wg.Add(1)
	go s.dispatch(ctx)

	s.wg.Wait()
	s.logger.Info("docker discovery scheduler stopped")
}

func (s *DockerDiscoveryScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("docker discovery scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *DockerDiscoveryScheduler) enqueueCycle(ctx context.Context) {
	vms, err := s.store.ListDockerScanEnabledVMs(ctx)
	if err != nil {
		s.logger.Error("docker scan: failed to list scan-eligible VMs", "error", err)
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

func (s *DockerDiscoveryScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for resourceID := range s.jobs {
		s.scan(ctx, resourceID)
	}
}

func (s *DockerDiscoveryScheduler) scan(ctx context.Context, resourceID uuid.UUID) {
	if _, loaded := s.inFlight.LoadOrStore(resourceID, struct{}{}); loaded {
		s.logger.Warn("docker scan: skipping cycle, previous scan still running", "resource_id", resourceID)
		return
	}
	defer s.inFlight.Delete(resourceID)

	start := time.Now()
	result, err := s.docker.Scan(ctx, resourceID)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("docker scan: failed", "resource_id", resourceID, "error", err, "duration_ms", duration.Milliseconds())
		return
	}
	s.logger.Info("docker scan: completed",
		"resource_id", resourceID, "status", result.Status, "daemon_status", result.DaemonStatus,
		"container_count", result.ContainerCount, "image_count", result.ImageCount,
		"network_count", result.NetworkCount, "volume_count", result.VolumeCount, "duration_ms", duration.Milliseconds())
}

// ScanNow runs one immediate, out-of-band full scan -- the admin's [Scan
// Docker] button. Shares the overlap guard with the scheduler.
func (s *DockerDiscoveryScheduler) ScanNow(ctx context.Context, resourceID uuid.UUID) (DockerScanResult, error) {
	if last, ok := s.lastManualTrigger.Load(resourceID); ok {
		if elapsed := time.Since(last.(time.Time)); elapsed < minManualDockerScanInterval {
			return DockerScanResult{}, ErrDockerScanRateLimited
		}
	}
	if _, loaded := s.inFlight.LoadOrStore(resourceID, struct{}{}); loaded {
		return DockerScanResult{}, ErrDockerScanInProgress
	}
	defer s.inFlight.Delete(resourceID)
	s.lastManualTrigger.Store(resourceID, time.Now())

	return s.docker.Scan(ctx, resourceID)
}
