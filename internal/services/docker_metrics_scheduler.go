package services

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/repository"
)

// DockerMetricsScheduler is the background container-metrics collection
// loop (spec §33-39): structurally identical to MonitoringScheduler (Step
// 6) -- fixed worker pool, per-VM overlap guard, graceful shutdown -- run
// on DOCKER_METRICS_INTERVAL (default 15s), independent of and never
// combined with DockerDiscoveryScheduler's much longer inventory cadence.
// Unlike monitoring/package/discovery, there is no manual "collect now"
// trigger for this one -- metrics are always either the scheduled cycle
// or the live WebSocket stream reading the same cache this populates,
// never a one-off admin action.
type DockerMetricsScheduler struct {
	store    *repository.Store
	metrics  *DockerMetricsService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs     chan uuid.UUID
	inFlight sync.Map // uuid.UUID -> struct{}{}
	wg       sync.WaitGroup
}

// NewDockerMetricsScheduler creates a DockerMetricsScheduler.
func NewDockerMetricsScheduler(store *repository.Store, metrics *DockerMetricsService, interval time.Duration, workers int32, logger *slog.Logger) *DockerMetricsScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DockerMetricsScheduler{store: store, metrics: metrics, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher, blocking until ctx
// is cancelled and every launched goroutine has actually returned.
func (s *DockerMetricsScheduler) Run(ctx context.Context) {
	s.jobs = make(chan uuid.UUID, 64)

	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	s.wg.Add(1)
	go s.dispatch(ctx)

	s.wg.Wait()
	s.logger.Info("docker metrics scheduler stopped")
}

func (s *DockerMetricsScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("docker metrics scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *DockerMetricsScheduler) enqueueCycle(ctx context.Context) {
	vms, err := s.store.ListDockerMetricsEnabledVMs(ctx)
	if err != nil {
		s.logger.Error("docker metrics: failed to list metrics-eligible VMs", "error", err)
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

func (s *DockerMetricsScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for resourceID := range s.jobs {
		s.collect(ctx, resourceID)
	}
}

func (s *DockerMetricsScheduler) collect(ctx context.Context, resourceID uuid.UUID) {
	if _, loaded := s.inFlight.LoadOrStore(resourceID, struct{}{}); loaded {
		s.logger.Warn("docker metrics: skipping cycle, previous collection still running", "resource_id", resourceID)
		return
	}
	defer s.inFlight.Delete(resourceID)

	start := time.Now()
	result, err := s.metrics.CollectAll(ctx, resourceID)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("docker metrics: collection failed", "resource_id", resourceID, "error", err, "duration_ms", duration.Milliseconds())
		return
	}
	s.logger.Debug("docker metrics: collection completed",
		"resource_id", resourceID, "status", result.Status, "container_count", result.ContainerCount, "duration_ms", duration.Milliseconds())
}
