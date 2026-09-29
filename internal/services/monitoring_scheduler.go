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

// ErrMonitoringInProgress is returned by CollectNow when a collection for
// the same VM (scheduled or manual) is already running -- Step 6 spec §69:
// overlapping collection for one VM is always skipped, never queued.
var ErrMonitoringInProgress = errors.New("a monitoring collection is already running for this VM")

// ErrMonitoringRateLimited is returned by CollectNow when it's called
// again too soon after the previous manual trigger for the same VM (Step
// 6 spec §48: "must not allow unlimited rapid requests").
var ErrMonitoringRateLimited = errors.New("collection was triggered too recently for this VM; please wait before retrying")

// minManualCollectInterval debounces POST .../monitoring/collect per VM.
// Not configurable via environment -- spec §48/§50 lists it as an
// implementation detail ("add rate limiting/debouncing"), not one of the
// named configuration variables.
const minManualCollectInterval = 10 * time.Second

// MonitoringScheduler is the background collection loop (Step 6 spec §5-6):
// a small fixed worker pool pulls VM jobs off a channel, so the number of
// concurrent SSH connections is always bounded by VM_MONITOR_WORKERS
// regardless of how many VMs exist. One VM's failure never affects
// another's (§67); a VM already being collected (by the scheduler or a
// manual trigger) is skipped rather than queued a second time (§69).
type MonitoringScheduler struct {
	store      *repository.Store
	monitoring *VMMonitoringService
	interval   time.Duration
	workers    int32
	logger     *slog.Logger

	jobs              chan uuid.UUID
	inFlight          sync.Map // uuid.UUID -> struct{}{}
	lastManualTrigger sync.Map // uuid.UUID -> time.Time
	wg                sync.WaitGroup
}

// NewMonitoringScheduler creates a MonitoringScheduler. Call Run(ctx) to
// start it; Run blocks until ctx is cancelled and every in-flight
// collection has finished (graceful shutdown, spec §5).
func NewMonitoringScheduler(store *repository.Store, monitoring *VMMonitoringService, interval time.Duration, workers int32, logger *slog.Logger) *MonitoringScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &MonitoringScheduler{store: store, monitoring: monitoring, interval: interval, workers: workers, logger: logger}
}

// Run starts the fixed worker pool and the ticking dispatcher, and blocks
// until ctx is cancelled and every launched goroutine has returned. Safe
// to call exactly once per scheduler instance.
func (s *MonitoringScheduler) Run(ctx context.Context) {
	s.jobs = make(chan uuid.UUID, 64)

	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	s.wg.Add(1)
	go s.dispatch(ctx)

	s.wg.Wait()
	s.logger.Info("monitoring scheduler stopped")
}

func (s *MonitoringScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs) // lets every worker's range loop exit once dispatching stops

	s.logger.Info("monitoring scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *MonitoringScheduler) enqueueCycle(ctx context.Context) {
	vms, err := s.store.ListMonitoringEnabledVMs(ctx)
	if err != nil {
		s.logger.Error("monitoring: failed to list monitoring-enabled VMs", "error", err)
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

func (s *MonitoringScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for resourceID := range s.jobs {
		s.collect(ctx, resourceID)
	}
}

// collect wraps VMMonitoringService.Collect with the overlap guard and
// safe logging (Step 6 spec §67: connection attempt/success/failure with
// only safe metadata -- vm/resource IDs and durations, never anything
// credential-shaped).
func (s *MonitoringScheduler) collect(ctx context.Context, resourceID uuid.UUID) {
	if _, loaded := s.inFlight.LoadOrStore(resourceID, struct{}{}); loaded {
		s.logger.Warn("monitoring: skipping cycle, previous collection still running", "resource_id", resourceID)
		return
	}
	defer s.inFlight.Delete(resourceID)

	start := time.Now()
	result, err := s.monitoring.Collect(ctx, resourceID)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("monitoring: collection failed", "resource_id", resourceID, "error", err, "duration_ms", duration.Milliseconds())
		return
	}
	s.logger.Info("monitoring: collection completed",
		"resource_id", resourceID, "status", result.Status, "health", result.Health, "duration_ms", duration.Milliseconds())
}

// CollectNow runs one immediate, out-of-band collection for resourceID --
// the admin "Collect Now" button (spec §48). It shares the scheduler's
// overlap guard (a manual trigger can never run concurrently with a
// scheduled cycle, or another manual trigger, for the same VM) and adds a
// short per-VM debounce on top of that.
func (s *MonitoringScheduler) CollectNow(ctx context.Context, resourceID uuid.UUID) (MonitoringResult, error) {
	if last, ok := s.lastManualTrigger.Load(resourceID); ok {
		if elapsed := time.Since(last.(time.Time)); elapsed < minManualCollectInterval {
			return MonitoringResult{}, ErrMonitoringRateLimited
		}
	}
	if _, loaded := s.inFlight.LoadOrStore(resourceID, struct{}{}); loaded {
		return MonitoringResult{}, ErrMonitoringInProgress
	}
	defer s.inFlight.Delete(resourceID)
	s.lastManualTrigger.Store(resourceID, time.Now())

	return s.monitoring.Collect(ctx, resourceID)
}
