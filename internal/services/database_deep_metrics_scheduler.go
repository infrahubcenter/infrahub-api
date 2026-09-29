package services

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/repository"
)

// DatabaseDeepMetricsScheduler is the background deep-metrics loop:
// structurally identical to DatabaseMetricsScheduler -- a fixed worker
// pool draining a queue of database IDs -- but run on its own, much
// longer DATABASE_DEEP_METRICS_INTERVAL (default 60s) with its own
// DATABASE_DEEP_METRICS_WORKERS pool, so an expensive deep cycle can
// never delay or starve the fast/common metrics cycle.
type DatabaseDeepMetricsScheduler struct {
	store    *repository.Store
	deep     *DatabaseDeepMetricsService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs     chan uuid.UUID
	inFlight sync.Map
	wg       sync.WaitGroup
}

// NewDatabaseDeepMetricsScheduler creates a DatabaseDeepMetricsScheduler.
func NewDatabaseDeepMetricsScheduler(store *repository.Store, deep *DatabaseDeepMetricsService, interval time.Duration, workers int32, logger *slog.Logger) *DatabaseDeepMetricsScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DatabaseDeepMetricsScheduler{store: store, deep: deep, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher.
func (s *DatabaseDeepMetricsScheduler) Run(ctx context.Context) {
	s.jobs = make(chan uuid.UUID, 128)
	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
	s.wg.Add(1)
	go s.dispatch(ctx)
	s.wg.Wait()
	s.logger.Info("database deep metrics scheduler stopped")
}

func (s *DatabaseDeepMetricsScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("database deep metrics scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *DatabaseDeepMetricsScheduler) enqueueCycle(ctx context.Context) {
	dbs, err := s.store.ListDatabasesForMonitoring(ctx)
	if err != nil {
		s.logger.Error("database deep metrics: failed to list monitoring-enabled databases", "error", err)
		return
	}
	for _, db := range dbs {
		select {
		case s.jobs <- db.ID:
		case <-ctx.Done():
			return
		}
	}
}

func (s *DatabaseDeepMetricsScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for databaseID := range s.jobs {
		s.collect(ctx, databaseID)
	}
}

func (s *DatabaseDeepMetricsScheduler) collect(ctx context.Context, databaseID uuid.UUID) {
	if _, loaded := s.inFlight.LoadOrStore(databaseID, struct{}{}); loaded {
		return
	}
	defer s.inFlight.Delete(databaseID)

	db, err := s.store.GetDatabaseForMonitoring(ctx, databaseID)
	if err != nil {
		return
	}
	if !db.MonitoringEnabled {
		return
	}
	if err := s.deep.CollectDeep(ctx, db); err != nil {
		s.logger.Error("database deep metrics: collection failed", "database_id", databaseID, "error", err)
	}
}
