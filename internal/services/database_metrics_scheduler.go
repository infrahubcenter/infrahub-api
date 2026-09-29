package services

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/repository"
)

// DatabaseMetricsScheduler is the background fast-metrics loop: a fixed
// worker pool draining a queue of database IDs, run on
// DATABASE_METRICS_INTERVAL (default 15s). Only databases with
// monitoring_enabled=true are ever enqueued.
type DatabaseMetricsScheduler struct {
	store    *repository.Store
	metrics  *DatabaseMetricsService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs     chan uuid.UUID
	inFlight sync.Map
	wg       sync.WaitGroup
}

// NewDatabaseMetricsScheduler creates a DatabaseMetricsScheduler.
func NewDatabaseMetricsScheduler(store *repository.Store, metrics *DatabaseMetricsService, interval time.Duration, workers int32, logger *slog.Logger) *DatabaseMetricsScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DatabaseMetricsScheduler{store: store, metrics: metrics, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher.
func (s *DatabaseMetricsScheduler) Run(ctx context.Context) {
	s.jobs = make(chan uuid.UUID, 128)
	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
	s.wg.Add(1)
	go s.dispatch(ctx)
	s.wg.Wait()
	s.logger.Info("database metrics scheduler stopped")
}

func (s *DatabaseMetricsScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("database metrics scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *DatabaseMetricsScheduler) enqueueCycle(ctx context.Context) {
	dbs, err := s.store.ListDatabasesForMonitoring(ctx)
	if err != nil {
		s.logger.Error("database metrics: failed to list monitoring-enabled databases", "error", err)
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

func (s *DatabaseMetricsScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for databaseID := range s.jobs {
		s.collect(ctx, databaseID)
	}
}

func (s *DatabaseMetricsScheduler) collect(ctx context.Context, databaseID uuid.UUID) {
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
	if err := s.metrics.CollectOne(ctx, db); err != nil {
		s.logger.Error("database metrics: collection failed", "database_id", databaseID, "error", err)
	}
}
