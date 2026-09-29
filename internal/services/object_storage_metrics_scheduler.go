package services

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/repository"
)

// ObjectStorageMetricsScheduler is the background fast-metrics loop for
// standalone object storage: a fixed worker pool draining a queue of
// object storage IDs, run on OBJECT_STORAGE_METRICS_INTERVAL (default
// 60s). Only object storages with monitoring_enabled=true are ever
// enqueued. Verbatim copy of DatabaseMetricsScheduler's
// worker-pool/ticker/sync.Map-in-flight-guard shape -- only type names
// change.
type ObjectStorageMetricsScheduler struct {
	store    *repository.Store
	metrics  *ObjectStorageMetricsService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs     chan uuid.UUID
	inFlight sync.Map
	wg       sync.WaitGroup
}

// NewObjectStorageMetricsScheduler creates an ObjectStorageMetricsScheduler.
func NewObjectStorageMetricsScheduler(store *repository.Store, metrics *ObjectStorageMetricsService, interval time.Duration, workers int32, logger *slog.Logger) *ObjectStorageMetricsScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ObjectStorageMetricsScheduler{store: store, metrics: metrics, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher.
func (s *ObjectStorageMetricsScheduler) Run(ctx context.Context) {
	s.jobs = make(chan uuid.UUID, 128)
	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
	s.wg.Add(1)
	go s.dispatch(ctx)
	s.wg.Wait()
	s.logger.Info("object storage metrics scheduler stopped")
}

func (s *ObjectStorageMetricsScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("object storage metrics scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *ObjectStorageMetricsScheduler) enqueueCycle(ctx context.Context) {
	storages, err := s.store.ListObjectStoragesForMonitoring(ctx)
	if err != nil {
		s.logger.Error("object storage metrics: failed to list monitoring-enabled object storages", "error", err)
		return
	}
	for _, os := range storages {
		select {
		case s.jobs <- os.ID:
		case <-ctx.Done():
			return
		}
	}
}

func (s *ObjectStorageMetricsScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for objectStorageID := range s.jobs {
		s.collect(ctx, objectStorageID)
	}
}

func (s *ObjectStorageMetricsScheduler) collect(ctx context.Context, objectStorageID uuid.UUID) {
	if _, loaded := s.inFlight.LoadOrStore(objectStorageID, struct{}{}); loaded {
		return
	}
	defer s.inFlight.Delete(objectStorageID)

	// GetObjectStorageByID (unlike GetDatabaseForMonitoring) carries no
	// monitoring-enabled/deleted_at filter of its own, so this re-checks
	// both explicitly -- guards against a storage disabled/soft-deleted
	// between enqueue and this worker actually dequeuing it.
	os, err := s.store.GetObjectStorageByID(ctx, objectStorageID)
	if err != nil {
		return
	}
	if !os.MonitoringEnabled || os.DeletedAt.Valid {
		return
	}

	start := time.Now()
	if err := s.metrics.CollectOne(ctx, os); err != nil {
		s.logger.Error("object storage metrics: collection failed", "object_storage_id", objectStorageID, "error", err, "duration_ms", time.Since(start).Milliseconds())
		return
	}
	s.logger.Debug("object storage metrics: collection completed", "object_storage_id", objectStorageID, "duration_ms", time.Since(start).Milliseconds())
}
