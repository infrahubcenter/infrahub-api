package services

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/repository"
)

// ObjectStorageDeepMetricsScheduler is the background deep-metrics loop for
// standalone object storage: structurally identical to
// ObjectStorageMetricsScheduler (Phase 2) and DatabaseDeepMetricsScheduler
// -- a fixed worker pool draining a queue of object storage IDs -- but run
// on its own, much longer OBJECT_STORAGE_DEEP_METRICS_INTERVAL (default
// 5m) with its own OBJECT_STORAGE_DEEP_METRICS_WORKERS pool, so an
// expensive CloudWatch/bucket-config/bounded-listing cycle can never delay
// or starve the fast, HeadBucket-only cycle.
type ObjectStorageDeepMetricsScheduler struct {
	store    *repository.Store
	deep     *ObjectStorageDeepMetricsService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs     chan uuid.UUID
	inFlight sync.Map
	wg       sync.WaitGroup
}

// NewObjectStorageDeepMetricsScheduler creates an ObjectStorageDeepMetricsScheduler.
func NewObjectStorageDeepMetricsScheduler(store *repository.Store, deep *ObjectStorageDeepMetricsService, interval time.Duration, workers int32, logger *slog.Logger) *ObjectStorageDeepMetricsScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ObjectStorageDeepMetricsScheduler{store: store, deep: deep, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher.
func (s *ObjectStorageDeepMetricsScheduler) Run(ctx context.Context) {
	s.jobs = make(chan uuid.UUID, 128)
	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
	s.wg.Add(1)
	go s.dispatch(ctx)
	s.wg.Wait()
	s.logger.Info("object storage deep metrics scheduler stopped")
}

func (s *ObjectStorageDeepMetricsScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("object storage deep metrics scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *ObjectStorageDeepMetricsScheduler) enqueueCycle(ctx context.Context) {
	storages, err := s.store.ListObjectStoragesForMonitoring(ctx)
	if err != nil {
		s.logger.Error("object storage deep metrics: failed to list monitoring-enabled object storages", "error", err)
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

func (s *ObjectStorageDeepMetricsScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for objectStorageID := range s.jobs {
		s.collect(ctx, objectStorageID)
	}
}

func (s *ObjectStorageDeepMetricsScheduler) collect(ctx context.Context, objectStorageID uuid.UUID) {
	if _, loaded := s.inFlight.LoadOrStore(objectStorageID, struct{}{}); loaded {
		return
	}
	defer s.inFlight.Delete(objectStorageID)

	// GetObjectStorageByID carries no monitoring-enabled/deleted_at filter
	// of its own, so this re-checks both explicitly -- guards against a
	// storage disabled/soft-deleted between enqueue and this worker
	// actually dequeuing it (mirrors ObjectStorageMetricsScheduler.collect
	// exactly).
	os, err := s.store.GetObjectStorageByID(ctx, objectStorageID)
	if err != nil {
		return
	}
	if !os.MonitoringEnabled || os.DeletedAt.Valid {
		return
	}

	start := time.Now()
	if err := s.deep.CollectDeep(ctx, os); err != nil {
		s.logger.Error("object storage deep metrics: collection failed", "object_storage_id", objectStorageID, "error", err, "duration_ms", time.Since(start).Milliseconds())
		return
	}
	s.logger.Debug("object storage deep metrics: collection completed", "object_storage_id", objectStorageID, "duration_ms", time.Since(start).Milliseconds())
}
