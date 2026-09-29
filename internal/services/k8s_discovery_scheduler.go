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

// ErrK8sScanInProgress mirrors ErrDockerScanInProgress: a scan for the
// same cluster (scheduled or manual) is already running -- overlapping
// scans are always skipped, never queued.
var ErrK8sScanInProgress = errors.New("a Kubernetes discovery scan is already running for this cluster")

// ErrK8sScanRateLimited mirrors ErrDockerScanRateLimited.
var ErrK8sScanRateLimited = errors.New("a Kubernetes discovery scan was triggered too recently for this cluster; please wait before retrying")

const minManualK8sScanInterval = 30 * time.Second

// K8sDiscoveryScheduler is the background K8s pod-discovery loop --
// structurally identical to DockerDiscoveryScheduler: fixed worker pool
// draining a job channel, per-cluster overlap guard, graceful shutdown.
// Jobs are keyed by k8s_clusters.id (not resources.id) since K8s clusters
// have no VM-style detail-table indirection to resolve.
type K8sDiscoveryScheduler struct {
	store    *repository.Store
	discover *K8sDiscoveryService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs              chan uuid.UUID
	inFlight          sync.Map
	lastManualTrigger sync.Map
	wg                sync.WaitGroup
}

// NewK8sDiscoveryScheduler creates a K8sDiscoveryScheduler.
func NewK8sDiscoveryScheduler(store *repository.Store, discover *K8sDiscoveryService, interval time.Duration, workers int32, logger *slog.Logger) *K8sDiscoveryScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &K8sDiscoveryScheduler{store: store, discover: discover, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher, blocking until ctx
// is cancelled and every launched goroutine has actually returned.
func (s *K8sDiscoveryScheduler) Run(ctx context.Context) {
	s.jobs = make(chan uuid.UUID, 64)

	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	s.wg.Add(1)
	go s.dispatch(ctx)

	s.wg.Wait()
	s.logger.Info("k8s discovery scheduler stopped")
}

func (s *K8sDiscoveryScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("k8s discovery scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *K8sDiscoveryScheduler) enqueueCycle(ctx context.Context) {
	clusters, err := s.store.ListK8sClustersForMonitoring(ctx)
	if err != nil {
		s.logger.Error("k8s scan: failed to list scan-eligible clusters", "error", err)
		return
	}
	for _, cluster := range clusters {
		select {
		case s.jobs <- cluster.ID:
		case <-ctx.Done():
			return
		}
	}
}

func (s *K8sDiscoveryScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for clusterID := range s.jobs {
		s.scan(ctx, clusterID)
	}
}

func (s *K8sDiscoveryScheduler) scan(ctx context.Context, clusterID uuid.UUID) {
	if _, loaded := s.inFlight.LoadOrStore(clusterID, struct{}{}); loaded {
		s.logger.Warn("k8s scan: skipping cycle, previous scan still running", "cluster_id", clusterID)
		return
	}
	defer s.inFlight.Delete(clusterID)

	start := time.Now()
	err := s.discover.Discover(ctx, clusterID)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("k8s scan: failed", "cluster_id", clusterID, "error", err, "duration_ms", duration.Milliseconds())
		return
	}
	s.logger.Info("k8s scan: completed", "cluster_id", clusterID, "duration_ms", duration.Milliseconds())
}

// ScanNow runs one immediate, out-of-band discovery scan -- the admin's
// [Scan] button on a cluster. Shares the overlap guard with the scheduler.
func (s *K8sDiscoveryScheduler) ScanNow(ctx context.Context, clusterID uuid.UUID) error {
	if last, ok := s.lastManualTrigger.Load(clusterID); ok {
		if elapsed := time.Since(last.(time.Time)); elapsed < minManualK8sScanInterval {
			return ErrK8sScanRateLimited
		}
	}
	if _, loaded := s.inFlight.LoadOrStore(clusterID, struct{}{}); loaded {
		return ErrK8sScanInProgress
	}
	defer s.inFlight.Delete(clusterID)
	s.lastManualTrigger.Store(clusterID, time.Now())

	err := s.discover.Discover(ctx, clusterID)
	if err != nil {
		s.logger.Error("k8s scan: failed (manual trigger)", "cluster_id", clusterID, "error", err)
	}
	return err
}
