// Package services: k8s_log_capture.go mirrors docker_log_capture.go
// exactly, for standalone Kubernetes pods -- a periodic, bounded pull per
// known pod via K8sService.FetchLogsSince (which asks the pod's cluster
// agent for everything since the last capture), independent of
// k8s_logs.go's live-tail WebSocket (which persists nothing).
package services

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// K8sLogCaptureService captures new log lines for one pod per call --
// mirrors DockerLogCaptureService.CaptureOne's shape exactly.
type K8sLogCaptureService struct {
	store     *repository.Store
	k8s       *K8sService
	retention time.Duration
}

// NewK8sLogCaptureService creates a K8sLogCaptureService.
func NewK8sLogCaptureService(store *repository.Store, k8sSvc *K8sService, retention time.Duration) *K8sLogCaptureService {
	return &K8sLogCaptureService{store: store, k8s: k8sSvc, retention: retention}
}

// CaptureOne pulls whatever log lines arrived since the last capture (or
// since the start of the retention window, on a pod's very first
// capture), stores them, and advances the cursor. A pod whose cluster has
// no connected agent right now is treated as "no new lines" -- expected
// and common (the agent may simply not be running at this exact moment),
// never fatal to the scheduler.
func (s *K8sLogCaptureService) CaptureOne(ctx context.Context, row generated.ListRunningK8sPodsForLogCaptureRow) error {
	since := time.Now().Add(-s.retention)
	if row.LastLogCapturedAt.Valid {
		since = row.LastLogCapturedAt.Time
	}

	output, err := s.k8s.FetchLogsSince(ctx, row.K8sClusterID, row.Namespace, row.PodName, since)
	if err != nil {
		if isK8sAgentOfflineErr(err) {
			return nil
		}
		return err
	}

	lines, latest := parseTimestampedLogLines(output, since)
	if len(lines) == 0 {
		return nil
	}

	for _, line := range lines {
		if err := s.store.InsertK8sPodLogLine(ctx, generated.InsertK8sPodLogLineParams{
			K8sPodID: row.ID, LoggedAt: pgutil.Timestamptz(line.LoggedAt), Line: line.Text,
		}); err != nil {
			return err
		}
	}
	return s.store.UpdateK8sPodLogCursor(ctx, generated.UpdateK8sPodLogCursorParams{
		ID: row.ID, LastLogCapturedAt: pgutil.Timestamptz(latest),
	})
}

func isK8sAgentOfflineErr(err error) bool {
	return err == ErrK8sAgentOffline
}

// K8sLogCaptureScheduler periodically captures new log lines for every
// known pod across every monitored cluster -- structurally identical to
// K8sDiscoveryScheduler/DockerLogCaptureScheduler.
type K8sLogCaptureScheduler struct {
	store    *repository.Store
	capture  *K8sLogCaptureService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs     chan generated.ListRunningK8sPodsForLogCaptureRow
	inFlight sync.Map
	wg       sync.WaitGroup
}

// NewK8sLogCaptureScheduler creates a K8sLogCaptureScheduler.
func NewK8sLogCaptureScheduler(store *repository.Store, capture *K8sLogCaptureService, interval time.Duration, workers int32, logger *slog.Logger) *K8sLogCaptureScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &K8sLogCaptureScheduler{store: store, capture: capture, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher, blocking until ctx is
// cancelled and every launched goroutine has actually returned.
func (s *K8sLogCaptureScheduler) Run(ctx context.Context) {
	s.jobs = make(chan generated.ListRunningK8sPodsForLogCaptureRow, 128)

	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	s.wg.Add(1)
	go s.dispatch(ctx)

	s.wg.Wait()
	s.logger.Info("k8s log capture scheduler stopped")
}

func (s *K8sLogCaptureScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("k8s log capture scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *K8sLogCaptureScheduler) enqueueCycle(ctx context.Context) {
	rows, err := s.store.ListRunningK8sPodsForLogCapture(ctx)
	if err != nil {
		s.logger.Error("k8s log capture: failed to list pods", "error", err)
		return
	}
	for _, row := range rows {
		select {
		case s.jobs <- row:
		case <-ctx.Done():
			return
		}
	}
}

func (s *K8sLogCaptureScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for row := range s.jobs {
		s.captureOne(ctx, row)
	}
}

func (s *K8sLogCaptureScheduler) captureOne(ctx context.Context, row generated.ListRunningK8sPodsForLogCaptureRow) {
	if _, loaded := s.inFlight.LoadOrStore(row.ID, struct{}{}); loaded {
		return // previous cycle's capture for this pod is still running
	}
	defer s.inFlight.Delete(row.ID)

	if err := s.capture.CaptureOne(ctx, row); err != nil {
		s.logger.Warn("k8s log capture: failed", "pod_id", row.ID, "pod_name", row.PodName, "error", err)
	}
}
