// Package services: docker_host_log_capture.go mirrors docker_log_capture.go
// and k8s_log_capture.go's shape for standalone Docker Hosts (docker-agent,
// not SSH) -- a periodic capture, independent of docker_host.go's
// ListContainers (browser-driven, live-only, persists nothing) and the
// live-tail WebSocket. Unlike VM-hosted Docker containers and Kubernetes
// pods, a Docker Host has no separate discovery step populating a
// container table for a scheduler to simply read -- this service's own
// ListRunningContainerIDs doubles as that discovery, via the same agent
// round trip docker_host.go's ListContainers already makes, and CaptureOne
// upserts docker_host_container_sightings (migration 055/057) itself, so
// history keeps accumulating even while nobody has that host's page open.
package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// DockerHostLogCaptureJob identifies one Docker Host's one running
// container -- the scheduler's own per-container unit of work, expanded
// from ListRunningContainerIDs at the start of each cycle.
type DockerHostLogCaptureJob struct {
	HostResourceID uuid.UUID
	ContainerID    string
}

// DockerHostLogCaptureService captures new log lines for one Docker
// Host's one container per call -- CaptureOne is deliberately
// synchronous and side-effect-bounded, exactly like
// DockerLogCaptureService.CaptureOne/K8sLogCaptureService.CaptureOne.
type DockerHostLogCaptureService struct {
	store     *repository.Store
	agent     *DockerAgentService
	retention time.Duration
}

// NewDockerHostLogCaptureService creates a DockerHostLogCaptureService.
// retention bounds how far back a container's very first capture
// backfills, same discipline as the other two capture services.
func NewDockerHostLogCaptureService(store *repository.Store, agent *DockerAgentService, retention time.Duration) *DockerHostLogCaptureService {
	return &DockerHostLogCaptureService{store: store, agent: agent, retention: retention}
}

// ListRunningContainerIDs asks one Docker Host's agent for its current
// container list and returns only the running ones' ids -- the same
// round trip docker_host.go's ListContainers handler makes, reused here
// as this scheduler's own discovery step. A host whose agent isn't
// connected right now returns ErrDockerAgentOffline, which the caller
// treats as "nothing to capture this cycle," never fatal.
func (s *DockerHostLogCaptureService) ListRunningContainerIDs(ctx context.Context, hostResourceID uuid.UUID) ([]string, error) {
	containers, err := s.agent.ListContainers(ctx, hostResourceID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(containers))
	for _, c := range containers {
		if c.Status == "RUNNING" && isDockerHexID(c.ContainerID) {
			ids = append(ids, c.ContainerID)
		}
	}
	return ids, nil
}

// refreshEngineVersion best-effort refreshes this host's stored
// engine_version -- piggybacks on this scheduler's own already-frequent,
// already-connected touchpoint (see ListRunningContainerIDs above)
// instead of a separate scheduler, so the Docker Hosts list's "Engine
// Version" column stays current automatically. Engine version essentially
// never changes between one cycle and the next, so this is deliberately
// unconditional rather than "only if currently blank" -- simpler, and the
// extra round trip is cheap. A failure here is silently ignored: log
// capture for this host's containers is this cycle's actual job, never
// blocked by this side effect.
func (s *DockerHostLogCaptureService) refreshEngineVersion(ctx context.Context, hostResourceID uuid.UUID) {
	result, err := s.agent.TestConnection(ctx, hostResourceID)
	if err != nil {
		return
	}
	_ = s.store.UpdateDockerHostEngineVersionByResourceID(ctx, generated.UpdateDockerHostEngineVersionByResourceIDParams{
		ResourceID: hostResourceID, EngineVersion: pgutil.Text(result.EngineVersion),
	})
}

// CaptureOne pulls whatever log lines arrived since the last capture (or
// since the start of the retention window, on this container's very
// first capture -- never further back, since anything older would be
// deleted by the very next retention pass), stores them, and advances
// this container's cursor. Also upserts the container's own sighting
// record (see migration 055's own doc comment), independent of whether
// anyone has that host's container list open in a browser right now --
// exactly what makes Docker Host log history keep accumulating even
// while nobody's watching. A connection or command failure is returned
// for the caller to log and move on -- never fatal to the scheduler.
func (s *DockerHostLogCaptureService) CaptureOne(ctx context.Context, job DockerHostLogCaptureJob) error {
	sighting, err := s.store.UpsertDockerHostContainerSighting(ctx, generated.UpsertDockerHostContainerSightingParams{
		DockerHostResourceID: job.HostResourceID, ContainerID: job.ContainerID,
	})
	if err != nil {
		return fmt.Errorf("upsert sighting: %w", err)
	}

	since := time.Now().Add(-s.retention)
	if sighting.LastLogCapturedAt.Valid {
		since = sighting.LastLogCapturedAt.Time
	}

	output, err := s.agent.FetchLogsSince(ctx, job.HostResourceID, job.ContainerID, since)
	if err != nil {
		if errors.Is(err, ErrDockerAgentOffline) {
			return nil
		}
		return fmt.Errorf("fetch logs via agent: %w", err)
	}

	lines, latest := parseTimestampedLogLines(output, since)
	if latest.IsZero() {
		latest = since
	}
	if len(lines) == 0 {
		return nil
	}

	for _, line := range lines {
		if err := s.store.InsertDockerHostContainerLogLine(ctx, generated.InsertDockerHostContainerLogLineParams{
			DockerHostContainerSightingID: sighting.ID, LoggedAt: pgutil.Timestamptz(line.LoggedAt), Line: line.Text,
		}); err != nil {
			return fmt.Errorf("insert log line: %w", err)
		}
	}
	return s.store.UpdateDockerHostContainerLogCursor(ctx, generated.UpdateDockerHostContainerLogCursorParams{
		ID: sighting.ID, LastLogCapturedAt: pgutil.Timestamptz(latest),
	})
}

// DockerHostLogCaptureScheduler periodically captures new log lines for
// every running container across every monitored Docker Host --
// structurally identical to DockerLogCaptureScheduler/
// K8sLogCaptureScheduler, except its own enqueueCycle also performs the
// discovery round trip (ListRunningContainerIDs) per host, since a
// Docker Host has no separate discovery scheduler populating a table of
// known containers the way VM-hosted Docker/Kubernetes already do.
type DockerHostLogCaptureScheduler struct {
	store    *repository.Store
	capture  *DockerHostLogCaptureService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs     chan DockerHostLogCaptureJob
	inFlight sync.Map
	wg       sync.WaitGroup
}

// NewDockerHostLogCaptureScheduler creates a DockerHostLogCaptureScheduler.
func NewDockerHostLogCaptureScheduler(store *repository.Store, capture *DockerHostLogCaptureService, interval time.Duration, workers int32, logger *slog.Logger) *DockerHostLogCaptureScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DockerHostLogCaptureScheduler{store: store, capture: capture, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher, blocking until ctx is
// cancelled and every launched goroutine has actually returned.
func (s *DockerHostLogCaptureScheduler) Run(ctx context.Context) {
	s.jobs = make(chan DockerHostLogCaptureJob, 128)

	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	s.wg.Add(1)
	go s.dispatch(ctx)

	s.wg.Wait()
	s.logger.Info("docker host log capture scheduler stopped")
}

func (s *DockerHostLogCaptureScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("docker host log capture scheduler started", "interval", s.interval, "workers", s.workers)
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

// enqueueCycle both discovers (one ListRunningContainerIDs round trip per
// monitored host) and enqueues -- a host with no agent currently
// connected is skipped for this cycle only, never an error worth logging
// loudly, since that's the expected, common case this whole feature
// exists to tolerate.
func (s *DockerHostLogCaptureScheduler) enqueueCycle(ctx context.Context) {
	hostResourceIDs, err := s.store.ListDockerHostsForLogCapture(ctx)
	if err != nil {
		s.logger.Error("docker host log capture: failed to list hosts", "error", err)
		return
	}
	for _, hostResourceID := range hostResourceIDs {
		containerIDs, err := s.capture.ListRunningContainerIDs(ctx, hostResourceID)
		if err != nil {
			if !errors.Is(err, ErrDockerAgentOffline) {
				s.logger.Warn("docker host log capture: failed to list containers", "host_resource_id", hostResourceID, "error", err)
			}
			continue
		}
		// The agent just proved it's reachable (the list call above
		// succeeded) -- piggyback a best-effort engine_version refresh on
		// this same already-frequent touchpoint rather than a separate
		// scheduler, so the Docker Hosts list's "Engine Version" column
		// stays current automatically once connected, with no admin click
		// required (mirrors what a manual Test Connection now also does).
		s.capture.refreshEngineVersion(ctx, hostResourceID)
		for _, containerID := range containerIDs {
			job := DockerHostLogCaptureJob{HostResourceID: hostResourceID, ContainerID: containerID}
			select {
			case s.jobs <- job:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *DockerHostLogCaptureScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for job := range s.jobs {
		s.captureOne(ctx, job)
	}
}

func (s *DockerHostLogCaptureScheduler) captureOne(ctx context.Context, job DockerHostLogCaptureJob) {
	key := job.HostResourceID.String() + "/" + job.ContainerID
	if _, loaded := s.inFlight.LoadOrStore(key, struct{}{}); loaded {
		return // previous cycle's capture for this container is still running
	}
	defer s.inFlight.Delete(key)

	if err := s.capture.CaptureOne(ctx, job); err != nil {
		s.logger.Warn("docker host log capture: failed", "host_resource_id", job.HostResourceID, "container_id", job.ContainerID, "error", err)
	}
}
