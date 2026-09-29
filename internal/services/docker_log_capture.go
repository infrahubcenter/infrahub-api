// Package services: docker_log_capture.go is the background counterpart to
// docker_logs.go's live-tail WebSocket. That handler only ever relays
// whatever streams by while a browser is actually connected and persists
// nothing; this service periodically runs one bounded, non-follow `docker
// logs --since <cursor> --timestamps` per running container (mirroring
// DockerDiscoveryService's connect-and-run-a-fixed-command shape, not the
// WebSocket's long-lived session), so a searchable history exists whether
// or not anyone was watching live.
package services

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// DockerLogCaptureService captures new log lines for one container per
// call -- CaptureOne is deliberately synchronous and side-effect-bounded
// (one connect, one command, one batch insert) so
// DockerLogCaptureScheduler's worker pool can call it directly, exactly
// like DockerDiscoveryScheduler calls DockerDiscoveryService.Scan.
// Prefers the per-VM Docker agent when one is connected for this
// container's VM (a WebSocket round trip, no SSH at all); otherwise
// falls back to SSH exactly as before.
type DockerLogCaptureService struct {
	store          *repository.Store
	ssh            *SSHService
	executor       *RemoteExecutor
	commandTimeout time.Duration
	retention      time.Duration
	agent          *DockerAgentService
}

// NewDockerLogCaptureService creates a DockerLogCaptureService. retention
// bounds how far back a container's very first capture backfills (never
// further than what the retention cleanup would keep anyway).
func NewDockerLogCaptureService(store *repository.Store, ssh *SSHService, executor *RemoteExecutor, commandTimeout, retention time.Duration, agent *DockerAgentService) *DockerLogCaptureService {
	return &DockerLogCaptureService{store: store, ssh: ssh, executor: executor, commandTimeout: commandTimeout, retention: retention, agent: agent}
}

// CaptureOne pulls whatever log lines arrived since the last capture (or
// since the start of the retention window, on a container's very first
// capture -- never further back, since anything older would be deleted
// by the very next retention pass), stores them, and advances the
// cursor. A connection or command failure is returned for the caller to
// log and move on -- never fatal to the scheduler, and never touches the
// VM's own connection_status (that remains owned by discovery/
// monitoring).
func (s *DockerLogCaptureService) CaptureOne(ctx context.Context, row generated.ListRunningDockerContainersForLogCaptureRow) error {
	if !isDockerHexID(row.ContainerID) {
		return fmt.Errorf("container record is invalid")
	}

	since := time.Now().Add(-s.retention)
	if row.LastLogCapturedAt.Valid {
		since = row.LastLogCapturedAt.Time
	}

	var output string
	if s.agent != nil && s.agent.IsAgentConnected(row.VmResourceID) {
		out, err := s.agent.FetchLogsSince(ctx, row.VmResourceID, row.ContainerID, since)
		if err != nil {
			return fmt.Errorf("fetch logs via agent: %w", err)
		}
		output = out
	} else {
		client, err := s.ssh.Connect(ctx, row.VmResourceID)
		if err != nil {
			return fmt.Errorf("connect: %w", classifyConnectError(err))
		}
		defer client.Close()

		out, err := s.fetchSince(ctx, client, row.ContainerID, since)
		if err != nil {
			return err
		}
		output = out
	}

	lines, latest := parseTimestampedLogLines(output, since)
	if latest.IsZero() {
		latest = since
	}
	if len(lines) == 0 {
		return nil
	}

	for _, line := range lines {
		if err := s.store.InsertDockerLogLine(ctx, generated.InsertDockerLogLineParams{
			DockerContainerID: row.ID, LoggedAt: pgutil.Timestamptz(line.LoggedAt), Line: line.Text,
		}); err != nil {
			return fmt.Errorf("insert log line: %w", err)
		}
	}
	if err := s.store.UpdateDockerContainerLogCursor(ctx, generated.UpdateDockerContainerLogCursorParams{
		ID: row.ID, LastLogCapturedAt: pgutil.Timestamptz(latest),
	}); err != nil {
		return fmt.Errorf("update log cursor: %w", err)
	}
	return nil
}

// fetchSince runs the bounded, non-follow capture command over SSH and
// returns its raw stdout for the caller to parse -- shared parsing (via
// parseTimestampedLogLines) keeps the SSH and agent paths' output
// handling identical. A container that has since stopped/been removed
// commonly exits this command nonzero with no stdout -- treated as "no
// new lines", never an error, mirroring discovery's own permissive
// philosophy for a container that simply isn't there to inspect anymore.
func (s *DockerLogCaptureService) fetchSince(ctx context.Context, client *ssh.Client, containerID string, since time.Time) (string, error) {
	cmd := fmt.Sprintf("docker logs --since %s --timestamps %s", since.UTC().Format(time.RFC3339Nano), containerID)
	res, err := s.executor.Execute(ctx, client, cmd, s.commandTimeout)
	if err != nil {
		return "", fmt.Errorf("run docker logs: %w", err)
	}
	if res.ExitCode != 0 && res.Stdout == "" {
		return "", nil
	}
	return res.Stdout, nil
}

// DockerLogCaptureScheduler periodically captures new log lines for every
// running container across every VM -- structurally identical to
// DockerDiscoveryScheduler: fixed worker pool draining a job channel,
// per-container overlap guard, graceful shutdown.
type DockerLogCaptureScheduler struct {
	store    *repository.Store
	capture  *DockerLogCaptureService
	interval time.Duration
	workers  int32
	logger   *slog.Logger

	jobs     chan generated.ListRunningDockerContainersForLogCaptureRow
	inFlight sync.Map
	wg       sync.WaitGroup
}

// NewDockerLogCaptureScheduler creates a DockerLogCaptureScheduler.
func NewDockerLogCaptureScheduler(store *repository.Store, capture *DockerLogCaptureService, interval time.Duration, workers int32, logger *slog.Logger) *DockerLogCaptureScheduler {
	if workers < 1 {
		workers = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DockerLogCaptureScheduler{store: store, capture: capture, interval: interval, workers: workers, logger: logger}
}

// Run starts the worker pool and ticking dispatcher, blocking until ctx is
// cancelled and every launched goroutine has actually returned.
func (s *DockerLogCaptureScheduler) Run(ctx context.Context) {
	s.jobs = make(chan generated.ListRunningDockerContainersForLogCaptureRow, 128)

	for i := int32(0); i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	s.wg.Add(1)
	go s.dispatch(ctx)

	s.wg.Wait()
	s.logger.Info("docker log capture scheduler stopped")
}

func (s *DockerLogCaptureScheduler) dispatch(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	s.logger.Info("docker log capture scheduler started", "interval", s.interval, "workers", s.workers)
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

func (s *DockerLogCaptureScheduler) enqueueCycle(ctx context.Context) {
	rows, err := s.store.ListRunningDockerContainersForLogCapture(ctx)
	if err != nil {
		s.logger.Error("docker log capture: failed to list running containers", "error", err)
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

func (s *DockerLogCaptureScheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for row := range s.jobs {
		s.captureOne(ctx, row)
	}
}

func (s *DockerLogCaptureScheduler) captureOne(ctx context.Context, row generated.ListRunningDockerContainersForLogCaptureRow) {
	if _, loaded := s.inFlight.LoadOrStore(row.ID, struct{}{}); loaded {
		return // previous cycle's capture for this container is still running
	}
	defer s.inFlight.Delete(row.ID)

	if err := s.capture.CaptureOne(ctx, row); err != nil {
		s.logger.Warn("docker log capture: failed", "container_id", row.ID, "name", row.Name, "error", err)
	}
}
