// Package services: vm_agent.go is the typed layer over VMAgentHub --
// mirrors DockerAgentService's role exactly for the logs half (callers
// never touch the raw VMAgentCommand/VMAgentMessage wire types directly),
// plus HandleMetricsPush, the one method with no Docker-agent analogue:
// it is wired into VMAgentHub as the onPush callback (see main.go), and
// is what actually persists each pushed sample into the fully separate
// vm_agent_metric_snapshots table.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// VMAgentService is the typed layer over VMAgentHub.
type VMAgentService struct {
	store          *repository.Store
	hub            *VMAgentHub
	commandTimeout time.Duration
	metricsPub     *vmAgentMetricsBroadcaster
}

// NewVMAgentService creates a VMAgentService. hub is wired in after
// construction (see cmd/server/main.go) since VMAgentHub itself needs
// this service's HandleMetricsPush as its onPush callback -- the two are
// mutually referential, broken by a two-step construction: build the
// service first (hub nil), build the hub with a closure over the service,
// then call SetHub.
func NewVMAgentService(store *repository.Store, commandTimeout time.Duration) *VMAgentService {
	return &VMAgentService{store: store, commandTimeout: commandTimeout, metricsPub: newVMAgentMetricsBroadcaster()}
}

// SubscribeMetrics registers a live listener for every future metrics
// sample successfully persisted for vmRowID (see HandleMetricsPush) --
// true push, not a poll: a subscriber sees a new sample the instant the
// agent's own push arrives, no ticker involved. The returned cancel func
// must be called exactly once when the caller is done (e.g. on the
// browser WebSocket closing).
func (s *VMAgentService) SubscribeMetrics(vmRowID uuid.UUID) (<-chan generated.VmAgentMetricSnapshot, func()) {
	return s.metricsPub.subscribe(vmRowID)
}

// vmAgentMetricsBroadcaster fans out each freshly-persisted metrics
// snapshot to every currently-subscribed live-view listener for that VM.
// Unlike Database's Live Metrics (a ticker independently re-polling a
// shared cache, see database_metrics_cache.go), this is a real publish:
// HandleMetricsPush calls publish exactly once per successfully-inserted
// sample.
type vmAgentMetricsBroadcaster struct {
	mu   sync.Mutex
	subs map[uuid.UUID]map[chan generated.VmAgentMetricSnapshot]struct{}
}

func newVMAgentMetricsBroadcaster() *vmAgentMetricsBroadcaster {
	return &vmAgentMetricsBroadcaster{subs: map[uuid.UUID]map[chan generated.VmAgentMetricSnapshot]struct{}{}}
}

func (b *vmAgentMetricsBroadcaster) subscribe(vmRowID uuid.UUID) (<-chan generated.VmAgentMetricSnapshot, func()) {
	ch := make(chan generated.VmAgentMetricSnapshot, 4)
	b.mu.Lock()
	if b.subs[vmRowID] == nil {
		b.subs[vmRowID] = map[chan generated.VmAgentMetricSnapshot]struct{}{}
	}
	b.subs[vmRowID][ch] = struct{}{}
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		delete(b.subs[vmRowID], ch)
		if len(b.subs[vmRowID]) == 0 {
			delete(b.subs, vmRowID)
		}
		b.mu.Unlock()
	}
	return ch, cancel
}

// publish never blocks the calling push-worker goroutine on a slow/stuck
// subscriber -- a full channel just drops that one sample for that one
// listener rather than stalling metrics ingestion for every VM.
func (b *vmAgentMetricsBroadcaster) publish(vmRowID uuid.UUID, row generated.VmAgentMetricSnapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[vmRowID] {
		select {
		case ch <- row:
		default:
		}
	}
}

// SetHub wires the hub after both it and this service have been
// constructed -- see NewVMAgentService's doc comment.
func (s *VMAgentService) SetHub(hub *VMAgentHub) {
	s.hub = hub
}

// IsAgentConnected reports whether vmResourceID currently has a live
// agent connection.
func (s *VMAgentService) IsAgentConnected(vmResourceID uuid.UUID) bool {
	return s.hub.IsConnected(vmResourceID)
}

// HandleMetricsPush persists one agent-pushed metrics sample and updates
// the VM's heartbeat -- called from a VMAgentHub push-worker goroutine,
// never from the connection's own read loop (see vm_agent_hub.go). Errors
// are the caller's (the worker's) to log; there is no request to fail
// back to the agent for a push it never expects an answer to.
func (s *VMAgentService) HandleMetricsPush(ctx context.Context, vmResourceID uuid.UUID, data VMAgentMetricsPushData) error {
	vm, err := s.store.GetVMByResourceID(ctx, vmResourceID)
	if err != nil {
		return fmt.Errorf("load vm: %w", err)
	}
	row, err := s.store.InsertVMAgentMetricSnapshot(ctx, generated.InsertVMAgentMetricSnapshotParams{
		VmID:               vm.ID,
		CpuPercent:         pgutil.Float8FromPtr(data.CPUPercent),
		CpuCores:           pgutil.Int4FromPtr(data.CPUCores),
		MemoryUsedBytes:    pgutil.Int8FromPtr(data.MemoryUsedBytes),
		MemoryTotalBytes:   pgutil.Int8FromPtr(data.MemoryTotalBytes),
		SwapUsedBytes:      pgutil.Int8FromPtr(data.SwapUsedBytes),
		SwapTotalBytes:     pgutil.Int8FromPtr(data.SwapTotalBytes),
		Load1m:             pgutil.Float8FromPtr(data.Load1m),
		Load5m:             pgutil.Float8FromPtr(data.Load5m),
		Load15m:            pgutil.Float8FromPtr(data.Load15m),
		UptimeSeconds:      pgutil.Int8FromPtr(data.UptimeSeconds),
		StorageUsedBytes:   pgutil.Int8FromPtr(data.StorageUsedBytes),
		StorageTotalBytes:  pgutil.Int8FromPtr(data.StorageTotalBytes),
		NetworkRxRateBytes: pgutil.Int8FromPtr(data.NetworkRxRateBytes),
		NetworkTxRateBytes: pgutil.Int8FromPtr(data.NetworkTxRateBytes),
		ProcessCount:       pgutil.Int4FromPtr(data.ProcessCount),
	})
	if err != nil {
		return fmt.Errorf("insert metric snapshot: %w", err)
	}
	s.metricsPub.publish(vm.ID, row)
	if _, err := s.store.UpdateVMAgentHeartbeat(ctx, generated.UpdateVMAgentHeartbeatParams{
		ResourceID:           vmResourceID,
		VmAgentOs:            pgutil.TextFromPtr(data.OS),
		VmAgentOsVersion:     pgutil.TextFromPtr(data.OSVersion),
		VmAgentKernelVersion: pgutil.TextFromPtr(data.KernelVersion),
		VmAgentHostname:      pgutil.TextFromPtr(data.Hostname),
	}); err != nil {
		return fmt.Errorf("update heartbeat: %w", err)
	}
	return nil
}

// LatestMetrics returns the most recent agent-pushed sample, if any.
func (s *VMAgentService) LatestMetrics(ctx context.Context, vmRowID uuid.UUID) (generated.VmAgentMetricSnapshot, error) {
	return s.store.GetLatestVMAgentMetricSnapshot(ctx, vmRowID)
}

// MetricsHistory returns every agent-pushed sample since the given time.
func (s *VMAgentService) MetricsHistory(ctx context.Context, vmRowID uuid.UUID, since time.Time) ([]generated.VmAgentMetricSnapshot, error) {
	return s.store.ListVMAgentMetricSnapshotsSince(ctx, generated.ListVMAgentMetricSnapshotsSinceParams{
		VmID: vmRowID, CapturedAt: pgutil.Timestamptz(since),
	})
}

// TestConnection sends a real, synchronous round-trip ping to the
// connected agent and returns how long it took -- unlike IsAgentConnected
// (which just reports whether a WebSocket happens to be open) or the
// heartbeat timestamp (which can be up to a full metrics-push interval
// stale), this proves the agent is actually alive right now. Mirrors
// DockerAgentService.TestConnection's role for Docker hosts.
func (s *VMAgentService) TestConnection(ctx context.Context, vmResourceID uuid.UUID) (time.Duration, error) {
	if !s.hub.IsConnected(vmResourceID) {
		return 0, ErrVMAgentOffline
	}
	reqCtx, cancel := context.WithTimeout(ctx, s.commandTimeout)
	defer cancel()

	start := time.Now()
	if _, err := s.hub.SendCommand(reqCtx, vmResourceID, VMAgentCommand{Type: VMAgentCmdPing}); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// FetchLogsSince asks the connected agent for VM log lines newer than
// since (RFC3339Nano).
func (s *VMAgentService) FetchLogsSince(ctx context.Context, vmResourceID uuid.UUID, since time.Time) (string, error) {
	if !s.hub.IsConnected(vmResourceID) {
		return "", ErrVMAgentOffline
	}
	reqCtx, cancel := context.WithTimeout(ctx, s.commandTimeout)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, vmResourceID, VMAgentCommand{
		Type: VMAgentCmdFetchLogsSince, Since: since.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return "", err
	}
	var result struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("decode agent response: %w", err)
	}
	return result.Output, nil
}

// StreamLogs starts a live, agent-side follow tail of the VM's logs.
func (s *VMAgentService) StreamLogs(vmResourceID uuid.UUID) (<-chan VMAgentMessage, func(), error) {
	if !s.hub.IsConnected(vmResourceID) {
		return nil, nil, ErrVMAgentOffline
	}
	return s.hub.StreamLogs(vmResourceID, "")
}
