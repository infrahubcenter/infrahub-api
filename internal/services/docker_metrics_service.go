package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// DockerMetricsResult summarizes one CollectAll call.
type DockerMetricsResult struct {
	Status         string // SUCCESS | FAILED
	ContainerCount int
	ErrorSummary   string
}

// DockerMetricsService collects a point-in-time stats sample for every
// currently running container on a VM. Prefers the per-VM Docker agent
// (docker_agent_hub.go) when one is connected -- a single already-open
// WebSocket round trip, no SSH involved at all; otherwise falls back to
// exactly one SSH connection and exactly one `docker stats --no-stream`
// command per cycle (spec §34 -- mandatory batching, never one
// connection or one command per container). Either source persists a
// snapshot row per matched container and refreshes the shared
// DockerMetricsCache so the WebSocket stream never needs its own round
// trip.
type DockerMetricsService struct {
	store  *repository.Store
	ssh    *SSHService
	docker *DockerClient
	cache  *DockerMetricsCache
	agent  *DockerAgentService
}

// NewDockerMetricsService creates a DockerMetricsService.
func NewDockerMetricsService(store *repository.Store, ssh *SSHService, docker *DockerClient, cache *DockerMetricsCache, agent *DockerAgentService) *DockerMetricsService {
	return &DockerMetricsService{store: store, ssh: ssh, docker: docker, cache: cache, agent: agent}
}

// CollectAll runs one metrics cycle for resourceID.
func (s *DockerMetricsService) CollectAll(ctx context.Context, resourceID uuid.UUID) (DockerMetricsResult, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return DockerMetricsResult{}, fmt.Errorf("load vm: %w", err)
	}

	running, err := s.store.ListRunningDockerContainersByVM(ctx, vm.ID)
	if err != nil {
		return DockerMetricsResult{}, fmt.Errorf("list running containers: %w", err)
	}
	if len(running) == 0 {
		// Nothing currently running -- a normal, valid outcome, not a
		// failure, and no reason to open an SSH connection (or bother the
		// agent) at all.
		return DockerMetricsResult{Status: "SUCCESS"}, nil
	}

	if s.agent != nil && s.agent.IsAgentConnected(resourceID) {
		agentStats, err := s.agent.ContainerStats(ctx, resourceID)
		if err != nil {
			// A connected-but-misbehaving agent is reported exactly like a
			// failed SSH command -- never silently falls back to SSH
			// mid-cycle, which would risk double-counting a snapshot.
			return DockerMetricsResult{Status: "FAILED", ErrorSummary: safeErrorMessage(err)}, nil
		}
		matched, err := s.applyStats(ctx, vm.ID, running, agentContainerStatsToContainerStats(agentStats))
		if err != nil {
			return DockerMetricsResult{}, err
		}
		return DockerMetricsResult{Status: "SUCCESS", ContainerCount: matched}, nil
	}

	client, connErr := s.ssh.Connect(ctx, resourceID)
	if outcomeErr := RecordConnectionOutcome(ctx, s.store, resourceID, vm.ID, connErr); outcomeErr != nil {
		return DockerMetricsResult{}, fmt.Errorf("record connection outcome: %w", outcomeErr)
	}
	if connErr != nil {
		sshErr := classifyConnectError(connErr)
		return DockerMetricsResult{Status: "FAILED", ErrorSummary: "Connection failed: " + sshErr.Message}, nil
	}
	defer client.Close()

	stats, err := s.docker.GetContainerStats(ctx, client)
	if err != nil {
		return DockerMetricsResult{Status: "FAILED", ErrorSummary: safeErrorMessage(err)}, nil
	}

	matched, err := s.applyStats(ctx, vm.ID, running, stats)
	if err != nil {
		return DockerMetricsResult{}, err
	}
	return DockerMetricsResult{Status: "SUCCESS", ContainerCount: matched}, nil
}

// applyStats persists a snapshot row and refreshes the cache for every
// stat that matches a known container -- shared by both the agent and
// SSH collection paths above so they can never drift in how a sample is
// stored.
func (s *DockerMetricsService) applyStats(ctx context.Context, vmRowID uuid.UUID, running []generated.DockerContainer, stats []ContainerStats) (int, error) {
	now := time.Now()
	matched := 0
	for _, stat := range stats {
		container, ok := matchContainerByShortID(running, stat.ContainerID)
		if !ok {
			// The stats source reported a container our last inventory
			// scan doesn't know about yet (started after that scan, or
			// docker_containers.container_id doesn't share its prefix) --
			// skip rather than guess which DB row it belongs to. The next
			// discovery scan (DOCKER_SCAN_INTERVAL) will pick it up, and
			// the next metrics cycle will then match it.
			continue
		}
		if _, err := s.store.InsertDockerContainerMetricSnapshot(ctx, generated.InsertDockerContainerMetricSnapshotParams{
			ContainerID: container.ID, VmID: vmRowID, CpuPercent: pgutil.Float8(stat.CPUPercent),
			MemoryUsageBytes: pgutil.Int8(stat.MemoryUsageBytes), MemoryLimitBytes: dockerMemoryLimitParam(stat),
			MemoryPercent: dockerMemoryPercentParam(stat), NetworkRxBytes: pgutil.Int8(stat.NetworkRxBytes),
			NetworkTxBytes: pgutil.Int8(stat.NetworkTxBytes), BlockReadBytes: pgutil.Int8(stat.BlockReadBytes),
			BlockWriteBytes: pgutil.Int8(stat.BlockWriteBytes), Pids: pgutil.Int4(int32(stat.PIDs)),
		}); err != nil {
			return matched, fmt.Errorf("insert metric snapshot for %s: %w", container.Name, err)
		}
		s.cache.Set(container.ID, stat, now)
		matched++
	}
	return matched, nil
}

// agentContainerStatsToContainerStats adapts the agent's wire shape to
// this package's own ContainerStats (docker_parse.go) -- the two are
// kept field-for-field identical by convention (see
// AgentContainerStats's doc comment) specifically so this is a pure
// relabeling, never a lossy conversion.
func agentContainerStatsToContainerStats(agentStats []AgentContainerStats) []ContainerStats {
	stats := make([]ContainerStats, len(agentStats))
	for i, a := range agentStats {
		stats[i] = ContainerStats{
			ContainerID: a.ContainerID, CPUPercent: a.CPUPercent, MemoryUsageBytes: a.MemoryUsageBytes,
			MemoryLimitBytes: a.MemoryLimitBytes, HasMemoryLimit: a.HasMemoryLimit, MemoryPercent: a.MemoryPercent,
			NetworkRxBytes: a.NetworkRxBytes, NetworkTxBytes: a.NetworkTxBytes, BlockReadBytes: a.BlockReadBytes,
			BlockWriteBytes: a.BlockWriteBytes, PIDs: a.PIDs,
		}
	}
	return stats
}

// matchContainerByShortID finds the DB row whose full container_id
// (recorded from `docker inspect`) starts with `docker stats`' own
// short/truncated container ID -- the two commands report IDs at
// different lengths for the same container.
func matchContainerByShortID(containers []generated.DockerContainer, shortID string) (generated.DockerContainer, bool) {
	if shortID == "" {
		return generated.DockerContainer{}, false
	}
	for _, c := range containers {
		if strings.HasPrefix(c.ContainerID, shortID) {
			return c, true
		}
	}
	return generated.DockerContainer{}, false
}

// dockerMemoryLimitParam/dockerMemoryPercentParam store SQL NULL, never a
// fabricated value, when the container has no real memory limit (spec
// §37) -- ContainerStats.HasMemoryLimit already carries that distinction
// from parsing.
func dockerMemoryLimitParam(stat ContainerStats) pgtype.Int8 {
	if !stat.HasMemoryLimit {
		return pgtype.Int8{}
	}
	return pgutil.Int8(stat.MemoryLimitBytes)
}

func dockerMemoryPercentParam(stat ContainerStats) pgtype.Float8 {
	if !stat.HasMemoryLimit {
		return pgtype.Float8{}
	}
	return pgutil.Float8(stat.MemoryPercent)
}
