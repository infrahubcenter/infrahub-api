package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/repository"
)

// DockerAgentService is the typed layer over DockerAgentHub: it knows
// what each command means and how to decode its response, so callers
// (metrics collection, log capture, the live-tail handler) never touch
// the raw DockerAgentCommand/DockerAgentMessage wire types directly.
// Mirrors K8sService's role exactly.
type DockerAgentService struct {
	store          *repository.Store
	hub            *DockerAgentHub
	commandTimeout time.Duration
}

// NewDockerAgentService creates a DockerAgentService.
func NewDockerAgentService(store *repository.Store, hub *DockerAgentHub, commandTimeout time.Duration) *DockerAgentService {
	return &DockerAgentService{store: store, hub: hub, commandTimeout: commandTimeout}
}

// IsAgentConnected reports whether vmResourceID currently has a live
// agent connection -- callers (metrics/discovery/log-capture schedulers)
// use this to choose agent-based collection over the existing SSH+CLI
// path, per-VM, every cycle.
func (s *DockerAgentService) IsAgentConnected(vmResourceID uuid.UUID) bool {
	return s.hub.IsConnected(vmResourceID)
}

func (s *DockerAgentService) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.commandTimeout)
}

// DockerConnectionTestResult is the safe, structured result of a
// successful connection test.
type DockerConnectionTestResult struct {
	EngineVersion string
	APIVersion    string
	LatencyMS     int64
}

// TestConnection asks the connected agent for the Docker Engine's
// version -- the simplest possible round trip that proves the agent is
// online and can actually reach the local Docker socket.
func (s *DockerAgentService) TestConnection(ctx context.Context, vmResourceID uuid.UUID) (DockerConnectionTestResult, error) {
	if !s.hub.IsConnected(vmResourceID) {
		return DockerConnectionTestResult{}, ErrDockerAgentOffline
	}
	start := time.Now()
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, vmResourceID, DockerAgentCommand{Type: DockerAgentCmdEngineVersion})
	if err != nil {
		return DockerConnectionTestResult{}, err
	}
	var result AgentEngineVersionResult
	if err := json.Unmarshal(data, &result); err != nil {
		return DockerConnectionTestResult{}, fmt.Errorf("decode agent response: %w", err)
	}
	return DockerConnectionTestResult{EngineVersion: result.Version, APIVersion: result.APIVersion, LatencyMS: time.Since(start).Milliseconds()}, nil
}

// ListContainers asks the connected agent to list every container
// (running or not) on its VM.
func (s *DockerAgentService) ListContainers(ctx context.Context, vmResourceID uuid.UUID) ([]AgentContainerInfo, error) {
	if !s.hub.IsConnected(vmResourceID) {
		return nil, ErrDockerAgentOffline
	}
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, vmResourceID, DockerAgentCommand{Type: DockerAgentCmdListContainers})
	if err != nil {
		return nil, err
	}
	var containers []AgentContainerInfo
	if err := json.Unmarshal(data, &containers); err != nil {
		return nil, fmt.Errorf("decode agent response: %w", err)
	}
	return containers, nil
}

// ContainerStats asks the connected agent for a point-in-time stats
// sample of every currently-running container -- the agent-based
// alternative to the SSH path's `docker stats --no-stream` call.
func (s *DockerAgentService) ContainerStats(ctx context.Context, vmResourceID uuid.UUID) ([]AgentContainerStats, error) {
	if !s.hub.IsConnected(vmResourceID) {
		return nil, ErrDockerAgentOffline
	}
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, vmResourceID, DockerAgentCommand{Type: DockerAgentCmdContainerStats})
	if err != nil {
		return nil, err
	}
	var stats []AgentContainerStats
	if err := json.Unmarshal(data, &stats); err != nil {
		return nil, fmt.Errorf("decode agent response: %w", err)
	}
	return stats, nil
}

// HostResources asks the connected agent for the Docker daemon's full
// image/volume/network/build-cache inventory with storage sizes -- the
// agent-based counterpart to `docker system df`, used by both a VM's own
// Docker section and a standalone Docker Host's Monitor dashboard (same
// hub, same protocol, keyed by whichever resource the agent registered
// under).
func (s *DockerAgentService) HostResources(ctx context.Context, resourceID uuid.UUID) (AgentHostResources, error) {
	if !s.hub.IsConnected(resourceID) {
		return AgentHostResources{}, ErrDockerAgentOffline
	}
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, resourceID, DockerAgentCommand{Type: DockerAgentCmdHostResources})
	if err != nil {
		return AgentHostResources{}, err
	}
	var result AgentHostResources
	if err := json.Unmarshal(data, &result); err != nil {
		return AgentHostResources{}, fmt.Errorf("decode agent response: %w", err)
	}
	return result, nil
}

// HostSystemMetrics asks the connected agent for the Docker HOST
// machine's own OS-level CPU/memory/load/disk usage -- see
// AgentHostSystemMetrics's doc comment for why this needs the agent's
// /proc and / bind mounts.
func (s *DockerAgentService) HostSystemMetrics(ctx context.Context, resourceID uuid.UUID) (AgentHostSystemMetrics, error) {
	if !s.hub.IsConnected(resourceID) {
		return AgentHostSystemMetrics{}, ErrDockerAgentOffline
	}
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, resourceID, DockerAgentCommand{Type: DockerAgentCmdHostSystemMetrics})
	if err != nil {
		return AgentHostSystemMetrics{}, err
	}
	var result AgentHostSystemMetrics
	if err := json.Unmarshal(data, &result); err != nil {
		return AgentHostSystemMetrics{}, fmt.Errorf("decode agent response: %w", err)
	}
	return result, nil
}

// FetchLogsSince asks the connected agent for a container's log lines
// newer than since (RFC3339Nano) -- used by the background log-capture
// cycle (never the live-tail stream, which uses StreamLogs below).
func (s *DockerAgentService) FetchLogsSince(ctx context.Context, vmResourceID uuid.UUID, containerID string, since time.Time) (string, error) {
	if !s.hub.IsConnected(vmResourceID) {
		return "", ErrDockerAgentOffline
	}
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, vmResourceID, DockerAgentCommand{
		Type: DockerAgentCmdFetchLogsSince, ContainerID: containerID, Since: since.UTC().Format(time.RFC3339Nano),
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

// StreamLogs starts a live, agent-side `follow` tail of one container's
// logs -- see DockerAgentHub.StreamLogs for the exact channel/cleanup
// contract.
func (s *DockerAgentService) StreamLogs(vmResourceID uuid.UUID, containerID string) (<-chan DockerAgentMessage, func(), error) {
	if !s.hub.IsConnected(vmResourceID) {
		return nil, nil, ErrDockerAgentOffline
	}
	return s.hub.StreamLogs(vmResourceID, containerID, "")
}
