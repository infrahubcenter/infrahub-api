package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/repository"
)

// K8sService is the typed layer over K8sAgentHub: it knows what each
// command means and how to decode its response, so callers (discovery,
// log capture, the live-tail handler) never touch the raw
// K8sAgentCommand/K8sAgentMessage wire types directly. Mirrors
// SSHService's role for VMs -- just backed by an agent's own in-cluster
// credentials instead of a kubeconfig this backend would otherwise have
// to hold.
type K8sService struct {
	store          *repository.Store
	hub            *K8sAgentHub
	commandTimeout time.Duration
}

// NewK8sService creates a K8sService.
func NewK8sService(store *repository.Store, hub *K8sAgentHub, commandTimeout time.Duration) *K8sService {
	return &K8sService{store: store, hub: hub, commandTimeout: commandTimeout}
}

// IsAgentConnected reports whether clusterID currently has a live agent
// connection -- used to give a cluster's connection_status a name-brand
// meaning ("CONNECTED" iff an agent is actually online right now) without
// needing a separate command round trip.
func (s *K8sService) IsAgentConnected(clusterID uuid.UUID) bool {
	return s.hub.IsConnected(clusterID)
}

func (s *K8sService) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.commandTimeout)
}

// K8sConnectionTestResult is the safe, structured result of a successful
// connection test -- never a credential, never agent/client-go internals.
type K8sConnectionTestResult struct {
	KubernetesVersion string
	LatencyMS         int64
}

// TestConnection asks the connected agent for the cluster's Kubernetes
// version -- the simplest possible round trip that proves the agent is
// online and can actually reach its own cluster's API server.
func (s *K8sService) TestConnection(ctx context.Context, clusterID uuid.UUID) (K8sConnectionTestResult, error) {
	if !s.hub.IsConnected(clusterID) {
		return K8sConnectionTestResult{}, ErrK8sAgentOffline
	}
	start := time.Now()
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, clusterID, K8sAgentCommand{Type: K8sAgentCmdServerVersion})
	if err != nil {
		return K8sConnectionTestResult{}, err
	}
	var result AgentServerVersionResult
	if err := json.Unmarshal(data, &result); err != nil {
		return K8sConnectionTestResult{}, fmt.Errorf("decode agent response: %w", err)
	}
	return K8sConnectionTestResult{KubernetesVersion: result.Version, LatencyMS: time.Since(start).Milliseconds()}, nil
}

// ListPods asks the connected agent to list every pod (namespace == ""
// means every namespace) plus best-effort metrics -- the agent itself
// decides whether metrics-server is available; a pod with none simply
// has nil CPU/Memory fields, never a fabricated value.
func (s *K8sService) ListPods(ctx context.Context, clusterID uuid.UUID, namespace string) ([]AgentPodInfo, error) {
	if !s.hub.IsConnected(clusterID) {
		return nil, ErrK8sAgentOffline
	}
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, clusterID, K8sAgentCommand{Type: K8sAgentCmdListPods, Namespace: namespace})
	if err != nil {
		return nil, err
	}
	var pods []AgentPodInfo
	if err := json.Unmarshal(data, &pods); err != nil {
		return nil, fmt.Errorf("decode agent response: %w", err)
	}
	return pods, nil
}

// FetchLogsSince asks the connected agent for a pod's log lines newer
// than since (RFC3339Nano) -- a single bounded, non-follow response, used
// by the background log-capture cycle (never the live-tail stream, which
// uses StreamLogs below).
func (s *K8sService) FetchLogsSince(ctx context.Context, clusterID uuid.UUID, namespace, podName string, since time.Time) (string, error) {
	if !s.hub.IsConnected(clusterID) {
		return "", ErrK8sAgentOffline
	}
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, clusterID, K8sAgentCommand{
		Type: K8sAgentCmdFetchLogsSince, Namespace: namespace, PodName: podName, Since: since.UTC().Format(time.RFC3339Nano),
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

// ListNodes asks the connected agent to list every node in its cluster,
// with best-effort capacity/allocatable/usage figures -- powers the
// cluster-level node detail view (CPU/memory/storage % per node, pod
// count per node).
func (s *K8sService) ListNodes(ctx context.Context, clusterID uuid.UUID) ([]AgentNodeInfo, error) {
	if !s.hub.IsConnected(clusterID) {
		return nil, ErrK8sAgentOffline
	}
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, clusterID, K8sAgentCommand{Type: K8sAgentCmdListNodes})
	if err != nil {
		return nil, err
	}
	var nodes []AgentNodeInfo
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, fmt.Errorf("decode agent response: %w", err)
	}
	return nodes, nil
}

// ClusterResourceSummary asks the connected agent for cluster-wide counts
// of the resource kinds its RBAC can read -- powers the "all resources in
// this cluster" summary alongside the per-node view.
func (s *K8sService) ClusterResourceSummary(ctx context.Context, clusterID uuid.UUID) (AgentClusterResourceSummary, error) {
	if !s.hub.IsConnected(clusterID) {
		return AgentClusterResourceSummary{}, ErrK8sAgentOffline
	}
	reqCtx, cancel := s.withTimeout(ctx)
	defer cancel()

	data, err := s.hub.SendCommand(reqCtx, clusterID, K8sAgentCommand{Type: K8sAgentCmdClusterResourceSummary})
	if err != nil {
		return AgentClusterResourceSummary{}, err
	}
	var summary AgentClusterResourceSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		return AgentClusterResourceSummary{}, fmt.Errorf("decode agent response: %w", err)
	}
	return summary, nil
}

// StreamLogs starts a live, agent-side `follow` tail of one pod's logs --
// see K8sAgentHub.StreamLogs for the exact channel/cleanup contract.
func (s *K8sService) StreamLogs(clusterID uuid.UUID, namespace, podName string) (<-chan K8sAgentMessage, func(), error) {
	if !s.hub.IsConnected(clusterID) {
		return nil, nil, ErrK8sAgentOffline
	}
	return s.hub.StreamLogs(clusterID, namespace, podName, "")
}
