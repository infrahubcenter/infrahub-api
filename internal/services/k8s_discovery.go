package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// normalizeK8sPodPhase maps a pod's phase as Kubernetes itself reports it
// (corev1.PodPhase: "Pending", "Running", "Succeeded", "Failed",
// "Unknown" -- capitalized-first-letter-only, verbatim from the agent) to
// the all-caps vocabulary k8s_pods.phase's CHECK constraint requires
// ('PENDING', 'RUNNING', ...). Without this, every single UpsertK8sPod
// call fails its CHECK constraint on the very first pod of every scan --
// discovery never records a single pod, even though the agent's own
// ListPods call (and every other agent command) succeeded moments
// earlier -- exactly the "Pods: 0 despite a live, connected agent"
// symptom. An unrecognized phase falls back to 'UNKNOWN' rather than
// letting the INSERT fail outright.
func normalizeK8sPodPhase(phase string) string {
	switch strings.ToUpper(phase) {
	case "PENDING", "RUNNING", "SUCCEEDED", "FAILED", "UNKNOWN":
		return strings.ToUpper(phase)
	default:
		return "UNKNOWN"
	}
}

// K8sDiscoveryService asks a cluster's connected agent to list its pods
// and upserts them into k8s_pods -- mirrors DockerDiscoveryService's
// connect/list/upsert/mark-removed shape exactly (internal/services/
// docker_discovery_service.go), just via K8sService/the agent instead of
// SSH + the docker CLI.
type K8sDiscoveryService struct {
	store *repository.Store
	k8s   *K8sService
}

// NewK8sDiscoveryService creates a K8sDiscoveryService.
func NewK8sDiscoveryService(store *repository.Store, k8s *K8sService) *K8sDiscoveryService {
	return &K8sDiscoveryService{store: store, k8s: k8s}
}

// Discover asks clusterID's agent for its pods, upserts every one into
// k8s_pods, and marks any pod not seen in this pass as removed (never
// hard-deleted, same convention as Docker container discovery). Also
// records the connection outcome on the cluster row itself.
func (s *K8sDiscoveryService) Discover(ctx context.Context, clusterID uuid.UUID) error {
	cluster, err := s.store.GetK8sClusterByID(ctx, clusterID)
	if err != nil {
		return fmt.Errorf("load cluster: %w", err)
	}

	namespace := pgutil.TextOrEmpty(cluster.NamespaceFilter) // "" lists every namespace
	pods, err := s.k8s.ListPods(ctx, clusterID, namespace)
	if err != nil {
		s.recordConnectionOutcome(ctx, clusterID, err, "")
		return err
	}

	scanStart := time.Now()
	for _, pod := range pods {
		params := generated.UpsertK8sPodParams{
			K8sClusterID: clusterID, Namespace: pod.Namespace, PodName: pod.PodName,
			NodeName: pgutil.Text(pod.NodeName), Phase: normalizeK8sPodPhase(pod.Phase),
			ReadyContainers: pgutil.Int4(pod.ReadyContainers), TotalContainers: pgutil.Int4(pod.TotalContainers),
			RestartCount: pgutil.Int4(pod.RestartCount),
		}
		if pod.StartedAt != "" {
			if t, err := time.Parse(time.RFC3339, pod.StartedAt); err == nil {
				params.StartedAt = pgutil.Timestamptz(t)
			}
		}
		if pod.CPUMillicores != nil {
			params.CpuUsageMillicores = pgutil.Int8(*pod.CPUMillicores)
		}
		if pod.MemoryBytes != nil {
			params.MemoryUsageBytes = pgutil.Int8(*pod.MemoryBytes)
		}
		if _, err := s.store.UpsertK8sPod(ctx, params); err != nil {
			return fmt.Errorf("upsert pod %s/%s: %w", pod.Namespace, pod.PodName, err)
		}
	}

	if err := s.store.MarkK8sPodsRemovedSince(ctx, generated.MarkK8sPodsRemovedSinceParams{
		K8sClusterID: clusterID, LastDiscoveredAt: pgutil.Timestamptz(scanStart),
	}); err != nil {
		return fmt.Errorf("mark removed pods: %w", err)
	}

	if err := s.store.UpdateK8sClusterDiscovered(ctx, clusterID); err != nil {
		return fmt.Errorf("record discovery timestamp: %w", err)
	}

	// Best-effort: one extra cheap round trip per scan cycle (not per pod)
	// so kubernetes_version keeps itself current automatically as long as
	// discovery keeps succeeding -- never previously fetched here at all,
	// which is why the version stayed blank even for a cluster that had
	// been successfully scanning pods for a while. A failure here never
	// fails the scan itself; the version simply stays whatever it was
	// (UpdateK8sClusterConnectionStatus's own COALESCE).
	version := ""
	if result, err := s.k8s.TestConnection(ctx, clusterID); err == nil {
		version = result.KubernetesVersion
	}
	s.recordConnectionOutcome(ctx, clusterID, nil, version)

	// Best-effort, same spirit as the version fetch above: the broader
	// resource summary (Jobs/CronJobs/ReplicaSets/PVs/StorageClasses/
	// Ingresses/NetworkPolicies/EndpointSlices/ResourceQuotas/
	// LimitRanges/PDBs/HPAs) is what keeps k8s_resources fresh so the
	// Monitoring Overview dashboard survives the agent going offline
	// later, exactly like pods above -- but it's genuinely optional to
	// THIS call succeeding; a failure here never fails Discover itself.
	if summary, err := s.k8s.ClusterResourceSummary(ctx, clusterID); err != nil {
		slog.Warn("k8s discovery: cluster resource summary failed, k8s_resources not refreshed this cycle", "cluster_id", clusterID, "error", err)
	} else {
		s.syncK8sResources(ctx, clusterID, scanStart, summary)
	}
	return nil
}

// k8sResourceItem is the common shape every resource kind's Agent*Item is
// converted to before upserting into k8s_resources -- Detail is
// JSON-marshaled verbatim into that row's jsonb detail column.
type k8sResourceItem struct {
	Namespace string
	Name      string
	Detail    any
}

// syncK8sResources upserts every item across all 12 non-Pod resource
// kinds from one ClusterResourceSummary into k8s_resources, then marks
// anything not seen in this pass as removed -- except for any kind
// listed in summary.FailedKinds, where removal-marking is skipped
// entirely (see that field's own doc comment: a failed fetch's zero
// items must never be mistaken for confirmed emptiness). Errors are
// logged and skipped per kind rather than aborting the whole sweep --
// consistent with the agent's own per-kind error isolation this mirrors.
func (s *K8sDiscoveryService) syncK8sResources(ctx context.Context, clusterID uuid.UUID, scanStart time.Time, summary AgentClusterResourceSummary) {
	failed := make(map[string]bool, len(summary.FailedKinds))
	for _, k := range summary.FailedKinds {
		failed[k] = true
	}

	kinds := []struct {
		kind  string
		items []k8sResourceItem
	}{
		{"replicasets", workloadItemsToResourceItems(summary.ReplicaSetItems)},
		{"jobs", jobItemsToResourceItems(summary.JobItems)},
		{"cronjobs", cronJobItemsToResourceItems(summary.CronJobItems)},
		{"persistentvolumes", pvItemsToResourceItems(summary.PVItems)},
		{"storageclasses", storageClassItemsToResourceItems(summary.StorageClassItems)},
		{"ingresses", ingressItemsToResourceItems(summary.IngressItems)},
		{"networkpolicies", networkPolicyItemsToResourceItems(summary.NetworkPolicyItems)},
		{"endpointslices", endpointSliceItemsToResourceItems(summary.EndpointSliceItems)},
		{"resourcequotas", resourceQuotaItemsToResourceItems(summary.ResourceQuotaItems)},
		{"limitranges", limitRangeItemsToResourceItems(summary.LimitRangeItems)},
		{"poddisruptionbudgets", pdbItemsToResourceItems(summary.PDBItems)},
		{"horizontalpodautoscalers", hpaItemsToResourceItems(summary.HPAItems)},
	}

	for _, k := range kinds {
		for _, item := range k.items {
			detail, err := json.Marshal(item.Detail)
			if err != nil {
				slog.Warn("k8s discovery: marshal resource detail failed", "kind", k.kind, "namespace", item.Namespace, "name", item.Name, "error", err)
				continue
			}
			if _, err := s.store.UpsertK8sResource(ctx, generated.UpsertK8sResourceParams{
				K8sClusterID: clusterID, Kind: k.kind, Namespace: item.Namespace, Name: item.Name, Detail: detail,
			}); err != nil {
				slog.Warn("k8s discovery: upsert resource failed", "kind", k.kind, "namespace", item.Namespace, "name", item.Name, "error", err)
			}
		}
		if failed[k.kind] {
			continue
		}
		if err := s.store.MarkK8sResourcesRemovedSince(ctx, generated.MarkK8sResourcesRemovedSinceParams{
			K8sClusterID: clusterID, Kind: k.kind, LastDiscoveredAt: pgutil.Timestamptz(scanStart),
		}); err != nil {
			slog.Warn("k8s discovery: mark removed resources failed", "kind", k.kind, "error", err)
		}
	}
}

func workloadItemsToResourceItems(items []AgentWorkloadItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

func jobItemsToResourceItems(items []AgentJobItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

func cronJobItemsToResourceItems(items []AgentCronJobItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

// pvItemsToResourceItems -- PersistentVolumes are cluster-scoped, so
// Namespace is always "" (see migration 059's own note on why that's ""
// and not NULL).
func pvItemsToResourceItems(items []AgentPVItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: "", Name: it.Name, Detail: it})
	}
	return out
}

// storageClassItemsToResourceItems -- StorageClasses are cluster-scoped,
// same rationale as pvItemsToResourceItems.
func storageClassItemsToResourceItems(items []AgentStorageClassItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: "", Name: it.Name, Detail: it})
	}
	return out
}

func ingressItemsToResourceItems(items []AgentIngressItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

func networkPolicyItemsToResourceItems(items []AgentNetworkPolicyItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

func endpointSliceItemsToResourceItems(items []AgentEndpointSliceItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

func resourceQuotaItemsToResourceItems(items []AgentResourceQuotaItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

func limitRangeItemsToResourceItems(items []AgentLimitRangeItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

func pdbItemsToResourceItems(items []AgentPodDisruptionBudgetItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

func hpaItemsToResourceItems(items []AgentHPAItem) []k8sResourceItem {
	out := make([]k8sResourceItem, 0, len(items))
	for _, it := range items {
		out = append(out, k8sResourceItem{Namespace: it.Namespace, Name: it.Name, Detail: it})
	}
	return out
}

// recordConnectionOutcome persists the result of one discovery attempt to
// k8s_clusters.connection_status/last_connection_at/last_connection_error/
// kubernetes_version -- mirrors RecordConnectionOutcome (ssh.go)'s role
// for VMs. kubernetesVersion is "" on a failed attempt (COALESCE leaves
// the last-known-good value in place) or when the best-effort version
// fetch itself failed even though pod discovery succeeded.
func (s *K8sDiscoveryService) recordConnectionOutcome(ctx context.Context, clusterID uuid.UUID, connErr error, kubernetesVersion string) {
	params := generated.UpdateK8sClusterConnectionStatusParams{ID: clusterID}
	if kubernetesVersion != "" {
		params.KubernetesVersion = pgutil.Text(kubernetesVersion)
	}
	if connErr == nil {
		params.ConnectionStatus = "CONNECTED"
		params.LastConnectionError = pgutil.Text("")
	} else if errors.Is(connErr, ErrK8sAgentOffline) {
		params.ConnectionStatus = "UNAVAILABLE"
		params.LastConnectionError = pgutil.Text("No agent is currently connected for this cluster.")
	} else {
		params.ConnectionStatus = "UNAVAILABLE"
		params.LastConnectionError = pgutil.Text("The agent reported an error listing pods.")
	}
	_, _ = s.store.UpdateK8sClusterConnectionStatus(ctx, params)
}
