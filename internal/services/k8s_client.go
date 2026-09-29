// Package services: k8s_client.go defines the wire protocol between
// InfraHub's backend and the in-cluster K8s agent (see /k8s-agent at the
// repo root) -- a small, stable, JSON-over-WebSocket command/response
// protocol. The agent connects OUT to the backend (see k8s_agent_hub.go),
// authenticates with a bearer token (k8s_credential.go), and executes
// commands the backend sends it against its own in-cluster
// ServiceAccount credentials -- InfraHub never holds a kubeconfig or
// cluster-admin credential of any kind. Must stay in sync with the
// agent's own copy of this protocol (k8s-agent/internal/protocol.go).
package services

import (
	"encoding/json"
)

// K8sAgentCommandType enumerates every command the backend can send to a
// connected agent.
type K8sAgentCommandType string

const (
	K8sAgentCmdServerVersion          K8sAgentCommandType = "server_version"
	K8sAgentCmdListPods               K8sAgentCommandType = "list_pods"
	K8sAgentCmdFetchLogsSince         K8sAgentCommandType = "fetch_logs_since"
	K8sAgentCmdStreamLogs             K8sAgentCommandType = "stream_logs"
	K8sAgentCmdStopStream             K8sAgentCommandType = "stop_stream"
	K8sAgentCmdListNodes              K8sAgentCommandType = "list_nodes"
	K8sAgentCmdClusterResourceSummary K8sAgentCommandType = "cluster_resource_summary"
)

// K8sAgentCommand is one backend -> agent message.
type K8sAgentCommand struct {
	ID        string              `json:"id"`
	Type      K8sAgentCommandType `json:"type"`
	Namespace string              `json:"namespace,omitempty"` // "" means every namespace, for list_pods
	PodName   string              `json:"pod_name,omitempty"`
	Since     string              `json:"since,omitempty"` // RFC3339Nano; fetch_logs_since/stream_logs only
}

// K8sAgentMessageType enumerates every message an agent can send back.
type K8sAgentMessageType string

const (
	K8sAgentMsgResult  K8sAgentMessageType = "result"
	K8sAgentMsgLogLine K8sAgentMessageType = "log_line"
	K8sAgentMsgDone    K8sAgentMessageType = "done"
	K8sAgentMsgError   K8sAgentMessageType = "error"
)

// K8sAgentMessage is one agent -> backend message. Data carries a
// command-specific payload for "result" (AgentServerVersionResult or
// []AgentPodInfo, depending which command this answers); Line carries one
// log line for "log_line"; Message carries a safe, already-sanitized
// error description for "error" (the agent itself decides what's safe to
// say -- the backend never inspects raw client-go/Kubernetes error
// internals here, unlike the old kubeconfig-based path).
type K8sAgentMessage struct {
	ID      string              `json:"id"`
	Type    K8sAgentMessageType `json:"type"`
	Data    json.RawMessage     `json:"data,omitempty"`
	Line    string              `json:"line,omitempty"`
	Message string              `json:"message,omitempty"`
}

// AgentPodInfo is what "list_pods" returns, one entry per pod -- a small,
// stable, safe-to-serialize shape (never a raw client-go type), matching
// the same "resource-detail-in-transit" discipline as every other
// discovery payload in this app.
type AgentPodInfo struct {
	Namespace       string `json:"namespace"`
	PodName         string `json:"pod_name"`
	NodeName        string `json:"node_name,omitempty"`
	Phase           string `json:"phase"`
	ReadyContainers int32  `json:"ready_containers"`
	TotalContainers int32  `json:"total_containers"`
	RestartCount    int32  `json:"restart_count"`
	CPUMillicores   *int64 `json:"cpu_millicores,omitempty"`
	MemoryBytes     *int64 `json:"memory_bytes,omitempty"`
	StartedAt       string `json:"started_at,omitempty"` // RFC3339; empty if the pod hasn't started
}

// AgentServerVersionResult is what "server_version" returns.
type AgentServerVersionResult struct {
	Version string `json:"version"`
}

// AgentNodeInfo is what "list_nodes" returns, one entry per cluster node.
// Usage fields (CPU/Memory/Storage) are always best-effort: nil when
// metrics-server or the node's kubelet stats API isn't reachable, never a
// fabricated value -- matching AgentPodInfo's own convention.
type AgentNodeInfo struct {
	Name                     string   `json:"name"`
	Ready                    bool     `json:"ready"`
	Roles                    []string `json:"roles,omitempty"`
	KubeletVersion           string   `json:"kubelet_version,omitempty"`
	OSImage                  string   `json:"os_image,omitempty"`
	CPUCapacityMillicores    int64    `json:"cpu_capacity_millicores"`
	CPUAllocatableMillicores int64    `json:"cpu_allocatable_millicores"`
	CPUUsageMillicores       *int64   `json:"cpu_usage_millicores,omitempty"`
	MemoryCapacityBytes      int64    `json:"memory_capacity_bytes"`
	MemoryAllocatableBytes   int64    `json:"memory_allocatable_bytes"`
	MemoryUsageBytes         *int64   `json:"memory_usage_bytes,omitempty"`
	StorageCapacityBytes     *int64   `json:"storage_capacity_bytes,omitempty"`
	StorageUsageBytes        *int64   `json:"storage_usage_bytes,omitempty"`
	PodCapacity              int64    `json:"pod_capacity,omitempty"`
	PodCount                 int32    `json:"pod_count"`
}

// AgentClusterResourceSummary is what "cluster_resource_summary" returns --
// cluster-wide counts of the resource kinds InfraHub's agent RBAC is
// scoped to read, plus (via the Item lists) each resource's own identity
// for click-through detail. Deliberately excludes Secrets/ConfigMaps and
// every RBAC-object kind (ServiceAccounts/Roles/RoleBindings/
// ClusterRoles/ClusterRoleBindings): this agent's ClusterRole never
// grants access to them (see infrahub-agents/infrahub-k8s-agent/deploy/
// manifest.yaml) precisely so a compromised or curious InfraHub
// deployment can't enumerate a cluster's secret material or
// privilege-escalation surface, even just names. Also deliberately
// excludes Gateway API kinds and VerticalPodAutoscaler (CRD-based, may
// not be installed on a given cluster).
//
// A kind's count/items being zero does not necessarily mean the cluster
// has none of that kind -- see FailedKinds.
type AgentClusterResourceSummary struct {
	Namespaces               int32 `json:"namespaces"`
	Nodes                    int32 `json:"nodes"`
	Pods                     int32 `json:"pods"`
	Deployments              int32 `json:"deployments"`
	StatefulSets             int32 `json:"stateful_sets"`
	DaemonSets               int32 `json:"daemon_sets"`
	ReplicaSets              int32 `json:"replica_sets"`
	Jobs                     int32 `json:"jobs"`
	CronJobs                 int32 `json:"cron_jobs"`
	Services                 int32 `json:"services"`
	PersistentVolumeClaims   int32 `json:"persistent_volume_claims"`
	PersistentVolumes        int32 `json:"persistent_volumes"`
	StorageClasses           int32 `json:"storage_classes"`
	Ingresses                int32 `json:"ingresses"`
	NetworkPolicies          int32 `json:"network_policies"`
	EndpointSlices           int32 `json:"endpoint_slices"`
	ResourceQuotas           int32 `json:"resource_quotas"`
	LimitRanges              int32 `json:"limit_ranges"`
	PodDisruptionBudgets     int32 `json:"pod_disruption_budgets"`
	HorizontalPodAutoscalers int32 `json:"horizontal_pod_autoscalers"`

	NamespaceItems     []AgentNamespaceItem           `json:"namespace_items,omitempty"`
	DeploymentItems    []AgentWorkloadItem            `json:"deployment_items,omitempty"`
	StatefulSetItems   []AgentWorkloadItem            `json:"stateful_set_items,omitempty"`
	DaemonSetItems     []AgentWorkloadItem            `json:"daemon_set_items,omitempty"`
	ReplicaSetItems    []AgentWorkloadItem            `json:"replica_set_items,omitempty"`
	JobItems           []AgentJobItem                 `json:"job_items,omitempty"`
	CronJobItems       []AgentCronJobItem             `json:"cron_job_items,omitempty"`
	ServiceItems       []AgentServiceItem             `json:"service_items,omitempty"`
	PVCItems           []AgentPVCItem                 `json:"pvc_items,omitempty"`
	PVItems            []AgentPVItem                  `json:"pv_items,omitempty"`
	StorageClassItems  []AgentStorageClassItem        `json:"storage_class_items,omitempty"`
	IngressItems       []AgentIngressItem             `json:"ingress_items,omitempty"`
	NetworkPolicyItems []AgentNetworkPolicyItem       `json:"network_policy_items,omitempty"`
	EndpointSliceItems []AgentEndpointSliceItem       `json:"endpoint_slice_items,omitempty"`
	ResourceQuotaItems []AgentResourceQuotaItem       `json:"resource_quota_items,omitempty"`
	LimitRangeItems    []AgentLimitRangeItem          `json:"limit_range_items,omitempty"`
	PDBItems           []AgentPodDisruptionBudgetItem `json:"pdb_items,omitempty"`
	HPAItems           []AgentHPAItem                 `json:"hpa_items,omitempty"`

	// FailedKinds lists which kinds' List() call failed on the agent this
	// round (see infrahub-k8s-agent/k8s.go's logListErr) -- the
	// discovery sweep (k8s_discovery.go) must skip removal-marking for
	// any kind listed here, since its zero count/items reflects a failed
	// fetch, not confirmed emptiness.
	FailedKinds []string `json:"failed_kinds,omitempty"`
}

// AgentNamespaceItem is one entry in AgentClusterResourceSummary.NamespaceItems.
type AgentNamespaceItem struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// AgentWorkloadItem is one entry in AgentClusterResourceSummary's
// Deployment/StatefulSet/DaemonSet item lists.
type AgentWorkloadItem struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	DesiredReplicas int32  `json:"desired_replicas"`
	ReadyReplicas   int32  `json:"ready_replicas"`
}

// AgentServiceItem is one entry in AgentClusterResourceSummary.ServiceItems.
type AgentServiceItem struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Type      string   `json:"type"`
	ClusterIP string   `json:"cluster_ip,omitempty"`
	Ports     []string `json:"ports,omitempty"`
}

// AgentPVCItem is one entry in AgentClusterResourceSummary.PVCItems.
type AgentPVCItem struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	Status        string `json:"status"`
	CapacityBytes *int64 `json:"capacity_bytes,omitempty"`
	StorageClass  string `json:"storage_class,omitempty"`
}

// AgentJobItem is one entry in AgentClusterResourceSummary.JobItems.
type AgentJobItem struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Completions *int32 `json:"completions,omitempty"`
	Succeeded   int32  `json:"succeeded"`
	Failed      int32  `json:"failed"`
	Active      int32  `json:"active"`
}

// AgentCronJobItem is one entry in AgentClusterResourceSummary.CronJobItems.
type AgentCronJobItem struct {
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	Schedule         string `json:"schedule"`
	Suspended        bool   `json:"suspended"`
	ActiveJobs       int32  `json:"active_jobs"`
	LastScheduleTime string `json:"last_schedule_time,omitempty"`
}

// AgentPVItem is one entry in AgentClusterResourceSummary.PVItems.
// PersistentVolumes are cluster-scoped (no namespace).
type AgentPVItem struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	CapacityBytes *int64 `json:"capacity_bytes,omitempty"`
	StorageClass  string `json:"storage_class,omitempty"`
	ReclaimPolicy string `json:"reclaim_policy,omitempty"`
}

// AgentStorageClassItem is one entry in
// AgentClusterResourceSummary.StorageClassItems. StorageClasses are
// cluster-scoped (no namespace).
type AgentStorageClassItem struct {
	Name          string `json:"name"`
	Provisioner   string `json:"provisioner"`
	ReclaimPolicy string `json:"reclaim_policy,omitempty"`
	IsDefault     bool   `json:"is_default"`
}

// AgentIngressItem is one entry in AgentClusterResourceSummary.IngressItems.
type AgentIngressItem struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	ClassName string   `json:"class_name,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
}

// AgentNetworkPolicyItem is one entry in
// AgentClusterResourceSummary.NetworkPolicyItems.
type AgentNetworkPolicyItem struct {
	Name        string   `json:"name"`
	Namespace   string   `json:"namespace"`
	PolicyTypes []string `json:"policy_types,omitempty"`
}

// AgentEndpointSliceItem is one entry in
// AgentClusterResourceSummary.EndpointSliceItems.
type AgentEndpointSliceItem struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	AddressType   string `json:"address_type"`
	EndpointCount int32  `json:"endpoint_count"`
}

// AgentResourceQuotaItem is one entry in
// AgentClusterResourceSummary.ResourceQuotaItems -- Hard is the
// configured limit per resource name (e.g. "cpu": "4", "memory": "8Gi"),
// the actual reason this kind is worth showing at all.
type AgentResourceQuotaItem struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Hard      map[string]string `json:"hard,omitempty"`
}

// AgentLimitRangeItem is one entry in
// AgentClusterResourceSummary.LimitRangeItems -- Types lists which
// LimitType entries (e.g. "Container", "Pod", "PVC") this LimitRange
// constrains.
type AgentLimitRangeItem struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Types     []string `json:"types,omitempty"`
}

// AgentPodDisruptionBudgetItem is one entry in
// AgentClusterResourceSummary.PDBItems.
type AgentPodDisruptionBudgetItem struct {
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	MinAvailable   string `json:"min_available,omitempty"`
	MaxUnavailable string `json:"max_unavailable,omitempty"`
	CurrentHealthy int32  `json:"current_healthy"`
	DesiredHealthy int32  `json:"desired_healthy"`
	ExpectedPods   int32  `json:"expected_pods"`
}

// AgentHPAItem is one entry in AgentClusterResourceSummary.HPAItems.
type AgentHPAItem struct {
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	MinReplicas      *int32 `json:"min_replicas,omitempty"`
	MaxReplicas      int32  `json:"max_replicas"`
	CurrentReplicas  int32  `json:"current_replicas"`
	TargetCPUPercent *int32 `json:"target_cpu_percent,omitempty"`
}
