// Package handlers: k8s_overview.go implements Step 25's top-level
// Kubernetes Monitoring dashboard (GET /api/k8s/overview) -- a cross-
// cluster pod list with each pod's latest discovered phase/readiness/
// restart-count/CPU/memory, mirroring docker_overview.go's
// MonitoringOverview exactly. Unlike Docker (which re-queries a live SSH
// stats cache), K8s pod data comes straight from k8s_pods -- the table
// K8sDiscoveryScheduler keeps fresh in the background, so this endpoint
// never talks to a cluster's API server itself.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type K8sOverviewHandler struct {
	store *repository.Store
	authz *services.AuthorizationService
	k8s   *services.K8sService
}

func NewK8sOverviewHandler(store *repository.Store, authz *services.AuthorizationService, k8s *services.K8sService) *K8sOverviewHandler {
	return &K8sOverviewHandler{store: store, authz: authz, k8s: k8s}
}

type k8sOverviewPodDTO struct {
	PodID string `json:"pod_id"`
	// Namespace/PodName/NodeName/ClusterName/ClusterResourceID are the real
	// Kubernetes identity -- Admin-only (see the redaction rule below). A
	// Member's response always has these empty (omitted from the JSON) and
	// relies entirely on DisplayName instead.
	Namespace          string  `json:"namespace,omitempty"`
	PodName            string  `json:"pod_name,omitempty"`
	DisplayName        string  `json:"display_name"`
	NodeName           string  `json:"node_name,omitempty"`
	Phase              string  `json:"phase"`
	ReadyContainers    *int32  `json:"ready_containers,omitempty"`
	TotalContainers    *int32  `json:"total_containers,omitempty"`
	RestartCount       *int32  `json:"restart_count,omitempty"`
	CPUUsageMillicores *int64  `json:"cpu_usage_millicores,omitempty"`
	MemoryUsageBytes   *int64  `json:"memory_usage_bytes,omitempty"`
	StartedAt          *string `json:"started_at,omitempty"`
	// LastDiscoveredAt is when this row's own phase/CPU/memory were last
	// confirmed live from the cluster -- always populated (the discovery
	// scheduler stamps it on every write), unlike the other optional
	// fields above. Lets the frontend flag a pod's status as stale
	// instead of implying it's current when the cluster's agent is
	// offline right now (this list is read straight from k8s_pods, never
	// the live agent -- see this handler's own doc comment).
	LastDiscoveredAt  *string `json:"last_discovered_at,omitempty"`
	ClusterResourceID string  `json:"cluster_resource_id,omitempty"`
	ClusterName       string  `json:"cluster_name,omitempty"`
	WorkspaceName     string  `json:"workspace_name"`
}

// MonitoringOverview handles GET /api/k8s/overview: every pod the caller
// may monitor, across every standalone cluster. Admin sees everything,
// including which cluster and which real pod this is. A Member sees only
// pods on clusters within a Project/Group they hold a k8s.monitor grant
// on, and even then only ever sees the custom App Name (see
// unnamedAppLabel in docker_overview.go) -- never the cluster/namespace/pod
// name, which stay Admin-only infrastructure detail. Mirrors
// DockerHandler.MonitoringOverview exactly.
func (h *K8sOverviewHandler) MonitoringOverview(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	isAdmin := user.IsAdmin()

	resourceIDs, err := h.authz.AccessibleK8sClusterResourceIDsForFeature(r.Context(), user, services.PermK8sMonitor)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return
	}

	// Optional narrowing to one cluster -- used by a Dashboard's Monitoring
	// tab (see handlers/dashboards.go), which is already scoped to exactly
	// one bound cluster by DashboardService.CanView before the frontend
	// ever calls this endpoint with the param set. Mirrors
	// DockerHandler.MonitoringOverview's identical vm_resource_id filter.
	if filter := r.URL.Query().Get("cluster_resource_id"); filter != "" {
		filterID, err := uuid.Parse(filter)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid cluster_resource_id")
			return
		}
		if isAdmin || containsUUID(resourceIDs, filterID) {
			resourceIDs = []uuid.UUID{filterID}
		} else {
			resourceIDs = []uuid.UUID{}
		}
	}

	rows, err := h.store.ListK8sPodsForClusterResourceIDs(r.Context(), resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load pods")
		return
	}

	items := make([]k8sOverviewPodDTO, 0, len(rows))
	for _, row := range rows {
		displayName := pgutil.TextOrEmpty(row.DisplayName)
		dto := k8sOverviewPodDTO{
			PodID: row.ID.String(), Phase: row.Phase, StartedAt: formatTimestamptz(row.StartedAt),
			LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt), WorkspaceName: row.WorkspaceName,
		}
		if isAdmin {
			dto.Namespace = row.Namespace
			dto.PodName = row.PodName
			dto.NodeName = pgutil.TextOrEmpty(row.NodeName)
			dto.ClusterResourceID = row.ClusterResourceID.String()
			dto.ClusterName = row.ClusterName
			dto.DisplayName = displayName
		} else if displayName != "" {
			dto.DisplayName = displayName
		} else {
			dto.DisplayName = unnamedAppLabel
		}
		if row.ReadyContainers.Valid {
			v := row.ReadyContainers.Int32
			dto.ReadyContainers = &v
		}
		if row.TotalContainers.Valid {
			v := row.TotalContainers.Int32
			dto.TotalContainers = &v
		}
		if row.RestartCount.Valid {
			v := row.RestartCount.Int32
			dto.RestartCount = &v
		}
		if row.CpuUsageMillicores.Valid {
			v := row.CpuUsageMillicores.Int64
			dto.CPUUsageMillicores = &v
		}
		if row.MemoryUsageBytes.Valid {
			v := row.MemoryUsageBytes.Int64
			dto.MemoryUsageBytes = &v
		}
		items = append(items, dto)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"pods": items})
}

// ClusterResources handles GET /api/k8s/overview/clusters/:clusterId/resources
// -- the Monitoring>Kubernetes Dashboard Overview page's data source
// (stat cards' resource counts + per-node CPU/Memory/Storage for its
// live charts). Unlike K8sHandler.ResourceSummary/ListNodes (Admin-only
// by design, see k8s.go's own header comment), this is reachable by any
// authenticated role holding k8s.monitor on the cluster's Project/Group
// -- the new Monitoring dashboards must work for Members too, not just
// Admins. Same always-200 operation-endpoint convention as
// K8sHandler.ListNodes/ResourceSummary: no agent connected is an
// expected, common state, not a server error.
func (h *K8sOverviewHandler) ClusterResources(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	clusterID, err := uuid.Parse(r.PathValue("clusterId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	if !user.IsAdmin() {
		resourceIDs, err := h.authz.AccessibleK8sClusterResourceIDsForFeature(r.Context(), user, services.PermK8sMonitor)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		if !containsUUID(resourceIDs, clusterID) {
			httpx.WriteError(w, http.StatusNotFound, "cluster not found")
			return
		}
	}
	cluster, err := h.store.GetK8sClusterByResourceID(r.Context(), clusterID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}

	summary, err := h.k8s.ClusterResourceSummary(r.Context(), cluster.ID)
	if err != nil {
		status, message := "failed", "Unable to reach the cluster's agent."
		if errors.Is(err, services.ErrK8sAgentOffline) {
			status, message = "agent_offline", "No agent is currently connected for this cluster."
		}
		// The 12 k8s_resources-backed kinds still populate here (from the
		// last successful discovery sweep) even though the live agent
		// call above just failed -- that's the entire point of storing
		// them separately; see addPersistedResourceKinds's own doc
		// comment. Everything else in this response (nodes, the 6
		// legacy live-only kinds) has no such fallback and stays empty.
		response := map[string]any{"status": status, "message": message, "nodes": []k8sNodeDTO{}}
		h.addPersistedResourceKinds(r.Context(), clusterID, response)
		httpx.WriteJSON(w, http.StatusOK, response)
		return
	}
	nodes, err := h.k8s.ListNodes(r.Context(), cluster.ID)
	if err != nil {
		nodes = nil // resource counts are still meaningful even if the node detail call itself failed
	}
	nodeItems := make([]k8sNodeDTO, 0, len(nodes))
	for _, n := range nodes {
		nodeItems = append(nodeItems, toK8sNodeDTO(n))
	}
	response := map[string]any{
		"status": "ok", "nodes": nodeItems,
		"namespaces": summary.Namespaces, "node_count": summary.Nodes, "pods": summary.Pods,
		"deployments": summary.Deployments, "stateful_sets": summary.StatefulSets, "daemon_sets": summary.DaemonSets,
		"services": summary.Services, "persistent_volume_claims": summary.PersistentVolumeClaims,
		// Item lists power click-through detail on each stat card (a
		// namespace/deployment/etc.'s actual name, not just its count) --
		// nodes and pods already have full detail above/via the pods tab,
		// so they're not duplicated here.
		"namespace_items":    toK8sNamespaceDTOs(summary.NamespaceItems),
		"deployment_items":   toK8sWorkloadDTOs(summary.DeploymentItems),
		"stateful_set_items": toK8sWorkloadDTOs(summary.StatefulSetItems),
		"daemon_set_items":   toK8sWorkloadDTOs(summary.DaemonSetItems),
		"service_items":      toK8sServiceDTOs(summary.ServiceItems),
		"pvc_items":          toK8sPVCDTOs(summary.PVCItems),
	}
	h.addPersistedResourceKinds(r.Context(), clusterID, response)
	httpx.WriteJSON(w, http.StatusOK, response)
}

// addPersistedResourceKinds fills in the 12 resource kinds backed by
// k8s_resources (Jobs/CronJobs/ReplicaSets/PVs/StorageClasses/Ingresses/
// NetworkPolicies/EndpointSlices/ResourceQuotas/LimitRanges/PDBs/HPAs) --
// unlike everything above (a live agent call that goes to zero the
// moment the agent disconnects), these are read from the DB table the
// discovery scheduler keeps fresh in the background (k8s_discovery.go's
// syncK8sResources), so they keep showing their last-known state with a
// per-item last_discovered_at even while the agent is offline right now
// -- mirroring MonitoringOverview's identical pods-survive-offline
// pattern. Always called regardless of whether the live agent call
// above succeeded.
func (h *K8sOverviewHandler) addPersistedResourceKinds(ctx context.Context, clusterResourceID uuid.UUID, response map[string]any) {
	ids := []uuid.UUID{clusterResourceID}

	replicaSets := h.listK8sResources(ctx, "replicasets", ids)
	response["replica_sets"], response["replica_set_items"] = len(replicaSets), toK8sWorkloadResourceDTOs(replicaSets)

	jobs := h.listK8sResources(ctx, "jobs", ids)
	response["jobs"], response["job_items"] = len(jobs), toK8sJobDTOs(jobs)

	cronJobs := h.listK8sResources(ctx, "cronjobs", ids)
	response["cron_jobs"], response["cron_job_items"] = len(cronJobs), toK8sCronJobDTOs(cronJobs)

	pvs := h.listK8sResources(ctx, "persistentvolumes", ids)
	response["persistent_volumes"], response["pv_items"] = len(pvs), toK8sPVDTOs(pvs)

	storageClasses := h.listK8sResources(ctx, "storageclasses", ids)
	response["storage_classes"], response["storage_class_items"] = len(storageClasses), toK8sStorageClassDTOs(storageClasses)

	ingresses := h.listK8sResources(ctx, "ingresses", ids)
	response["ingresses"], response["ingress_items"] = len(ingresses), toK8sIngressDTOs(ingresses)

	networkPolicies := h.listK8sResources(ctx, "networkpolicies", ids)
	response["network_policies"], response["network_policy_items"] = len(networkPolicies), toK8sNetworkPolicyDTOs(networkPolicies)

	endpointSlices := h.listK8sResources(ctx, "endpointslices", ids)
	response["endpoint_slices"], response["endpoint_slice_items"] = len(endpointSlices), toK8sEndpointSliceDTOs(endpointSlices)

	resourceQuotas := h.listK8sResources(ctx, "resourcequotas", ids)
	response["resource_quotas"], response["resource_quota_items"] = len(resourceQuotas), toK8sResourceQuotaDTOs(resourceQuotas)

	limitRanges := h.listK8sResources(ctx, "limitranges", ids)
	response["limit_ranges"], response["limit_range_items"] = len(limitRanges), toK8sLimitRangeDTOs(limitRanges)

	pdbs := h.listK8sResources(ctx, "poddisruptionbudgets", ids)
	response["pod_disruption_budgets"], response["pdb_items"] = len(pdbs), toK8sPDBDTOs(pdbs)

	hpas := h.listK8sResources(ctx, "horizontalpodautoscalers", ids)
	response["horizontal_pod_autoscalers"], response["hpa_items"] = len(hpas), toK8sHPADTOs(hpas)
}

// listK8sResources fetches one kind's rows for one cluster resource ID --
// a query failure yields an empty (not nil-panicking) result, same
// tolerant convention as this handler's own ListNodes fallback above.
func (h *K8sOverviewHandler) listK8sResources(ctx context.Context, kind string, resourceIDs []uuid.UUID) []generated.ListK8sResourcesForClusterResourceIDsRow {
	rows, err := h.store.ListK8sResourcesForClusterResourceIDs(ctx, generated.ListK8sResourcesForClusterResourceIDsParams{Kind: kind, ResourceIds: resourceIDs})
	if err != nil {
		return nil
	}
	return rows
}

type k8sNamespaceDTO struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func toK8sNamespaceDTOs(items []services.AgentNamespaceItem) []k8sNamespaceDTO {
	out := make([]k8sNamespaceDTO, 0, len(items))
	for _, it := range items {
		out = append(out, k8sNamespaceDTO{Name: it.Name, Status: it.Status})
	}
	return out
}

type k8sWorkloadDTO struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	DesiredReplicas int32  `json:"desired_replicas"`
	ReadyReplicas   int32  `json:"ready_replicas"`
}

func toK8sWorkloadDTOs(items []services.AgentWorkloadItem) []k8sWorkloadDTO {
	out := make([]k8sWorkloadDTO, 0, len(items))
	for _, it := range items {
		out = append(out, k8sWorkloadDTO{Name: it.Name, Namespace: it.Namespace, DesiredReplicas: it.DesiredReplicas, ReadyReplicas: it.ReadyReplicas})
	}
	return out
}

type k8sServiceDTO struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Type      string   `json:"type"`
	ClusterIP string   `json:"cluster_ip,omitempty"`
	Ports     []string `json:"ports,omitempty"`
}

func toK8sServiceDTOs(items []services.AgentServiceItem) []k8sServiceDTO {
	out := make([]k8sServiceDTO, 0, len(items))
	for _, it := range items {
		out = append(out, k8sServiceDTO{Name: it.Name, Namespace: it.Namespace, Type: it.Type, ClusterIP: it.ClusterIP, Ports: it.Ports})
	}
	return out
}

type k8sPVCDTO struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	Status        string `json:"status"`
	CapacityBytes *int64 `json:"capacity_bytes,omitempty"`
	StorageClass  string `json:"storage_class,omitempty"`
}

func toK8sPVCDTOs(items []services.AgentPVCItem) []k8sPVCDTO {
	out := make([]k8sPVCDTO, 0, len(items))
	for _, it := range items {
		out = append(out, k8sPVCDTO{Name: it.Name, Namespace: it.Namespace, Status: it.Status, CapacityBytes: it.CapacityBytes, StorageClass: it.StorageClass})
	}
	return out
}

// --- The 12 k8s_resources-backed kinds below (see addPersistedResourceKinds)
// -- every DTO carries LastDiscoveredAt (unlike the live-agent DTOs above,
// which don't need one) since that's the whole point of reading these
// from the DB: the frontend can show "last confirmed X ago" instead of
// implying the count is live. unmarshalK8sResourceDetail decodes one
// row's jsonb detail column back into the exact Agent*Item struct
// k8s_discovery.go originally marshaled it from.

func unmarshalK8sResourceDetail[T any](row generated.ListK8sResourcesForClusterResourceIDsRow) (T, bool) {
	var detail T
	if err := json.Unmarshal(row.Detail, &detail); err != nil {
		var zero T
		return zero, false
	}
	return detail, true
}

type k8sWorkloadResourceDTO struct {
	k8sWorkloadDTO
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

func toK8sWorkloadResourceDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sWorkloadResourceDTO {
	out := make([]k8sWorkloadResourceDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentWorkloadItem](row); ok {
			out = append(out, k8sWorkloadResourceDTO{
				k8sWorkloadDTO:   k8sWorkloadDTO{Name: it.Name, Namespace: it.Namespace, DesiredReplicas: it.DesiredReplicas, ReadyReplicas: it.ReadyReplicas},
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sJobDTO struct {
	Name             string  `json:"name"`
	Namespace        string  `json:"namespace"`
	Completions      *int32  `json:"completions,omitempty"`
	Succeeded        int32   `json:"succeeded"`
	Failed           int32   `json:"failed"`
	Active           int32   `json:"active"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

func toK8sJobDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sJobDTO {
	out := make([]k8sJobDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentJobItem](row); ok {
			out = append(out, k8sJobDTO{
				Name: it.Name, Namespace: it.Namespace, Completions: it.Completions, Succeeded: it.Succeeded, Failed: it.Failed, Active: it.Active,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sCronJobDTO struct {
	Name             string  `json:"name"`
	Namespace        string  `json:"namespace"`
	Schedule         string  `json:"schedule"`
	Suspended        bool    `json:"suspended"`
	ActiveJobs       int32   `json:"active_jobs"`
	LastScheduleTime string  `json:"last_schedule_time,omitempty"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

func toK8sCronJobDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sCronJobDTO {
	out := make([]k8sCronJobDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentCronJobItem](row); ok {
			out = append(out, k8sCronJobDTO{
				Name: it.Name, Namespace: it.Namespace, Schedule: it.Schedule, Suspended: it.Suspended,
				ActiveJobs: it.ActiveJobs, LastScheduleTime: it.LastScheduleTime,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sPVDTO struct {
	Name             string  `json:"name"`
	Status           string  `json:"status"`
	CapacityBytes    *int64  `json:"capacity_bytes,omitempty"`
	StorageClass     string  `json:"storage_class,omitempty"`
	ReclaimPolicy    string  `json:"reclaim_policy,omitempty"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

func toK8sPVDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sPVDTO {
	out := make([]k8sPVDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentPVItem](row); ok {
			out = append(out, k8sPVDTO{
				Name: it.Name, Status: it.Status, CapacityBytes: it.CapacityBytes, StorageClass: it.StorageClass, ReclaimPolicy: it.ReclaimPolicy,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sStorageClassDTO struct {
	Name             string  `json:"name"`
	Provisioner      string  `json:"provisioner"`
	ReclaimPolicy    string  `json:"reclaim_policy,omitempty"`
	IsDefault        bool    `json:"is_default"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

func toK8sStorageClassDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sStorageClassDTO {
	out := make([]k8sStorageClassDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentStorageClassItem](row); ok {
			out = append(out, k8sStorageClassDTO{
				Name: it.Name, Provisioner: it.Provisioner, ReclaimPolicy: it.ReclaimPolicy, IsDefault: it.IsDefault,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sIngressDTO struct {
	Name             string   `json:"name"`
	Namespace        string   `json:"namespace"`
	ClassName        string   `json:"class_name,omitempty"`
	Hosts            []string `json:"hosts,omitempty"`
	LastDiscoveredAt *string  `json:"last_discovered_at,omitempty"`
}

func toK8sIngressDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sIngressDTO {
	out := make([]k8sIngressDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentIngressItem](row); ok {
			out = append(out, k8sIngressDTO{
				Name: it.Name, Namespace: it.Namespace, ClassName: it.ClassName, Hosts: it.Hosts,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sNetworkPolicyDTO struct {
	Name             string   `json:"name"`
	Namespace        string   `json:"namespace"`
	PolicyTypes      []string `json:"policy_types,omitempty"`
	LastDiscoveredAt *string  `json:"last_discovered_at,omitempty"`
}

func toK8sNetworkPolicyDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sNetworkPolicyDTO {
	out := make([]k8sNetworkPolicyDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentNetworkPolicyItem](row); ok {
			out = append(out, k8sNetworkPolicyDTO{
				Name: it.Name, Namespace: it.Namespace, PolicyTypes: it.PolicyTypes,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sEndpointSliceDTO struct {
	Name             string  `json:"name"`
	Namespace        string  `json:"namespace"`
	AddressType      string  `json:"address_type"`
	EndpointCount    int32   `json:"endpoint_count"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

func toK8sEndpointSliceDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sEndpointSliceDTO {
	out := make([]k8sEndpointSliceDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentEndpointSliceItem](row); ok {
			out = append(out, k8sEndpointSliceDTO{
				Name: it.Name, Namespace: it.Namespace, AddressType: it.AddressType, EndpointCount: it.EndpointCount,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sResourceQuotaDTO struct {
	Name             string            `json:"name"`
	Namespace        string            `json:"namespace"`
	Hard             map[string]string `json:"hard,omitempty"`
	LastDiscoveredAt *string           `json:"last_discovered_at,omitempty"`
}

func toK8sResourceQuotaDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sResourceQuotaDTO {
	out := make([]k8sResourceQuotaDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentResourceQuotaItem](row); ok {
			out = append(out, k8sResourceQuotaDTO{
				Name: it.Name, Namespace: it.Namespace, Hard: it.Hard,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sLimitRangeDTO struct {
	Name             string   `json:"name"`
	Namespace        string   `json:"namespace"`
	Types            []string `json:"types,omitempty"`
	LastDiscoveredAt *string  `json:"last_discovered_at,omitempty"`
}

func toK8sLimitRangeDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sLimitRangeDTO {
	out := make([]k8sLimitRangeDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentLimitRangeItem](row); ok {
			out = append(out, k8sLimitRangeDTO{
				Name: it.Name, Namespace: it.Namespace, Types: it.Types,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sPDBDTO struct {
	Name             string  `json:"name"`
	Namespace        string  `json:"namespace"`
	MinAvailable     string  `json:"min_available,omitempty"`
	MaxUnavailable   string  `json:"max_unavailable,omitempty"`
	CurrentHealthy   int32   `json:"current_healthy"`
	DesiredHealthy   int32   `json:"desired_healthy"`
	ExpectedPods     int32   `json:"expected_pods"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

func toK8sPDBDTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sPDBDTO {
	out := make([]k8sPDBDTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentPodDisruptionBudgetItem](row); ok {
			out = append(out, k8sPDBDTO{
				Name: it.Name, Namespace: it.Namespace, MinAvailable: it.MinAvailable, MaxUnavailable: it.MaxUnavailable,
				CurrentHealthy: it.CurrentHealthy, DesiredHealthy: it.DesiredHealthy, ExpectedPods: it.ExpectedPods,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}

type k8sHPADTO struct {
	Name             string  `json:"name"`
	Namespace        string  `json:"namespace"`
	MinReplicas      *int32  `json:"min_replicas,omitempty"`
	MaxReplicas      int32   `json:"max_replicas"`
	CurrentReplicas  int32   `json:"current_replicas"`
	TargetCPUPercent *int32  `json:"target_cpu_percent,omitempty"`
	LastDiscoveredAt *string `json:"last_discovered_at,omitempty"`
}

func toK8sHPADTOs(rows []generated.ListK8sResourcesForClusterResourceIDsRow) []k8sHPADTO {
	out := make([]k8sHPADTO, 0, len(rows))
	for _, row := range rows {
		if it, ok := unmarshalK8sResourceDetail[services.AgentHPAItem](row); ok {
			out = append(out, k8sHPADTO{
				Name: it.Name, Namespace: it.Namespace, MinReplicas: it.MinReplicas, MaxReplicas: it.MaxReplicas,
				CurrentReplicas: it.CurrentReplicas, TargetCPUPercent: it.TargetCPUPercent,
				LastDiscoveredAt: formatTimestamptz(row.LastDiscoveredAt),
			})
		}
	}
	return out
}
