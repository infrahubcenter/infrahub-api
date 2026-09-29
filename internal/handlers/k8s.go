// Package handlers: k8s.go implements Step 25's Kubernetes cluster
// CRUD/agent-token/connection-test/scan surface -- Admin-only end to end
// (every route mounted behind requireAdmin in router.go), mirroring
// ObjectStorageHandler's own CRUD shape exactly. A Member never reaches
// any handler in this file; their only access to K8s data is the
// cross-cluster Monitoring/Logs dashboards in k8s_overview.go/k8s_logs.go,
// gated by docker_access_grants' k8s.monitor/k8s.logs.
//
// Unlike the retired kubeconfig-upload model, this never accepts or
// stores a cluster credential of any kind -- Configure/RegenerateAgentToken
// instead hand back a one-time-visible bearer token for the admin to
// install into the in-cluster agent (see /k8s-agent at the repo root),
// which then dials OUT to /api/k8s/agent/connect using its own
// ServiceAccount credentials.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type K8sHandler struct {
	store      *repository.Store
	clusters   *services.K8sClusterService
	tokens     *services.K8sAgentTokenService
	k8s        *services.K8sService
	scheduler  *services.K8sDiscoveryScheduler
	audit      *services.AuditService
	backendURL string
}

func NewK8sHandler(
	store *repository.Store, clusters *services.K8sClusterService, tokens *services.K8sAgentTokenService,
	k8sSvc *services.K8sService, scheduler *services.K8sDiscoveryScheduler, audit *services.AuditService, backendURL string,
) *K8sHandler {
	return &K8sHandler{store: store, clusters: clusters, tokens: tokens, k8s: k8sSvc, scheduler: scheduler, audit: audit, backendURL: backendURL}
}

// --- DTOs ---

type k8sClusterDTO struct {
	ID                   string  `json:"id"`
	ResourceID           string  `json:"resource_id"`
	Name                 string  `json:"name"`
	WorkspaceID          string  `json:"workspace_id"`
	WorkspaceName        string  `json:"workspace_name"`
	NamespaceFilter      string  `json:"namespace_filter,omitempty"`
	KubernetesVersion    string  `json:"kubernetes_version,omitempty"`
	MonitoringEnabled    bool    `json:"monitoring_enabled"`
	ConnectionStatus     string  `json:"connection_status"`
	LastConnectionAt     *string `json:"last_connection_at,omitempty"`
	LastConnectionError  string  `json:"last_connection_error,omitempty"`
	LastDiscoveredAt     *string `json:"last_discovered_at,omitempty"`
	AgentTokenConfigured bool    `json:"agent_token_configured"`
	AgentConnected       bool    `json:"agent_connected"`
}

func (h *K8sHandler) toClusterDTO(r *http.Request, cluster generated.ListK8sClustersForAdminRow) k8sClusterDTO {
	dto := k8sClusterDTO{
		ID: cluster.ID.String(), ResourceID: cluster.ResourceID.String(), Name: cluster.ResourceName,
		WorkspaceID: cluster.WorkspaceID.String(), WorkspaceName: cluster.WorkspaceName,
		NamespaceFilter: pgutil.TextOrEmpty(cluster.NamespaceFilter), KubernetesVersion: pgutil.TextOrEmpty(cluster.KubernetesVersion),
		MonitoringEnabled: cluster.MonitoringEnabled, ConnectionStatus: cluster.ConnectionStatus,
		LastConnectionAt: formatTimestamptz(cluster.LastConnectionAt), LastConnectionError: pgutil.TextOrEmpty(cluster.LastConnectionError),
		LastDiscoveredAt: formatTimestamptz(cluster.LastDiscoveredAt),
		AgentConnected:   h.k8s.IsAgentConnected(cluster.ID),
	}
	configured, _ := h.tokens.HasToken(r.Context(), cluster.ID)
	dto.AgentTokenConfigured = configured
	return dto
}

// List handles GET /api/k8s/clusters.
func (h *K8sHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.ListK8sClustersForAdmin(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load clusters")
		return
	}
	items := make([]k8sClusterDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, h.toClusterDTO(r, row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"clusters": items})
}

// Get handles GET /api/k8s/clusters/:id.
func (h *K8sHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	row, err := h.store.GetK8sClusterWithResourceByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.toClusterDTO(r, generated.ListK8sClustersForAdminRow(row)))
}

type configureK8sClusterRequest struct {
	WorkspaceID     string `json:"workspace_id"`
	Name            string `json:"name"`
	NamespaceFilter string `json:"namespace_filter,omitempty"`
}

// configureK8sClusterResponse embeds the cluster DTO plus the freshly
// generated agent token -- AgentToken is present ONLY in this one
// response (and RegenerateAgentToken's), never again afterward; the
// backend only ever stores its hash. BackendURL is this backend's own
// externally-reachable WebSocket connect URL (K8S_AGENT_BACKEND_URL) --
// empty if unconfigured, in which case the frontend falls back to
// deriving one from its own API base (see k8sAgentConnectUrl in api.ts),
// same as before this field existed.
type configureK8sClusterResponse struct {
	k8sClusterDTO
	AgentToken string `json:"agent_token"`
	BackendURL string `json:"backend_url,omitempty"`
}

// Configure handles POST /api/k8s/clusters. Never accepts a credential of
// any kind -- see RegenerateAgentToken for how the admin gets the
// plaintext token to install into their in-cluster agent.
func (h *K8sHandler) Configure(w http.ResponseWriter, r *http.Request) {
	var req configureK8sClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}
	in := services.ConfigureK8sClusterInput{WorkspaceID: workspaceID, Name: req.Name, NamespaceFilter: req.NamespaceFilter}

	cluster, token, err := h.clusters.Configure(r.Context(), in)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditK8sClusterCreated, ResourceType: "K8S_CLUSTER", ResourceID: &cluster.ResourceID,
		Metadata: map[string]any{"name": req.Name},
	})
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditK8sCredentialConfigured, ResourceType: "K8S_CLUSTER", ResourceID: &cluster.ResourceID,
	})

	row, _ := h.store.GetK8sClusterWithResourceByID(r.Context(), cluster.ID)
	httpx.WriteJSON(w, http.StatusCreated, configureK8sClusterResponse{
		k8sClusterDTO: h.toClusterDTO(r, generated.ListK8sClustersForAdminRow(row)), AgentToken: token, BackendURL: h.backendURL,
	})
}

type updateK8sClusterRequest struct {
	NamespaceFilter *string `json:"namespace_filter,omitempty"`
}

// Update handles PATCH /api/k8s/clusters/:id.
func (h *K8sHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	var req updateK8sClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := h.clusters.Update(r.Context(), id, services.UpdateK8sClusterInput{NamespaceFilter: req.NamespaceFilter})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditK8sClusterUpdated, ResourceType: "K8S_CLUSTER", ResourceID: &updated.ResourceID,
	})
	row, _ := h.store.GetK8sClusterWithResourceByID(r.Context(), updated.ID)
	httpx.WriteJSON(w, http.StatusOK, h.toClusterDTO(r, generated.ListK8sClustersForAdminRow(row)))
}

type deleteK8sClusterRequest struct {
	ConfirmationName string `json:"confirmation_name"`
}

// Delete handles DELETE /api/k8s/clusters/:id -- same exact-name
// confirmation discipline as Project/Group/VM/Database/Object Storage
// delete (Step 22).
func (h *K8sHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	var req deleteK8sClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	row, err := h.store.GetK8sClusterWithResourceByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	if req.ConfirmationName != row.ResourceName {
		httpx.WriteError(w, http.StatusBadRequest, services.ErrConfirmationMismatch.Error())
		return
	}
	if err := h.clusters.Delete(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete cluster")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditK8sClusterDeleted, ResourceType: "K8S_CLUSTER", ResourceID: &row.ResourceID,
		Metadata: map[string]any{"name": row.ResourceName},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

type setK8sMonitoringRequest struct {
	Enabled bool `json:"enabled"`
}

// SetMonitoringEnabled handles PUT /api/k8s/clusters/:id/monitoring.
func (h *K8sHandler) SetMonitoringEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	var req setK8sMonitoringRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := h.clusters.SetMonitoringEnabled(r.Context(), id, req.Enabled)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	action := services.AuditK8sMonitoringDisabled
	if req.Enabled {
		action = services.AuditK8sMonitoringEnabled
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: action, ResourceType: "K8S_CLUSTER", ResourceID: &updated.ResourceID})
	row, _ := h.store.GetK8sClusterWithResourceByID(r.Context(), updated.ID)
	httpx.WriteJSON(w, http.StatusOK, h.toClusterDTO(r, generated.ListK8sClustersForAdminRow(row)))
}

// --- Agent token ---

type k8sAgentTokenResponse struct {
	AgentToken string `json:"agent_token"`
	BackendURL string `json:"backend_url,omitempty"`
}

// RegenerateAgentToken handles POST /api/k8s/clusters/:id/agent-token --
// issues a brand new bearer token, immediately invalidating whatever the
// currently-installed agent was using. The response is the ONLY place
// this plaintext token is ever shown; only its hash is stored.
func (h *K8sHandler) RegenerateAgentToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	token, err := h.clusters.RegenerateAgentToken(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditK8sCredentialReplaced, ResourceType: "K8S_CLUSTER", ResourceID: &id,
	})
	httpx.WriteJSON(w, http.StatusOK, k8sAgentTokenResponse{AgentToken: token, BackendURL: h.backendURL})
}

// --- Connection test + scan ---

type k8sConnectionTestResponse struct {
	Status            string `json:"status"`
	KubernetesVersion string `json:"kubernetes_version,omitempty"`
	LatencyMS         int64  `json:"latency_ms,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
	Message           string `json:"message,omitempty"`
}

// TestConnection handles POST /api/k8s/clusters/:id/connection-test. An
// operation endpoint: always 200 with a structured outcome, matching
// SSHHandler.TestConnection's convention.
func (h *K8sHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	result, connErr := h.k8s.TestConnection(r.Context(), id)

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditK8sConnectionTested, ResourceType: "K8S_CLUSTER", ResourceID: &id})

	if connErr != nil {
		code, msg := "K8S_CONNECTION_FAILED", "Unable to connect to the cluster."
		if errors.Is(connErr, services.ErrK8sAgentOffline) {
			code, msg = "K8S_AGENT_OFFLINE", "No agent is currently connected for this cluster. Check that it's installed and running."
		}
		httpx.WriteJSON(w, http.StatusOK, k8sConnectionTestResponse{Status: "failed", ErrorCode: code, Message: msg})
		return
	}
	// Persist immediately -- a manual "Test Connection" click is itself a
	// successful connect+version-fetch, the exact same signal
	// K8sDiscoveryService.recordConnectionOutcome already persists after
	// every periodic scan; without this, kubernetes_version stayed NULL
	// forever (this handler used to only return it in the response, never
	// store it) and the cluster list's "Kubernetes Version" column showed
	// "—" even right after a successful test.
	_, _ = h.store.UpdateK8sClusterConnectionStatus(r.Context(), generated.UpdateK8sClusterConnectionStatusParams{
		ID: id, ConnectionStatus: "CONNECTED", LastConnectionError: pgutil.Text(""),
		KubernetesVersion: pgutil.Text(result.KubernetesVersion),
	})
	httpx.WriteJSON(w, http.StatusOK, k8sConnectionTestResponse{
		Status: "connected", KubernetesVersion: result.KubernetesVersion, LatencyMS: result.LatencyMS,
	})
}

// Scan handles POST /api/k8s/clusters/:id/scan -- an immediate, out-of-
// band pod discovery pass.
func (h *K8sHandler) Scan(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	if _, err := h.store.GetK8sClusterByID(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditK8sDiscoveryStarted, ResourceType: "K8S_CLUSTER", ResourceID: &id})

	if err := h.scheduler.ScanNow(r.Context(), id); err != nil {
		if errors.Is(err, services.ErrK8sScanInProgress) || errors.Is(err, services.ErrK8sScanRateLimited) {
			httpx.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		message := "check that the cluster's agent is installed and connected."
		if errors.Is(err, services.ErrK8sAgentOffline) {
			message = "No agent is currently connected for this cluster."
		}
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &actor.ID, Action: services.AuditK8sDiscoveryFailed, ResourceType: "K8S_CLUSTER", ResourceID: &id,
			Metadata: map[string]any{"error": message},
		})
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "failed", "message": message})
		return
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditK8sDiscoveryCompleted, ResourceType: "K8S_CLUSTER", ResourceID: &id})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "completed"})
}

// --- Cluster-level node detail + resource summary ---

type k8sNodeDTO struct {
	Name                     string   `json:"name"`
	Ready                    bool     `json:"ready"`
	Roles                    []string `json:"roles,omitempty"`
	KubeletVersion           string   `json:"kubelet_version,omitempty"`
	OSImage                  string   `json:"os_image,omitempty"`
	CPUCapacityMillicores    int64    `json:"cpu_capacity_millicores"`
	CPUAllocatableMillicores int64    `json:"cpu_allocatable_millicores"`
	CPUUsageMillicores       *int64   `json:"cpu_usage_millicores,omitempty"`
	CPUUsagePercent          *float64 `json:"cpu_usage_percent,omitempty"`
	MemoryCapacityBytes      int64    `json:"memory_capacity_bytes"`
	MemoryAllocatableBytes   int64    `json:"memory_allocatable_bytes"`
	MemoryUsageBytes         *int64   `json:"memory_usage_bytes,omitempty"`
	MemoryUsagePercent       *float64 `json:"memory_usage_percent,omitempty"`
	StorageCapacityBytes     *int64   `json:"storage_capacity_bytes,omitempty"`
	StorageUsageBytes        *int64   `json:"storage_usage_bytes,omitempty"`
	StorageUsagePercent      *float64 `json:"storage_usage_percent,omitempty"`
	PodCapacity              int64    `json:"pod_capacity,omitempty"`
	PodCount                 int32    `json:"pod_count"`
}

// toK8sNodeDTO derives the *_usage_percent convenience fields here (never
// on the wire from the agent) -- the agent's job is only to report raw
// capacity/usage figures it actually observed.
func toK8sNodeDTO(n services.AgentNodeInfo) k8sNodeDTO {
	dto := k8sNodeDTO{
		Name: n.Name, Ready: n.Ready, Roles: n.Roles, KubeletVersion: n.KubeletVersion, OSImage: n.OSImage,
		CPUCapacityMillicores: n.CPUCapacityMillicores, CPUAllocatableMillicores: n.CPUAllocatableMillicores, CPUUsageMillicores: n.CPUUsageMillicores,
		MemoryCapacityBytes: n.MemoryCapacityBytes, MemoryAllocatableBytes: n.MemoryAllocatableBytes, MemoryUsageBytes: n.MemoryUsageBytes,
		StorageCapacityBytes: n.StorageCapacityBytes, StorageUsageBytes: n.StorageUsageBytes,
		PodCapacity: n.PodCapacity, PodCount: n.PodCount,
	}
	if n.CPUUsageMillicores != nil && n.CPUAllocatableMillicores > 0 {
		p := float64(*n.CPUUsageMillicores) / float64(n.CPUAllocatableMillicores) * 100
		dto.CPUUsagePercent = &p
	}
	if n.MemoryUsageBytes != nil && n.MemoryAllocatableBytes > 0 {
		p := float64(*n.MemoryUsageBytes) / float64(n.MemoryAllocatableBytes) * 100
		dto.MemoryUsagePercent = &p
	}
	if n.StorageUsageBytes != nil && n.StorageCapacityBytes != nil && *n.StorageCapacityBytes > 0 {
		p := float64(*n.StorageUsageBytes) / float64(*n.StorageCapacityBytes) * 100
		dto.StorageUsagePercent = &p
	}
	return dto
}

// ListNodes handles GET /api/k8s/clusters/:id/nodes -- Admin-only,
// cluster-level node detail (CPU/Memory/Storage capacity+usage, pod count)
// straight from the connected agent. An operation endpoint: always 200
// with a structured outcome (status: "ok" | "agent_offline" | "failed"),
// matching TestConnection's convention -- no agent connected right now is
// an expected, common state, not a server error.
func (h *K8sHandler) ListNodes(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	if _, err := h.store.GetK8sClusterByID(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	nodes, err := h.k8s.ListNodes(r.Context(), id)
	if err != nil {
		status, message := "failed", "Unable to reach the cluster's agent."
		if errors.Is(err, services.ErrK8sAgentOffline) {
			status, message = "agent_offline", "No agent is currently connected for this cluster."
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": status, "message": message, "nodes": []k8sNodeDTO{}})
		return
	}
	items := make([]k8sNodeDTO, 0, len(nodes))
	for _, n := range nodes {
		items = append(items, toK8sNodeDTO(n))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "nodes": items})
}

// ResourceSummary handles GET /api/k8s/clusters/:id/resources -- cluster-
// wide counts of the resource kinds the agent's RBAC can read (see
// AgentClusterResourceSummary's doc comment for what's deliberately
// excluded). Same always-200 convention as ListNodes.
func (h *K8sHandler) ResourceSummary(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	if _, err := h.store.GetK8sClusterByID(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "cluster not found")
		return
	}
	summary, err := h.k8s.ClusterResourceSummary(r.Context(), id)
	if err != nil {
		status, message := "failed", "Unable to reach the cluster's agent."
		if errors.Is(err, services.ErrK8sAgentOffline) {
			status, message = "agent_offline", "No agent is currently connected for this cluster."
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": status, "message": message})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "namespaces": summary.Namespaces, "nodes": summary.Nodes, "pods": summary.Pods,
		"deployments": summary.Deployments, "stateful_sets": summary.StatefulSets, "daemon_sets": summary.DaemonSets,
		"services": summary.Services, "persistent_volume_claims": summary.PersistentVolumeClaims,
	})
}

type setPodDisplayNameRequest struct {
	DisplayName string `json:"display_name"`
}

// SetPodDisplayName handles PUT /api/k8s/pods/:podId/name -- Admin-only.
// An empty display_name clears the custom "App Name" label, reverting
// display to the pod's real name everywhere (Monitoring, Logs). Mirrors
// DockerHandler.SetContainerDisplayName exactly.
func (h *K8sHandler) SetPodDisplayName(w http.ResponseWriter, r *http.Request) {
	podID, err := uuid.Parse(r.PathValue("podId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "pod not found")
		return
	}
	var req setPodDisplayNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	trimmed := strings.TrimSpace(req.DisplayName)
	var displayName pgtype.Text
	if trimmed != "" {
		displayName = pgutil.Text(trimmed)
	}

	updated, err := h.store.SetK8sPodDisplayName(r.Context(), generated.SetK8sPodDisplayNameParams{
		ID: podID, DisplayName: displayName,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "pod not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update display name")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditK8sPodRenamed, ResourceType: "K8S_POD", ResourceID: &podID,
		Metadata: map[string]any{"pod_name": updated.PodName, "display_name": trimmed},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": updated.ID.String(), "pod_name": updated.PodName, "display_name": pgutil.TextOrEmpty(updated.DisplayName),
	})
}
