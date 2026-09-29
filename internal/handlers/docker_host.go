// Package handlers: docker_host.go implements the standalone Docker
// Host CRUD/agent-token surface -- Admin-only end to end (every route
// mounted behind requireAdmin in router.go), mirroring k8s.go's
// K8sHandler CRUD shape exactly. A Docker Host has no VM record and no
// SSH access at all: Configure/RegenerateAgentToken hand back a
// one-time-visible bearer token for the admin to run `docker run ...`
// with (see services.DockerAgentRunCommand), which then dials OUT to the
// existing /api/docker-agent/connect endpoint -- the same connect/hub
// plumbing a VM's own SSH-installed agent already uses.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type DockerHostHandler struct {
	store          *repository.Store
	hosts          *services.DockerHostService
	tokens         *services.DockerHostAgentTokenService
	hub            *services.DockerAgentHub
	agents         *services.DockerAgentService
	authz          *services.AuthorizationService
	audit          *services.AuditService
	backendURL     string
	frontendOrigin string
	logRetention   time.Duration
}

// NewDockerHostHandler creates a DockerHostHandler. backendURL is
// config.DockerAgentBackendURL -- the same value DockerAgentInstallService
// embeds into a VM's agent env, reused here to build the `docker run`
// command shown to the admin. agents is the same DockerAgentService a VM's
// own agent uses (see docker_agent.go) -- a Docker Host's resource_id
// registers with the identical DockerAgentHub, so TestConnection below
// needs no Docker-Host-specific service of its own. authz/frontendOrigin
// back the live containers/logs endpoints added for the top-level Docker
// Monitoring/Logs dashboards (see authorizeFeature below) -- every other
// method on this handler stays Admin-only CRUD, untouched by that.
// logRetention is DOCKER_LOG_RETENTION_DAYS (same policy DockerLogsHandler
// uses), backing Search below.
func NewDockerHostHandler(
	store *repository.Store, hosts *services.DockerHostService, tokens *services.DockerHostAgentTokenService,
	hub *services.DockerAgentHub, agents *services.DockerAgentService, authz *services.AuthorizationService,
	audit *services.AuditService, backendURL, frontendOrigin string, logRetention time.Duration,
) *DockerHostHandler {
	return &DockerHostHandler{
		store: store, hosts: hosts, tokens: tokens, hub: hub, agents: agents, authz: authz,
		audit: audit, backendURL: backendURL, frontendOrigin: frontendOrigin, logRetention: logRetention,
	}
}

// authorizeFeature resolves :id as the Docker Host's RESOURCE id (a
// resources.id, NOT a docker_hosts.id) and checks permission
// (PermDockerMonitor/PermDockerLogs) via CanAccessDockerFeature -- the
// same top-level Docker Monitoring/Logs access model a VM's containers
// already use (see docker.go's authorizeVMView, which treats its own
// :id identically as a resource id), now DOCKER_HOST-aware (see
// authorization.go). Deliberately NOT a docker_hosts.id, unlike every
// CRUD method above on this handler: monitoring_dashboards.vm_resource_id
// (and the wizard's own resource picker) already store/use the resource
// id for both VM and Docker Host dashboards alike, so keying these
// routes the same way lets the frontend pass that same id straight
// through with no extra docker_hosts.id lookup. 404-not-403 on failure,
// matching every other resource-scoped endpoint in this app.
func (h *DockerHostHandler) authorizeFeature(w http.ResponseWriter, r *http.Request, permission string) (resourceID uuid.UUID, ok bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return uuid.Nil, false
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return uuid.Nil, false
	}
	allowed, err := h.authz.CanAccessDockerFeature(r.Context(), user, resourceID, permission)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return uuid.Nil, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return uuid.Nil, false
	}
	return resourceID, true
}

// --- DTOs ---

type dockerHostDTO struct {
	ID                   string  `json:"id"`
	ResourceID           string  `json:"resource_id"`
	Name                 string  `json:"name"`
	WorkspaceID          string  `json:"workspace_id"`
	WorkspaceName        string  `json:"workspace_name"`
	EngineVersion        string  `json:"engine_version,omitempty"`
	MonitoringEnabled    bool    `json:"monitoring_enabled"`
	LastConnectionAt     *string `json:"last_connection_at,omitempty"`
	AgentTokenConfigured bool    `json:"agent_token_configured"`
	AgentConnected       bool    `json:"agent_connected"`
}

func (h *DockerHostHandler) toHostDTO(r *http.Request, host generated.ListDockerHostsForAdminRow) dockerHostDTO {
	dto := dockerHostDTO{
		ID: host.ID.String(), ResourceID: host.ResourceID.String(), Name: host.ResourceName,
		WorkspaceID: host.WorkspaceID.String(), WorkspaceName: host.WorkspaceName,
		EngineVersion: pgutil.TextOrEmpty(host.EngineVersion), MonitoringEnabled: host.MonitoringEnabled,
		LastConnectionAt: formatTimestamptz(host.LastConnectionAt),
		AgentConnected:   h.hub.IsConnected(host.ResourceID),
	}
	configured, _ := h.tokens.HasToken(r.Context(), host.ID)
	dto.AgentTokenConfigured = configured
	return dto
}

// List handles GET /api/docker/hosts.
func (h *DockerHostHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.ListDockerHostsForAdmin(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load docker hosts")
		return
	}
	items := make([]dockerHostDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, h.toHostDTO(r, row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"hosts": items})
}

// Get handles GET /api/docker/hosts/:id.
func (h *DockerHostHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return
	}
	row, err := h.store.GetDockerHostWithResourceByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.toHostDTO(r, generated.ListDockerHostsForAdminRow(row)))
}

type configureDockerHostRequest struct {
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
}

// configureDockerHostResponse embeds the host DTO plus the freshly
// generated agent token and the exact `docker run` command to paste --
// AgentToken/RunCommand are present ONLY in this one response (and
// RegenerateAgentToken's), never again afterward; the backend only ever
// stores the token's hash.
type configureDockerHostResponse struct {
	dockerHostDTO
	AgentToken string `json:"agent_token"`
	RunCommand string `json:"run_command"`
}

// Configure handles POST /api/docker/hosts. Never accepts a credential of
// any kind -- see RegenerateAgentToken for how the admin gets the
// plaintext token again later if needed.
func (h *DockerHostHandler) Configure(w http.ResponseWriter, r *http.Request) {
	var req configureDockerHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}

	host, token, err := h.hosts.Configure(r.Context(), services.ConfigureDockerHostInput{WorkspaceID: workspaceID, Name: req.Name})
	if err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDockerHostCreated, ResourceType: "DOCKER_HOST", ResourceID: &host.ResourceID,
		Metadata: map[string]any{"name": req.Name},
	})
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDockerHostCredentialIssued, ResourceType: "DOCKER_HOST", ResourceID: &host.ResourceID,
	})

	row, _ := h.store.GetDockerHostWithResourceByID(r.Context(), host.ID)
	httpx.WriteJSON(w, http.StatusCreated, configureDockerHostResponse{
		dockerHostDTO: h.toHostDTO(r, generated.ListDockerHostsForAdminRow(row)),
		AgentToken:    token, RunCommand: services.DockerAgentRunCommand(h.backendURL, token),
	})
}

type deleteDockerHostRequest struct {
	ConfirmationName string `json:"confirmation_name"`
}

// Delete handles DELETE /api/docker/hosts/:id -- same exact-name
// confirmation discipline as every other resource delete in this app.
func (h *DockerHostHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return
	}
	var req deleteDockerHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	row, err := h.store.GetDockerHostWithResourceByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return
	}
	if req.ConfirmationName != row.ResourceName {
		httpx.WriteError(w, http.StatusBadRequest, services.ErrConfirmationMismatch.Error())
		return
	}
	if err := h.hosts.Delete(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete docker host")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDockerHostDeleted, ResourceType: "DOCKER_HOST", ResourceID: &row.ResourceID,
		Metadata: map[string]any{"name": row.ResourceName},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

type setDockerHostMonitoringRequest struct {
	Enabled bool `json:"enabled"`
}

// SetMonitoringEnabled handles PUT /api/docker/hosts/:id/monitoring.
func (h *DockerHostHandler) SetMonitoringEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return
	}
	var req setDockerHostMonitoringRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := h.hosts.SetMonitoringEnabled(r.Context(), id, req.Enabled)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	action := services.AuditDockerHostMonitoringDisabled
	if req.Enabled {
		action = services.AuditDockerHostMonitoringEnabled
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: action, ResourceType: "DOCKER_HOST", ResourceID: &updated.ResourceID})
	row, _ := h.store.GetDockerHostWithResourceByID(r.Context(), updated.ID)
	httpx.WriteJSON(w, http.StatusOK, h.toHostDTO(r, generated.ListDockerHostsForAdminRow(row)))
}

// TestConnection handles POST /api/docker/hosts/:id/connection-test --
// Admin-only. An operation endpoint: always 200 with a structured
// outcome, matching K8sHandler.TestConnection/DockerAgentHandler.
// TestConnection's convention exactly -- reuses dockerAgentConnectionTestResponse
// (docker_agent.go) since the shape is identical.
func (h *DockerHostHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return
	}
	row, err := h.store.GetDockerHostWithResourceByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return
	}

	result, connErr := h.agents.TestConnection(r.Context(), row.ResourceID)
	if connErr != nil {
		code, msg := "DOCKER_AGENT_CONNECTION_FAILED", "Unable to reach the Docker agent."
		if errors.Is(connErr, services.ErrDockerAgentOffline) {
			code, msg = "DOCKER_AGENT_OFFLINE", "No agent is currently connected for this host. Check that the container is running and can reach this backend."
		}
		httpx.WriteJSON(w, http.StatusOK, dockerAgentConnectionTestResponse{Status: "failed", ErrorCode: code, Message: msg})
		return
	}
	// Persist immediately -- UpdateDockerHostEngineVersion existed but was
	// never called anywhere, so engine_version stayed NULL forever and the
	// host list's "Engine Version" column always showed "—" even right
	// after a successful test.
	_ = h.store.UpdateDockerHostEngineVersion(r.Context(), generated.UpdateDockerHostEngineVersionParams{
		ID: row.ID, EngineVersion: pgutil.Text(result.EngineVersion),
	})
	httpx.WriteJSON(w, http.StatusOK, dockerAgentConnectionTestResponse{
		Status: "connected", EngineVersion: result.EngineVersion, LatencyMS: result.LatencyMS,
	})
}

// --- Agent token ---

type dockerHostAgentTokenResponse struct {
	AgentToken string `json:"agent_token"`
	RunCommand string `json:"run_command"`
}

// RegenerateAgentToken handles POST /api/docker/hosts/:id/agent-token --
// issues a brand new bearer token, immediately invalidating whatever the
// currently-running agent container was using. The response is the ONLY
// place this plaintext token is ever shown again; only its hash is
// stored.
func (h *DockerHostHandler) RegenerateAgentToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "docker host not found")
		return
	}
	token, err := h.hosts.RegenerateAgentToken(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDockerHostCredentialReplaced, ResourceType: "DOCKER_HOST", ResourceID: &id,
	})
	httpx.WriteJSON(w, http.StatusOK, dockerHostAgentTokenResponse{
		AgentToken: token, RunCommand: services.DockerAgentRunCommand(h.backendURL, token),
	})
}

// --- Live containers/stats/logs (top-level Docker Monitoring/Logs
// dashboards bound to a Docker Host -- live-only, nothing persisted; see
// services/monitoring_dashboards.go's doc comment and the Docker Hosts
// live-dashboard plan). Gated by docker.monitor/docker.logs via
// authorizeFeature above, not requireAdmin -- unlike every method above
// this one, which is pure Admin-only CRUD/agent management.

type dockerHostContainerMetricDTO struct {
	CPUPercent       *float64 `json:"cpu_percent,omitempty"`
	MemoryUsageBytes *int64   `json:"memory_usage_bytes,omitempty"`
	MemoryLimitBytes *int64   `json:"memory_limit_bytes,omitempty"`
	MemoryPercent    *float64 `json:"memory_percent,omitempty"`
	NetworkRxBytes   *int64   `json:"network_rx_bytes,omitempty"`
	NetworkTxBytes   *int64   `json:"network_tx_bytes,omitempty"`
	BlockReadBytes   *int64   `json:"block_read_bytes,omitempty"`
	BlockWriteBytes  *int64   `json:"block_write_bytes,omitempty"`
	Pids             *int32   `json:"pids,omitempty"`
}

// dockerHostContainerDTO mirrors dockerContainerDTO (docker.go) closely
// enough for frontend rendering reuse, but is sourced live from the
// connected agent -- no `id`/`display_name` fields (those are
// docker_containers-table-only concepts; a Docker Host's containers are
// never persisted, so there is no DB row to hold an admin-set custom
// label). ContainerID is the real Docker container ID string -- this
// DTO's own identity, since there is no synthetic DB row to key on
// instead.
type dockerHostContainerDTO struct {
	ContainerID     string `json:"container_id"`
	Name            string `json:"name"`
	Image           string `json:"image"`
	Status          string `json:"status"`
	State           string `json:"state,omitempty"`
	Health          string `json:"health,omitempty"`
	Command         string `json:"command,omitempty"`
	RestartCount    int    `json:"restart_count"`
	CreatedAtRemote string `json:"created_at_remote,omitempty"`
	StartedAtRemote string `json:"started_at_remote,omitempty"`
	// FirstSeenAt is InfraHub's own record of when this container_id was
	// first reported by this host's agent -- distinct from
	// CreatedAtRemote (Docker's own container-creation timestamp). See
	// docker_host_container_sightings (migration 055).
	FirstSeenAt string                        `json:"first_seen_at,omitempty"`
	Metrics     *dockerHostContainerMetricDTO `json:"metrics,omitempty"`
}

func toDockerHostContainerDTO(c services.AgentContainerInfo, stats services.AgentContainerStats, hasStats bool) dockerHostContainerDTO {
	dto := dockerHostContainerDTO{
		ContainerID: c.ContainerID, Name: c.Name, Image: c.Image, Status: c.Status, State: c.State,
		Health: c.Health, Command: c.Command, RestartCount: c.RestartCount,
		CreatedAtRemote: c.CreatedAt, StartedAtRemote: c.StartedAt,
	}
	if dto.Health == "" {
		dto.Health = "NO_HEALTHCHECK" // matches normalizeHealthStatus's convention (docker_parse.go), which the agent doesn't apply itself
	}
	if hasStats {
		dto.Metrics = &dockerHostContainerMetricDTO{
			CPUPercent: float64Ptr(stats.CPUPercent), MemoryUsageBytes: int64Ptr(stats.MemoryUsageBytes),
			NetworkRxBytes: int64Ptr(stats.NetworkRxBytes), NetworkTxBytes: int64Ptr(stats.NetworkTxBytes),
			BlockReadBytes: int64Ptr(stats.BlockReadBytes), BlockWriteBytes: int64Ptr(stats.BlockWriteBytes),
			Pids: int32Ptr(int32(stats.PIDs)),
		}
		if stats.HasMemoryLimit {
			dto.Metrics.MemoryLimitBytes = int64Ptr(stats.MemoryLimitBytes)
			dto.Metrics.MemoryPercent = float64Ptr(stats.MemoryPercent)
		}
	}
	return dto
}

// ListContainers handles GET /api/docker/hosts/{id}/containers -- calls
// DockerAgentService.ListContainers + ContainerStats directly, no DB
// write and no docker_containers row involved. Combined into one response
// (never a separate stats endpoint): the wire protocol already issues two
// separate agent round trips regardless, and this mirrors
// /api/docker/overview's own embedded-metrics-per-container shape so the
// dashboard page's poll loop needs no special-casing for a
// Docker-Host-bound dashboard.
func (h *DockerHostHandler) ListContainers(w http.ResponseWriter, r *http.Request) {
	resourceID, ok := h.authorizeFeature(w, r, services.PermDockerMonitor)
	if !ok {
		return
	}
	containers, err := h.agents.ListContainers(r.Context(), resourceID)
	if err != nil {
		if errors.Is(err, services.ErrDockerAgentOffline) {
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"containers": []dockerHostContainerDTO{}, "total": 0, "agent_connected": false})
			return
		}
		httpx.WriteError(w, http.StatusBadGateway, "failed to reach docker agent")
		return
	}
	statsByID := map[string]services.AgentContainerStats{}
	if stats, err := h.agents.ContainerStats(r.Context(), resourceID); err == nil {
		for _, s := range stats {
			statsByID[s.ContainerID] = s
		}
	} // best-effort: a stats failure never fails the whole list, just omits Metrics

	items := make([]dockerHostContainerDTO, 0, len(containers))
	for _, c := range containers {
		stats, hasStats := statsByID[c.ContainerID]
		dto := toDockerHostContainerDTO(c, stats, hasStats)
		// Best-effort: stamps/refreshes this container's sighting record so
		// FirstSeenAt is available from the very next call onward. A
		// failure here (e.g. a transient DB hiccup) never fails the list
		// itself -- it only means this one container's FirstSeenAt is
		// empty for this response, same fallback as the stats-lookup miss
		// above.
		if sighting, err := h.store.UpsertDockerHostContainerSighting(r.Context(), generated.UpsertDockerHostContainerSightingParams{
			DockerHostResourceID: resourceID, ContainerID: c.ContainerID,
		}); err == nil {
			dto.FirstSeenAt = formatTimestamptzOrEmpty(sighting.FirstSeenAt)
		}
		items = append(items, dto)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"containers": items, "total": len(items), "agent_connected": true})
}

type dockerHostImageDTO struct {
	ID         string   `json:"id"`
	RepoTags   []string `json:"repo_tags,omitempty"`
	SizeBytes  int64    `json:"size_bytes"`
	Containers int64    `json:"containers"`
	CreatedAt  string   `json:"created_at,omitempty"`
}

type dockerHostVolumeDTO struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint,omitempty"`
	SizeBytes  *int64 `json:"size_bytes,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

type dockerHostNetworkDTO struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Scope      string `json:"scope"`
	Containers int    `json:"containers"`
}

type dockerHostBuildCacheDTO struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	SizeBytes   int64  `json:"size_bytes"`
	InUse       bool   `json:"in_use"`
	Shared      bool   `json:"shared"`
	LastUsedAt  string `json:"last_used_at,omitempty"`
}

// HostResources handles GET /api/docker/hosts/{id}/resources -- the full
// image/volume/network/build-cache inventory with storage sizes, powering
// the Monitor dashboard's click-through detail (a "not tracked yet" gap
// this closes: see DockerAgentService.HostResources's doc comment). Same
// always-200-with-agent_connected-false convention as ListContainers
// above, and works identically for a VM's own Docker section (same hub,
// same resourceID scoping).
func (h *DockerHostHandler) HostResources(w http.ResponseWriter, r *http.Request) {
	resourceID, ok := h.authorizeFeature(w, r, services.PermDockerMonitor)
	if !ok {
		return
	}
	resources, err := h.agents.HostResources(r.Context(), resourceID)
	if err != nil {
		if errors.Is(err, services.ErrDockerAgentOffline) {
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"agent_connected": false})
			return
		}
		httpx.WriteError(w, http.StatusBadGateway, "failed to reach docker agent")
		return
	}

	images := make([]dockerHostImageDTO, 0, len(resources.Images))
	for _, img := range resources.Images {
		images = append(images, dockerHostImageDTO{ID: img.ID, RepoTags: img.RepoTags, SizeBytes: img.SizeBytes, Containers: img.Containers, CreatedAt: img.CreatedAt})
	}
	volumes := make([]dockerHostVolumeDTO, 0, len(resources.Volumes))
	for _, vol := range resources.Volumes {
		volumes = append(volumes, dockerHostVolumeDTO{Name: vol.Name, Driver: vol.Driver, Mountpoint: vol.Mountpoint, SizeBytes: vol.SizeBytes, CreatedAt: vol.CreatedAt})
	}
	networks := make([]dockerHostNetworkDTO, 0, len(resources.Networks))
	for _, n := range resources.Networks {
		networks = append(networks, dockerHostNetworkDTO{ID: n.ID, Name: n.Name, Driver: n.Driver, Scope: n.Scope, Containers: n.Containers})
	}
	buildCache := make([]dockerHostBuildCacheDTO, 0, len(resources.BuildCache))
	for _, bc := range resources.BuildCache {
		buildCache = append(buildCache, dockerHostBuildCacheDTO{
			ID: bc.ID, Type: bc.Type, Description: bc.Description, SizeBytes: bc.SizeBytes, InUse: bc.InUse, Shared: bc.Shared, LastUsedAt: bc.LastUsedAt,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"agent_connected": true,
		"images":          images, "volumes": volumes, "networks": networks, "build_cache": buildCache,
		"total_images_size_bytes":      resources.TotalImagesSizeBytes,
		"total_volumes_size_bytes":     resources.TotalVolumesSizeBytes,
		"total_build_cache_size_bytes": resources.TotalBuildCacheSizeBytes,
	})
}

// SystemMetrics handles GET /api/docker/hosts/{id}/system-metrics -- the
// Docker HOST machine's own OS-level CPU/memory/load/disk usage (see
// AgentHostSystemMetrics's doc comment for why this is genuinely
// impossible any other way while staying agent-only, no SSH/VM Agent).
// Unlike HostResources above, a *connected* agent can still fail here
// specifically -- one installed before this feature existed has neither
// of the two new bind mounts this needs, so `available: false` (with the
// agent's own error message) is a distinct, expected response the
// frontend shows as "reinstall the agent" rather than a generic failure.
func (h *DockerHostHandler) SystemMetrics(w http.ResponseWriter, r *http.Request) {
	resourceID, ok := h.authorizeFeature(w, r, services.PermDockerMonitor)
	if !ok {
		return
	}
	metrics, err := h.agents.HostSystemMetrics(r.Context(), resourceID)
	if err != nil {
		if errors.Is(err, services.ErrDockerAgentOffline) {
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"agent_connected": false, "available": false})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"agent_connected": true, "available": false, "error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"agent_connected": true, "available": true,
		"cpu_percent": metrics.CPUPercent, "cpu_cores": metrics.CPUCores,
		"memory_total_bytes": metrics.MemoryTotalBytes, "memory_used_bytes": metrics.MemoryUsedBytes,
		"load_avg_1": metrics.LoadAvg1, "load_avg_5": metrics.LoadAvg5, "load_avg_15": metrics.LoadAvg15,
		"disk_total_bytes": metrics.DiskTotalBytes, "disk_used_bytes": metrics.DiskUsedBytes, "disk_available_bytes": metrics.DiskAvailableBytes,
	})
}

// Search handles GET /api/docker/hosts/{id}/containers/{containerId}/logs/search --
// searches the background-captured history (services/docker_host_log_capture.go),
// bounded to (at most) the retention window, exactly mirroring
// DockerLogsHandler.Search/K8sLogsHandler.Search -- see those for the
// shared query-param contract (q/from/to/limit/offset/severity). Replaces
// this handler's earlier live-only RecentLogs (removed once Docker Host
// containers gained their own background capture -- see migration
// 057/services/docker_host_log_capture.go): unlike that, this never
// depends on the agent being connected right now -- it only ever reads
// docker_host_container_log_lines, which the capture scheduler keeps
// filling in the background regardless of whether anyone has this host's
// page open.
func (h *DockerHostHandler) Search(w http.ResponseWriter, r *http.Request) {
	resourceID, ok := h.authorizeFeature(w, r, services.PermDockerLogs)
	if !ok {
		return
	}
	containerID := r.PathValue("containerId")
	if !isSafeDockerContainerID(containerID) {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}

	q := r.URL.Query()
	now := time.Now()
	retentionCutoff := now.Add(-h.logRetention)

	from := retentionCutoff
	if v := q.Get("from"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil && parsed.After(from) {
			from = parsed
		}
	}
	to := now
	if v := q.Get("to"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil && parsed.Before(to) {
			to = parsed
		}
	}
	if to.Before(from) {
		to = from
	}

	var searchTerm pgtype.Text
	if term := strings.TrimSpace(q.Get("q")); term != "" {
		searchTerm = pgutil.Text(term)
	}

	limit := int32(200)
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = int32(n)
		}
	}
	offset := int32(0)
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = int32(n)
		}
	}

	severityFilter, hasSeverityFilter := parseLogSeverityFilter(q.Get("severity"))

	fromTs, toTs := pgutil.Timestamptz(from), pgutil.Timestamptz(to)

	scanRows, err := h.store.SearchDockerHostContainerLogLines(r.Context(), generated.SearchDockerHostContainerLogLinesParams{
		DockerHostResourceID: resourceID, ContainerID: containerID, FromTs: fromTs, ToTs: toTs, Query: searchTerm, PageLimit: logSeverityScanCap, PageOffset: 0,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to search logs")
		return
	}
	var counts services.LogSeverityCounts
	classifiedScan := make([]logSearchLineDTO, 0, len(scanRows))
	for _, row := range scanRows {
		dto := toLogSearchLineDTO(row.ID.String(), row.LoggedAt.Time, row.Line)
		counts.Add(services.LogSeverity(dto.Severity))
		classifiedScan = append(classifiedScan, dto)
	}

	var items []logSearchLineDTO
	var total int64
	if hasSeverityFilter {
		var filtered []logSearchLineDTO
		for _, dto := range classifiedScan {
			if dto.Severity == string(severityFilter) {
				filtered = append(filtered, dto)
			}
		}
		total = int64(len(filtered))
		items = paginateClassifiedLines(filtered, limit, offset)
	} else {
		rows, err := h.store.SearchDockerHostContainerLogLines(r.Context(), generated.SearchDockerHostContainerLogLinesParams{
			DockerHostResourceID: resourceID, ContainerID: containerID, FromTs: fromTs, ToTs: toTs, Query: searchTerm, PageLimit: limit, PageOffset: offset,
		})
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to search logs")
			return
		}
		dbTotal, err := h.store.CountDockerHostContainerLogLines(r.Context(), generated.CountDockerHostContainerLogLinesParams{
			DockerHostResourceID: resourceID, ContainerID: containerID, FromTs: fromTs, ToTs: toTs, Query: searchTerm,
		})
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to search logs")
			return
		}
		total = dbTotal
		items = make([]logSearchLineDTO, 0, len(rows))
		for _, row := range rows {
			items = append(items, toLogSearchLineDTO(row.ID.String(), row.LoggedAt.Time, row.Line))
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"lines": items, "total": total, "retention_cutoff": retentionCutoff.Format(time.RFC3339), "counts": counts,
	})
}

// StreamLogs handles GET /api/docker/hosts/{id}/containers/{containerId}/logs/stream --
// live-tail only, sourced from DockerAgentService.StreamLogs (never SSH --
// a Docker Host has none).
func (h *DockerHostHandler) StreamLogs(w http.ResponseWriter, r *http.Request) {
	resourceID, ok := h.authorizeFeature(w, r, services.PermDockerLogs)
	if !ok {
		return
	}
	containerID := r.PathValue("containerId")
	if !isSafeDockerContainerID(containerID) {
		httpx.WriteError(w, http.StatusNotFound, "container not found")
		return
	}
	user, _ := services.UserFromContext(r.Context())

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == h.frontendOrigin
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	stream, cleanup, err := h.agents.StreamLogs(resourceID, containerID)
	if err != nil {
		msg := "Unable to reach the Docker agent."
		if errors.Is(err, services.ErrDockerAgentOffline) {
			msg = "No agent is currently connected for this host."
		}
		_ = conn.WriteJSON(dockerLogsOutboundFrame{Type: "error", Message: msg})
		return
	}
	defer cleanup()

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &user.ID, Action: services.AuditDockerLogsOpened, ResourceType: "DOCKER_HOST", ResourceID: &resourceID,
		Metadata: map[string]any{"container_id": containerID},
	})
	defer func() {
		_ = h.audit.Log(context.Background(), services.AuditEvent{
			UserID: &user.ID, Action: services.AuditDockerLogsClosed, ResourceType: "DOCKER_HOST", ResourceID: &resourceID,
			Metadata: map[string]any{"container_id": containerID},
		})
	}()

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-closed:
			return
		case msg, chOk := <-stream:
			if !chOk {
				return
			}
			switch msg.Type {
			case services.DockerAgentMsgLogLine:
				c := services.ClassifyLogLine(msg.Line)
				if conn.WriteJSON(dockerLogsOutboundFrame{Type: "log", Line: msg.Line, Severity: string(c.Severity), Category: c.Category, Suggestion: c.Suggestion}) != nil {
					return
				}
			case services.DockerAgentMsgDone:
				_ = conn.WriteJSON(dockerLogsOutboundFrame{Type: "closed"})
				return
			case services.DockerAgentMsgError:
				_ = conn.WriteJSON(dockerLogsOutboundFrame{Type: "error", Message: msg.Message})
				return
			}
		}
	}
}
