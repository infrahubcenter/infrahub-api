// Package handlers: docker_agent.go is the per-VM Docker agent's own
// inbound connection point (GET /api/docker-agent/connect) plus the
// Admin-only Install/Status actions that manage it -- mirrors
// k8s_agent.go's Connect handler exactly for the transport half, and
// k8s.go's RegenerateAgentToken/TestConnection conventions for the
// operation-endpoint half. The agent itself ships as a published
// container image (docker.io/infrahubcenter/infrahub-docker-agent), pulled and run
// on the VM by Install/InstallStreaming (over this app's own SSH access)
// or by hand via ManualInstall's `docker run` command -- calling Install
// again on an already-installed VM replaces the container outright and
// re-authenticates it from scratch, which doubles as repair/token-rotation.
package handlers

import (
	"errors"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type DockerAgentHandler struct {
	store          *repository.Store
	hub            *services.DockerAgentHub
	tokens         *services.DockerAgentTokenService
	hostTokens     *services.DockerHostAgentTokenService
	agents         *services.DockerAgentService
	installer      *services.DockerAgentInstallService
	audit          *services.AuditService
	frontendOrigin string
}

func NewDockerAgentHandler(
	store *repository.Store, hub *services.DockerAgentHub, tokens *services.DockerAgentTokenService,
	hostTokens *services.DockerHostAgentTokenService, agents *services.DockerAgentService,
	installer *services.DockerAgentInstallService, audit *services.AuditService, frontendOrigin string,
) *DockerAgentHandler {
	return &DockerAgentHandler{
		store: store, hub: hub, tokens: tokens, hostTokens: hostTokens, agents: agents,
		installer: installer, audit: audit, frontendOrigin: frontendOrigin,
	}
}

// Connect handles GET /api/docker-agent/connect. Blocks, serving the
// connection, until the agent disconnects. There is no human at the
// other end of this endpoint, so it is authenticated by a bearer token,
// never the session-cookie model every other route in this app uses, and
// is deliberately mounted outside requireAuth/requireAdmin in router.go.
// The exact same endpoint serves two kinds of agent: one installed on a
// VM (services.DockerAgentTokenService, keyed by the VM's own
// resource_id) and one for a standalone Docker Host (services.
// DockerHostAgentTokenService, keyed by the host's own resource_id via
// docker_hosts) -- both resolve to a plain resources.id and register with
// the same hub identically, so nothing downstream needs to know or care
// which kind of agent is on the other end of the connection.
func (h *DockerAgentHandler) Connect(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	resourceID, err := h.tokens.VMResourceIDForToken(r.Context(), token)
	markConnected := h.tokens.MarkConnected
	if err != nil {
		resourceID, err = h.hostTokens.ResourceIDForToken(r.Context(), token)
		markConnected = h.hostTokens.MarkConnected
	}
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid agent token")
		return
	}

	upgrader := websocket.Upgrader{
		// The caller here is our own agent binary, authenticated by the
		// bearer token above -- never a browser, so there is no
		// cookie/CSRF-style same-origin concern the way there is for every
		// other WebSocket endpoint in this app.
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	conn := h.hub.Register(resourceID, ws)
	_ = markConnected(r.Context(), resourceID)
	defer func() {
		h.hub.Unregister(resourceID, conn)
		_ = ws.Close()
	}()

	h.hub.Serve(conn)
}

// Install handles POST /api/vms/{id}/docker-agent/install -- Admin-only.
// An operation endpoint: always 200 with a structured outcome
// (status: "ok" | "failed"), matching SSHHandler.TestConnection's
// convention -- a real-world install failure (unreachable VM, no sudo,
// unsupported architecture) is an expected, common outcome, not a server
// error.
func (h *DockerAgentHandler) Install(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}
	if _, err := h.store.GetVMByResourceID(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	result, err := h.installer.Install(r.Context(), id)
	if err != nil {
		message := dockerAgentInstallErrorMessage(err)
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &actor.ID, Action: services.AuditDockerAgentInstalled, ResourceType: "VM", ResourceID: &id,
			Metadata: map[string]any{"status": "failed", "error": message},
		})
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "failed", "message": message})
		return
	}

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDockerAgentInstalled, ResourceType: "VM", ResourceID: &id,
		Metadata: map[string]any{"status": "ok", "connected": result.Connected},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "connected": result.Connected, "engine_version": result.EngineVersion,
	})
}

type dockerAgentManualInstallResponse struct {
	Token         string `json:"token"`
	BackendURL    string `json:"backend_url"`
	Image         string `json:"image"`
	ContainerName string `json:"container_name"`
	RunCommand    string `json:"run_command"`
}

// ManualInstall handles POST /api/vms/{id}/docker-agent/manual -- Admin-
// only. Issues a fresh agent token (the same side effect Install has: any
// previously running agent stops authenticating the moment this runs) and
// returns the exact `docker run` command an admin can paste directly into
// the VM's own console -- entirely independent of this app's SSH access to
// that VM, for exactly the case where automated SSH install can't be made
// to work or isn't wanted. The agent ships as a published image
// (docker.io/infrahubcenter/infrahub-docker-agent), so there is nothing to download
// or build by hand -- the VM's own `docker run` pulls it directly.
func (h *DockerAgentHandler) ManualInstall(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}
	if _, err := h.store.GetVMByResourceID(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}
	if h.installer.BackendURL() == "" {
		httpx.WriteError(w, http.StatusConflict, "the backend's agent connect URL is not configured (DOCKER_AGENT_BACKEND_URL); contact your administrator")
		return
	}

	token, err := h.tokens.GenerateToken(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate agent token")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditDockerAgentInstalled, ResourceType: "VM", ResourceID: &id,
		Metadata: map[string]any{"status": "ok", "mode": "manual_token_issued"},
	})

	backendURL := h.installer.BackendURL()
	spec := services.DockerAgentManualInstallInfo()
	httpx.WriteJSON(w, http.StatusOK, dockerAgentManualInstallResponse{
		Token: token, BackendURL: backendURL, Image: spec.Image, ContainerName: spec.ContainerName,
		RunCommand: services.DockerAgentRunCommand(backendURL, token),
	})
}

func dockerAgentInstallErrorMessage(err error) string {
	switch {
	case errors.Is(err, services.ErrDockerAgentBackendURLUnconfigured):
		return "The backend's agent connect URL is not configured. Contact your administrator."
	case errors.Is(err, services.ErrDockerAgentPrivilegeUnsupported):
		return "The VM's SSH user cannot run privileged commands (needs root or passwordless sudo)."
	case errors.Is(err, services.ErrDockerAgentDockerUnavailable):
		return "Docker isn't installed or reachable on this VM -- install/start Docker there first, then try again."
	default:
		return "Failed to install the Docker agent. Check SSH connectivity and try again."
	}
}

type dockerAgentStatusResponse struct {
	Installed       bool    `json:"installed"`
	Connected       bool    `json:"connected"`
	Version         string  `json:"version,omitempty"`
	LastHeartbeatAt *string `json:"last_heartbeat_at,omitempty"`
	TokenConfigured bool    `json:"token_configured"`
}

// Status handles GET /api/vms/{id}/docker-agent/status -- Admin-only.
// "Connected" always reflects the live hub state, never a cached/stale
// value -- an agent that stopped sending heartbeats shows as
// disconnected immediately, not "last known good".
func (h *DockerAgentHandler) Status(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}
	vm, err := h.store.GetVMByResourceID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}
	tokenConfigured, _ := h.tokens.HasToken(r.Context(), id)
	httpx.WriteJSON(w, http.StatusOK, dockerAgentStatusResponse{
		Installed: vm.DockerAgentInstalled, Connected: h.agents.IsAgentConnected(id),
		Version: pgutil.TextOrEmpty(vm.DockerAgentVersion), LastHeartbeatAt: formatTimestamptz(vm.DockerAgentLastHeartbeatAt),
		TokenConfigured: tokenConfigured,
	})
}

type dockerAgentConnectionTestResponse struct {
	Status        string `json:"status"`
	EngineVersion string `json:"engine_version,omitempty"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	Message       string `json:"message,omitempty"`
}

// TestConnection handles POST /api/vms/{id}/docker-agent/connection-test
// -- Admin-only. An operation endpoint: always 200 with a structured
// outcome, matching K8sHandler.TestConnection's convention exactly.
func (h *DockerAgentHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}
	if _, err := h.store.GetVMByResourceID(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}

	result, connErr := h.agents.TestConnection(r.Context(), id)
	if connErr != nil {
		code, msg := "DOCKER_AGENT_CONNECTION_FAILED", "Unable to reach the Docker agent."
		if errors.Is(connErr, services.ErrDockerAgentOffline) {
			code, msg = "DOCKER_AGENT_OFFLINE", "No agent is currently connected for this VM. Check that it's installed and running."
		}
		httpx.WriteJSON(w, http.StatusOK, dockerAgentConnectionTestResponse{Status: "failed", ErrorCode: code, Message: msg})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, dockerAgentConnectionTestResponse{
		Status: "connected", EngineVersion: result.EngineVersion, LatencyMS: result.LatencyMS,
	})
}

type dockerAgentInstallStreamFrame struct {
	Type          string `json:"type"` // "line" | "done"
	Line          string `json:"line,omitempty"`
	Status        string `json:"status,omitempty"` // "done" frame only: "ok" | "failed"
	Message       string `json:"message,omitempty"`
	Connected     bool   `json:"connected,omitempty"`
	EngineVersion string `json:"engine_version,omitempty"`
}

// InstallStream handles GET /api/vms/{id}/docker-agent/install-stream --
// Admin-only (requireAdmin in router.go). The "Manual / Live" install
// mode: the identical install Install already performs, but every real
// command's output streams live over this WebSocket as it runs instead
// of only reporting a final buffered outcome.
func (h *DockerAgentHandler) InstallStream(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}
	if _, err := h.store.GetVMByResourceID(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || httpx.OriginAllowed(h.frontendOrigin, origin)
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	var writeMu sync.Mutex
	writeLine := func(line string) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteJSON(dockerAgentInstallStreamFrame{Type: "line", Line: line})
	}

	actor, _ := services.UserFromContext(r.Context())
	result, installErr := h.installer.InstallStreaming(r.Context(), id, writeLine)

	writeMu.Lock()
	if installErr != nil {
		message := dockerAgentInstallErrorMessage(installErr)
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &actor.ID, Action: services.AuditDockerAgentInstalled, ResourceType: "VM", ResourceID: &id,
			Metadata: map[string]any{"status": "failed", "error": message, "mode": "manual"},
		})
		_ = conn.WriteJSON(dockerAgentInstallStreamFrame{Type: "done", Status: "failed", Message: message})
	} else {
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &actor.ID, Action: services.AuditDockerAgentInstalled, ResourceType: "VM", ResourceID: &id,
			Metadata: map[string]any{"status": "ok", "connected": result.Connected, "mode": "manual"},
		})
		_ = conn.WriteJSON(dockerAgentInstallStreamFrame{
			Type: "done", Status: "ok", Connected: result.Connected, EngineVersion: result.EngineVersion,
		})
	}
	writeMu.Unlock()

	// Push-only, identical convention to the Docker log stream -- reading
	// here only detects the browser disconnecting.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}
