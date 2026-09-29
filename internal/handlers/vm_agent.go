// Package handlers: vm_agent.go is the per-VM push-based VM Agent's own
// inbound connection point (GET /api/vm-agent/connect) plus the
// Admin-only ConnectAgentOnly/ManualInstall/Status/TestConnection actions
// that manage it -- deliberately has no SSH-based automated install (see
// services/vm_agent_install.go's doc comment for why): every install here
// is the admin running a docker command themselves, same as Docker
// Host/K8s Cluster. The agent itself ships as a published container image
// (docker.io/infrahubcenter/infrahub-vm-agent), pushed to the same registry as the
// Docker/K8s agents.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// vmAgentConnectionTestResponse mirrors dockerAgentConnectionTestResponse
// (docker_agent.go) -- same shape, no engine/version field since the VM
// Agent has none to report (see VMAgentPingResult's own doc comment).
type vmAgentConnectionTestResponse struct {
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`
}

type VMAgentHandler struct {
	store          *repository.Store
	vms            *services.VMService
	hub            *services.VMAgentHub
	tokens         *services.VMAgentTokenService
	agents         *services.VMAgentService
	installer      *services.VMAgentInstallService
	audit          *services.AuditService
	frontendOrigin string
}

func NewVMAgentHandler(
	store *repository.Store, vms *services.VMService, hub *services.VMAgentHub, tokens *services.VMAgentTokenService,
	agents *services.VMAgentService, installer *services.VMAgentInstallService, audit *services.AuditService, frontendOrigin string,
) *VMAgentHandler {
	return &VMAgentHandler{store: store, vms: vms, hub: hub, tokens: tokens, agents: agents, installer: installer, audit: audit, frontendOrigin: frontendOrigin}
}

// Connect handles GET /api/vm-agent/connect. Blocks, serving the
// connection, until the agent disconnects. Bearer-token authenticated,
// mounted outside requireAuth/requireAdmin in router.go -- there is no
// human at the other end of this endpoint, mirrors
// DockerAgentHandler.Connect exactly.
func (h *VMAgentHandler) Connect(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	resourceID, err := h.tokens.VMResourceIDForToken(r.Context(), token)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid agent token")
		return
	}

	upgrader := websocket.Upgrader{
		// The caller here is our own agent binary, authenticated by the
		// bearer token above -- never a browser.
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	conn := h.hub.Register(resourceID, ws)
	_ = h.tokens.MarkConnected(r.Context(), resourceID)
	defer func() {
		h.hub.Unregister(resourceID, conn)
		_ = ws.Close()
	}()

	h.hub.Serve(resourceID, conn)
}

type connectAgentOnlyVMRequest struct {
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
}

// connectAgentOnlyVMResponse embeds the same vmDetail shape every other
// VM endpoint returns, plus the freshly generated agent token and exact
// `docker run` command -- present ONLY in this one response (and
// ManualInstall's), mirroring configureDockerHostResponse's identical
// "shown once" discipline for Docker Host.
type connectAgentOnlyVMResponse struct {
	vmDetail
	AgentToken string `json:"agent_token"`
	RunCommand string `json:"run_command"`
	// BackendURL lets the frontend build the Windows/Mac native-agent
	// commands itself (see agent-install-command.ts) -- RunCommand above
	// is always the Linux docker-run form, so those two OS branches need
	// the raw URL rather than a pre-built command.
	BackendURL string `json:"backend_url"`
}

// ConnectAgentOnly handles POST /api/vms/agent-only -- Admin-only. "Connect
// VM" in the Configure tab: no SSH fields at all, just a name and a
// workspace, mirroring DockerHostHandler.Configure exactly. The created
// VM is a real vms row (see VMService.CreateAgentOnly's own doc comment
// for why) that will never have SSH configured -- the only way to ever
// reach it is the VM Agent's own docker-run command, returned here.
func (h *VMAgentHandler) ConnectAgentOnly(w http.ResponseWriter, r *http.Request) {
	var req connectAgentOnlyVMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}
	if h.installer.BackendURL() == "" {
		httpx.WriteError(w, http.StatusConflict, "the backend's agent connect URL is not configured (VM_AGENT_BACKEND_URL); contact your administrator")
		return
	}

	resourceID, err := h.vms.CreateAgentOnly(r.Context(), services.CreateAgentOnlyInput{WorkspaceID: workspaceID, Name: req.Name})
	if err != nil {
		writeServiceError(w, err)
		return
	}

	token, err := h.tokens.GenerateToken(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate agent token")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditVMCreated, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"workspace_id": workspaceID.String(), "name": req.Name, "mode": "agent_only"},
	})
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditVMAgentInstalled, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"status": "ok", "mode": "connect_agent_only"},
	})

	created, err := h.vms.Get(r.Context(), actor, resourceID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	backendURL := h.installer.BackendURL()
	httpx.WriteJSON(w, http.StatusCreated, connectAgentOnlyVMResponse{
		vmDetail:   toVMDetail(created.Detail, created.Permissions, created.Source),
		AgentToken: token, RunCommand: services.VMAgentRunCommand(backendURL, token),
		BackendURL: backendURL,
	})
}

type vmAgentManualInstallResponse struct {
	Token         string `json:"token"`
	BackendURL    string `json:"backend_url"`
	Image         string `json:"image"`
	ContainerName string `json:"container_name"`
	RunCommand    string `json:"run_command"`
}

// ManualInstall handles POST /api/vms/{id}/vm-agent/manual -- Admin-only.
// Mirrors DockerAgentHandler.ManualInstall exactly.
func (h *VMAgentHandler) ManualInstall(w http.ResponseWriter, r *http.Request) {
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
		httpx.WriteError(w, http.StatusConflict, "the backend's agent connect URL is not configured (VM_AGENT_BACKEND_URL); contact your administrator")
		return
	}

	token, err := h.tokens.GenerateToken(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate agent token")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditVMAgentInstalled, ResourceType: "VM", ResourceID: &id,
		Metadata: map[string]any{"status": "ok", "mode": "manual_token_issued"},
	})

	backendURL := h.installer.BackendURL()
	spec := services.VMAgentManualInstallInfo()
	httpx.WriteJSON(w, http.StatusOK, vmAgentManualInstallResponse{
		Token: token, BackendURL: backendURL, Image: spec.Image, ContainerName: spec.ContainerName,
		RunCommand: services.VMAgentRunCommand(backendURL, token),
	})
}

type vmAgentStatusResponse struct {
	Installed       bool    `json:"installed"`
	Connected       bool    `json:"connected"`
	Version         string  `json:"version,omitempty"`
	LastHeartbeatAt *string `json:"last_heartbeat_at,omitempty"`
	TokenConfigured bool    `json:"token_configured"`
	// AgentOS is the OS family last reported by this VM's own agent (see
	// migrations/060_vm_agent_host_identity.sql) -- lets the Configure
	// tab's "Regenerate Token" default its OS picker to whatever is
	// actually already running here, instead of always Linux.
	AgentOS *string `json:"agent_os,omitempty"`
}

// Status handles GET /api/vms/{id}/vm-agent/status -- Admin-only.
// "Connected" always reflects the live hub state, never cached.
func (h *VMAgentHandler) Status(w http.ResponseWriter, r *http.Request) {
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
	httpx.WriteJSON(w, http.StatusOK, vmAgentStatusResponse{
		Installed: vm.VmAgentInstalled, Connected: h.agents.IsAgentConnected(id),
		Version: pgutil.TextOrEmpty(vm.VmAgentVersion), LastHeartbeatAt: formatTimestamptz(vm.VmAgentLastHeartbeatAt),
		TokenConfigured: tokenConfigured, AgentOS: pgutil.StringPtr(vm.VmAgentOs),
	})
}

// TestConnection handles POST /api/vms/{id}/vm-agent/connection-test --
// a real, synchronous round-trip ping (see VMAgentService.TestConnection),
// not just a look at the last heartbeat timestamp. Always-200 operation
// endpoint, same convention as DockerHostHandler.TestConnection.
func (h *VMAgentHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}
	if _, err := h.store.GetVMByResourceID(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "vm not found")
		return
	}

	latency, connErr := h.agents.TestConnection(r.Context(), id)
	if connErr != nil {
		code, msg := "VM_AGENT_CONNECTION_FAILED", "Unable to reach the VM Agent."
		if errors.Is(connErr, services.ErrVMAgentOffline) {
			code, msg = "VM_AGENT_OFFLINE", "No agent is currently connected for this VM. Check that it's installed and running."
		}
		httpx.WriteJSON(w, http.StatusOK, vmAgentConnectionTestResponse{Status: "failed", ErrorCode: code, Message: msg})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, vmAgentConnectionTestResponse{Status: "connected", LatencyMS: latency.Milliseconds()})
}
