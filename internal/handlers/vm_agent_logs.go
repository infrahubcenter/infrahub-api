// Package handlers: vm_agent_logs.go serves the VM Agent's OS-level logs
// (journald, with a plain-text fallback -- see vm-agent/logs.go) -- both a
// bounded recent-window fetch and a live tail, sourced entirely from
// VMAgentService (never SSH). Mirrors DockerHostHandler.RecentLogs/
// StreamLogs exactly, adapted for a whole VM rather than one container
// (no container_id) and gated on vm.view (there is no separate "VM logs"
// permission the way Docker/K8s Monitoring's workspace-scoped grants
// exist -- this is a plain VM-scoped resource, same as packages/updates).
package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type VMAgentLogsHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	agent          *services.VMAgentService
	audit          *services.AuditService
	frontendOrigin string
}

func NewVMAgentLogsHandler(store *repository.Store, authz *services.AuthorizationService, agent *services.VMAgentService, audit *services.AuditService, frontendOrigin string) *VMAgentLogsHandler {
	return &VMAgentLogsHandler{store: store, authz: authz, agent: agent, audit: audit, frontendOrigin: frontendOrigin}
}

// authorizeVMView resolves :id and checks vm.view, returning the VM's
// resource ID. 404-not-403, same as every other VM-scoped endpoint.
func (h *VMAgentLogsHandler) authorizeVMView(w http.ResponseWriter, r *http.Request) (resourceID uuid.UUID, user services.AuthenticatedUser, ok bool) {
	u, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return uuid.Nil, u, false
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, u, false
	}
	allowed, err := h.authz.CanAccessVMAny(r.Context(), u, resourceID, services.PermVMView, services.PermVMMetrics)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return uuid.Nil, u, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, u, false
	}
	return resourceID, u, true
}

const (
	defaultVMAgentRecentLogsWindow = 1 * time.Hour
	maxVMAgentRecentLogsWindow     = 24 * time.Hour
	maxVMAgentRecentLogsLines      = 2000
)

type vmAgentLogLineDTO struct {
	LoggedAt   string `json:"logged_at"`
	Line       string `json:"line"`
	Severity   string `json:"severity"`
	Category   string `json:"category,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// RecentLogs handles GET /api/vms/{id}/vm-agent/logs/recent?since=.
// Live-only: nothing is persisted server-side, exactly like
// DockerHostHandler.RecentLogs -- a single bounded FetchLogsSince call,
// parsed and classified in-memory.
func (h *VMAgentLogsHandler) RecentLogs(w http.ResponseWriter, r *http.Request) {
	resourceID, _, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	since := time.Now().Add(-defaultVMAgentRecentLogsWindow)
	if v := r.URL.Query().Get("since"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			since = parsed
		}
	}
	if time.Since(since) > maxVMAgentRecentLogsWindow {
		since = time.Now().Add(-maxVMAgentRecentLogsWindow)
	}
	output, err := h.agent.FetchLogsSince(r.Context(), resourceID, since)
	if err != nil {
		if errors.Is(err, services.ErrVMAgentOffline) {
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"lines": []vmAgentLogLineDTO{}, "total": 0, "since": since.Format(time.RFC3339), "agent_connected": false})
			return
		}
		httpx.WriteError(w, http.StatusBadGateway, vmAgentLogsErrorMessage(err))
		return
	}
	parsed, _ := services.ParseTimestampedLogLines(output, since)
	if len(parsed) > maxVMAgentRecentLogsLines {
		parsed = parsed[len(parsed)-maxVMAgentRecentLogsLines:]
	}
	var counts services.LogSeverityCounts
	items := make([]vmAgentLogLineDTO, 0, len(parsed))
	for _, l := range parsed {
		c := services.ClassifyLogLine(l.Text)
		counts.Add(c.Severity)
		items = append(items, vmAgentLogLineDTO{
			LoggedAt: l.LoggedAt.Format(time.RFC3339Nano), Line: l.Text,
			Severity: string(c.Severity), Category: c.Category, Suggestion: c.Suggestion,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"lines": items, "total": len(items), "since": since.Format(time.RFC3339), "agent_connected": true, "counts": counts,
	})
}

// vmAgentLogsErrorMessage turns the agent's own reported error into
// something actionable rather than a generic "failed to fetch" that
// invites pointless retries. Safe to show verbatim -- it's the agent's
// own log message, never a connection string or credential. The "no
// journal and no plain-text log file found" case (vm-agent/logs.go) is
// structural, not transient: it means this host has neither a systemd
// journal nor /var/log/syslog|messages -- true of any non-Linux host
// (e.g. Windows), and also true when the agent runs in a container on
// Docker Desktop for Windows/Mac, since the bind-mounted "host" paths
// are Docker Desktop's own minimal internal Linux VM, not the real
// Windows/Mac machine -- there is no journal/syslog to find either way.
func vmAgentLogsErrorMessage(err error) string {
	if strings.Contains(err.Error(), "no journal and no plain-text log file found") {
		return "This VM's OS-level logs aren't available: the agent needs a systemd journal or a /var/log/syslog|messages file on the host, neither of which exists here. " +
			"This is expected on Windows/macOS hosts (including Docker Desktop) -- OS-level log collection currently only works on Linux hosts."
	}
	return "Failed to fetch logs from the VM agent: " + err.Error()
}

type vmAgentLogsOutboundFrame struct {
	Type       string `json:"type"` // "log" | "error" | "closed"
	Line       string `json:"line,omitempty"`
	Message    string `json:"message,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Category   string `json:"category,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// StreamLogs handles GET /api/vms/{id}/vm-agent/logs/stream -- live-tail
// only, sourced from VMAgentService.StreamLogs. Mirrors
// DockerHostHandler.StreamLogs exactly.
func (h *VMAgentLogsHandler) StreamLogs(w http.ResponseWriter, r *http.Request) {
	resourceID, user, ok := h.authorizeVMView(w, r)
	if !ok {
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

	stream, cleanup, err := h.agent.StreamLogs(resourceID)
	if err != nil {
		msg := "Unable to reach the VM agent."
		if errors.Is(err, services.ErrVMAgentOffline) {
			msg = "No agent is currently connected for this VM."
		}
		_ = conn.WriteJSON(vmAgentLogsOutboundFrame{Type: "error", Message: msg})
		return
	}
	defer cleanup()

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &user.ID, Action: services.AuditVMAgentLogsOpened, ResourceType: "VM", ResourceID: &resourceID,
	})
	defer func() {
		_ = h.audit.Log(context.Background(), services.AuditEvent{
			UserID: &user.ID, Action: services.AuditVMAgentLogsClosed, ResourceType: "VM", ResourceID: &resourceID,
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
			case services.VMAgentMsgLogLine:
				c := services.ClassifyLogLine(msg.Line)
				if conn.WriteJSON(vmAgentLogsOutboundFrame{Type: "log", Line: msg.Line, Severity: string(c.Severity), Category: c.Category, Suggestion: c.Suggestion}) != nil {
					return
				}
			case services.VMAgentMsgDone:
				_ = conn.WriteJSON(vmAgentLogsOutboundFrame{Type: "closed"})
				return
			case services.VMAgentMsgError:
				_ = conn.WriteJSON(vmAgentLogsOutboundFrame{Type: "error", Message: vmAgentLogsErrorMessage(errors.New(msg.Message))})
				return
			}
		}
	}
}
