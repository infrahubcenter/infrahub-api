// Package handlers: audit_logs.go implements Step 21's /audit-logs page --
// read-only access to the existing append-only audit_logs table
// (internal/services/audit.go writes it, unchanged; this only adds a way
// to browse what's already there). Admin-only: audit.view exists in the
// permission catalog (cmd/seed) but has never been checked anywhere or
// grantable through the existing resource_permissions mechanism (it isn't
// resource-scoped), so there is no existing Member grant path to honor --
// matching spec §16's own recommended default exactly.
package handlers

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

type AuditLogsHandler struct {
	audit *services.AuditQueryService
}

func NewAuditLogsHandler(audit *services.AuditQueryService) *AuditLogsHandler {
	return &AuditLogsHandler{audit: audit}
}

type auditLogEntryDTO struct {
	ID           string         `json:"id"`
	ActorID      string         `json:"actor_id,omitempty"`
	ActorName    string         `json:"actor_name,omitempty"`
	ActorEmail   string         `json:"actor_email,omitempty"`
	Action       string         `json:"action"`
	Category     string         `json:"category"`
	ResourceType string         `json:"resource_type,omitempty"`
	ResourceID   string         `json:"resource_id,omitempty"`
	IPAddress    string         `json:"ip_address,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    string         `json:"created_at"`
}

func toAuditLogEntryDTO(e services.AuditLogEntry) auditLogEntryDTO {
	dto := auditLogEntryDTO{
		ID: e.ID.String(), ActorName: e.ActorName, ActorEmail: e.ActorEmail,
		Action: e.Action, Category: string(e.Category), ResourceType: e.ResourceType,
		IPAddress: e.IPAddress, UserAgent: e.UserAgent, Metadata: e.Metadata,
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
	}
	if e.UserID != nil {
		dto.ActorID = e.UserID.String()
	}
	if e.ResourceID != nil {
		dto.ResourceID = e.ResourceID.String()
	}
	return dto
}

// List handles GET /api/audit-logs (Admin-only). Every filter is optional;
// unset means "don't filter on this," never "match nothing."
func (h *AuditLogsHandler) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdminActor(w, r); !ok {
		return
	}
	q := r.URL.Query()
	filter := services.AuditLogFilter{
		Action:       q.Get("action"),
		Category:     services.AuditCategory(q.Get("category")),
		ResourceType: q.Get("resource_type"),
		Search:       q.Get("search"),
	}
	if v := q.Get("user_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filter.UserID = &id
		}
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.To = &t
		}
	}
	filter.Limit, filter.Offset = parsePagination(r, 50, 200)

	entries, total, err := h.audit.List(r.Context(), filter)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load audit logs")
		return
	}
	items := make([]auditLogEntryDTO, 0, len(entries))
	for _, e := range entries {
		items = append(items, toAuditLogEntryDTO(e))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"audit_logs": items, "total": total})
}

type auditOverviewDTO struct {
	Total            int64 `json:"total"`
	Today            int64 `json:"today"`
	SecurityEvents   int64 `json:"security_events"`
	UserChanges      int64 `json:"user_changes"`
	ResourceChanges  int64 `json:"resource_changes"`
	OperationsEvents int64 `json:"operations_events"`
}

// Summary handles GET /api/audit-logs/summary (Admin-only).
func (h *AuditLogsHandler) Summary(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdminActor(w, r); !ok {
		return
	}
	overview, err := h.audit.Overview(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load audit log summary")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, auditOverviewDTO{
		Total: overview.Total, Today: overview.Today, SecurityEvents: overview.SecurityEvents,
		UserChanges: overview.UserChanges, ResourceChanges: overview.ResourceChanges, OperationsEvents: overview.OperationsEvents,
	})
}
