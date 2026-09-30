package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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

// AlertsHandler implements Step 16's alert-lifecycle API. GETs are any
// authenticated role, scoped to the caller's authorized resources
// exactly like RecommendationHandler (spec §22); acknowledge/suppress
// are Admin-only (spec §13/§64's "Admin can Acknowledge").
type AlertsHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	alerts         *services.AlertService
	audit          *services.AuditService
	streamInterval time.Duration
	frontendOrigin string
}

// NewAlertsHandler creates an AlertsHandler.
func NewAlertsHandler(
	store *repository.Store, authz *services.AuthorizationService, alerts *services.AlertService, audit *services.AuditService,
	streamInterval time.Duration, frontendOrigin string,
) *AlertsHandler {
	return &AlertsHandler{store: store, authz: authz, alerts: alerts, audit: audit, streamInterval: streamInterval, frontendOrigin: frontendOrigin}
}

type alertDTO struct {
	ID               string   `json:"id"`
	AlertRuleID      string   `json:"alert_rule_id"`
	ResourceID       string   `json:"resource_id"`
	ResourceName     string   `json:"resource_name"`
	ResourceType     string   `json:"resource_type"`
	ContainerID      *string  `json:"container_id,omitempty"`
	ContainerName    *string  `json:"container_name,omitempty"`
	WorkspaceID      *string  `json:"workspace_id,omitempty"`
	WorkspaceName    string   `json:"workspace_name,omitempty"`
	AlertType        string   `json:"alert_type"`
	Severity         string   `json:"severity"`
	Status           string   `json:"status"`
	Metric           string   `json:"metric"`
	CurrentValue     *float64 `json:"current_value,omitempty"`
	Threshold        float64  `json:"threshold"`
	Title            string   `json:"title"`
	Description      string   `json:"description,omitempty"`
	FirstSeenAt      string   `json:"first_seen_at"`
	LastSeenAt       string   `json:"last_seen_at"`
	AcknowledgedBy   *string  `json:"acknowledged_by,omitempty"`
	AcknowledgedAt   *string  `json:"acknowledged_at,omitempty"`
	ResolvedAt       *string  `json:"resolved_at,omitempty"`
	SuppressedAt     *string  `json:"suppressed_at,omitempty"`
	SuppressedReason string   `json:"suppressed_reason,omitempty"`
	CreatedAt        string   `json:"created_at"`
	// DurationSeconds is how long the alert has been open (first_seen_at
	// -> now, or -> resolved_at once terminal) -- spec §14/§17's "Duration".
	DurationSeconds int64 `json:"duration_seconds"`
}

func alertDuration(firstSeen, resolvedAt pgtype.Timestamptz) int64 {
	if !firstSeen.Valid {
		return 0
	}
	end := time.Now()
	if resolvedAt.Valid {
		end = resolvedAt.Time
	}
	return int64(end.Sub(firstSeen.Time).Seconds())
}

func toAlertListDTO(row generated.ListAlertsFilteredRow) alertDTO {
	dto := alertDTO{
		ID: row.ID.String(), AlertRuleID: row.AlertRuleID.String(), ResourceID: row.ResourceID.String(),
		ResourceName: row.ResourceName, ResourceType: row.ResourceType, WorkspaceName: pgutil.TextOrEmpty(row.WorkspaceName),
		AlertType: row.AlertType, Severity: row.Severity, Status: row.Status, Metric: row.Metric,
		CurrentValue: pgutil.Float8Ptr(row.CurrentValue), Threshold: row.Threshold, Title: row.Title,
		Description: pgutil.TextOrEmpty(row.Description), FirstSeenAt: formatTimestamptzOrEmpty(row.FirstSeenAt),
		LastSeenAt: formatTimestamptzOrEmpty(row.LastSeenAt), SuppressedReason: pgutil.TextOrEmpty(row.SuppressedReason),
		CreatedAt: formatTimestamptzOrEmpty(row.CreatedAt), DurationSeconds: alertDuration(row.FirstSeenAt, row.ResolvedAt),
		AcknowledgedAt: formatTimestamptz(row.AcknowledgedAt), ResolvedAt: formatTimestamptz(row.ResolvedAt), SuppressedAt: formatTimestamptz(row.SuppressedAt),
	}
	if row.ContainerID.Valid {
		id := pgutil.UUID(row.ContainerID).String()
		dto.ContainerID = &id
	}
	if row.ContainerName.Valid {
		dto.ContainerName = &row.ContainerName.String
	}
	if row.WorkspaceID.Valid {
		id := pgutil.UUID(row.WorkspaceID).String()
		dto.WorkspaceID = &id
	}
	if row.AcknowledgedBy.Valid {
		id := pgutil.UUID(row.AcknowledgedBy).String()
		dto.AcknowledgedBy = &id
	}
	return dto
}

func toAlertDetailDTO(row generated.GetAlertDetailRow, ackName string) alertDTO {
	dto := alertDTO{
		ID: row.ID.String(), AlertRuleID: row.AlertRuleID.String(), ResourceID: row.ResourceID.String(),
		ResourceName: row.ResourceName, ResourceType: row.ResourceType, WorkspaceName: pgutil.TextOrEmpty(row.WorkspaceName),
		AlertType: row.AlertType, Severity: row.Severity, Status: row.Status, Metric: row.Metric,
		CurrentValue: pgutil.Float8Ptr(row.CurrentValue), Threshold: row.Threshold, Title: row.Title,
		Description: pgutil.TextOrEmpty(row.Description), FirstSeenAt: formatTimestamptzOrEmpty(row.FirstSeenAt),
		LastSeenAt: formatTimestamptzOrEmpty(row.LastSeenAt), SuppressedReason: pgutil.TextOrEmpty(row.SuppressedReason),
		CreatedAt: formatTimestamptzOrEmpty(row.CreatedAt), DurationSeconds: alertDuration(row.FirstSeenAt, row.ResolvedAt),
		AcknowledgedAt: formatTimestamptz(row.AcknowledgedAt), ResolvedAt: formatTimestamptz(row.ResolvedAt), SuppressedAt: formatTimestamptz(row.SuppressedAt),
	}
	if row.ContainerID.Valid {
		id := pgutil.UUID(row.ContainerID).String()
		dto.ContainerID = &id
	}
	if row.ContainerName.Valid {
		dto.ContainerName = &row.ContainerName.String
	}
	if row.WorkspaceID.Valid {
		id := pgutil.UUID(row.WorkspaceID).String()
		dto.WorkspaceID = &id
	}
	if row.AcknowledgedBy.Valid {
		dto.AcknowledgedBy = &ackName
	}
	return dto
}

// authorizeAlert resolves :id, loads the alert, and confirms the caller
// (any authenticated role) can access its underlying resource -- 404 on
// any failure, matching every other resource-scoped GET's IDOR
// discipline in this project.
func (h *AlertsHandler) authorizeAlert(w http.ResponseWriter, r *http.Request) (generated.GetAlertDetailRow, services.AuthenticatedUser, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.GetAlertDetailRow{}, services.AuthenticatedUser{}, false
	}
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "alert not found")
		return generated.GetAlertDetailRow{}, services.AuthenticatedUser{}, false
	}
	detail, err := h.store.GetAlertDetail(r.Context(), alertID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "alert not found")
		return generated.GetAlertDetailRow{}, services.AuthenticatedUser{}, false
	}
	if !user.IsAdmin() {
		allowed, err := h.canAccessAlertResource(r.Context(), user, detail.ResourceType, detail.ResourceID)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return generated.GetAlertDetailRow{}, services.AuthenticatedUser{}, false
		}
		if !allowed {
			httpx.WriteError(w, http.StatusNotFound, "alert not found")
			return generated.GetAlertDetailRow{}, services.AuthenticatedUser{}, false
		}
	}
	return detail, user, true
}

func (h *AlertsHandler) canAccessAlertResource(ctx context.Context, user services.AuthenticatedUser, resourceType string, resourceID uuid.UUID) (bool, error) {
	if resourceType == "DATABASE" {
		return h.authz.CanAccessDatabase(ctx, user, resourceID, services.PermDatabaseView)
	}
	return h.authz.CanAccessVM(ctx, user, resourceID, services.PermVMView)
}

// List handles GET /api/alerts?status=&severity=&workspace_id=&resource_id=&search=&limit=&offset=.
func (h *AlertsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		ids, err := services.GetUserAlertAccessResourceIDs(r.Context(), h.authz, user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = ids
	}

	q := r.URL.Query()
	limit, offset := parsePagination(r, 50, 200)
	params := generated.ListAlertsFilteredParams{
		Limit: limit, Offset: offset, ResourceIds: resourceIDs,
		Status: optionalText(q.Get("status")), Severity: optionalText(q.Get("severity")), Search: optionalText(q.Get("search")),
	}
	if v := q.Get("workspace_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			params.WorkspaceID = pgutil.NullUUID(&id)
		}
	}
	if v := q.Get("resource_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			params.ResourceID = pgutil.NullUUID(&id)
		}
	}

	rows, err := h.store.ListAlertsFiltered(r.Context(), params)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load alerts")
		return
	}
	countParams := generated.CountAlertsFilteredParams{
		ResourceIds: resourceIDs, Status: params.Status, Severity: params.Severity,
		WorkspaceID: params.WorkspaceID, ResourceID: params.ResourceID, Search: params.Search,
	}
	total, _ := h.store.CountAlertsFiltered(r.Context(), countParams)

	items := make([]alertDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toAlertListDTO(row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"alerts": items, "total": total})
}

// Summary handles GET /api/alerts/summary -- the dashboard widget (spec
// §19): counts grouped by severity/status, scoped identically to List.
func (h *AlertsHandler) Summary(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		ids, err := services.GetUserAlertAccessResourceIDs(r.Context(), h.authz, user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = ids
	}
	rows, err := h.store.SummarizeAlertsByStatus(r.Context(), resourceIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to summarize alerts")
		return
	}
	summary := map[string]any{"critical": 0, "warning": 0, "info": 0, "acknowledged": 0, "active": 0}
	for _, row := range rows {
		switch row.Status {
		case "ACTIVE":
			summary["active"] = summary["active"].(int) + int(row.Total)
			switch row.Severity {
			case "CRITICAL":
				summary["critical"] = summary["critical"].(int) + int(row.Total)
			case "WARNING":
				summary["warning"] = summary["warning"].(int) + int(row.Total)
			case "INFO":
				summary["info"] = summary["info"].(int) + int(row.Total)
			}
		case "ACKNOWLEDGED":
			summary["acknowledged"] = summary["acknowledged"].(int) + int(row.Total)
		}
	}
	resolvedToday, _ := h.store.CountResolvedToday(r.Context(), resourceIDs)
	summary["resolved_today"] = resolvedToday
	httpx.WriteJSON(w, http.StatusOK, summary)
}

// Get handles GET /api/alerts/:id.
func (h *AlertsHandler) Get(w http.ResponseWriter, r *http.Request) {
	detail, _, ok := h.authorizeAlert(w, r)
	if !ok {
		return
	}
	ackName := ""
	if detail.AcknowledgedBy.Valid {
		if u, err := h.store.GetUserByID(r.Context(), pgutil.UUID(detail.AcknowledgedBy)); err == nil {
			ackName = u.Name
		}
	}
	httpx.WriteJSON(w, http.StatusOK, toAlertDetailDTO(detail, ackName))
}

// History handles GET /api/alerts/:id/history -- the timeline (spec §17).
func (h *AlertsHandler) History(w http.ResponseWriter, r *http.Request) {
	detail, _, ok := h.authorizeAlert(w, r)
	if !ok {
		return
	}
	events, err := h.store.ListAlertEvents(r.Context(), detail.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load alert history")
		return
	}
	items := make([]map[string]any, 0, len(events))
	for _, e := range events {
		items = append(items, map[string]any{
			"event_type": e.EventType, "status": e.Status, "value": pgutil.Float8Ptr(e.Value), "threshold": pgutil.Float8Ptr(e.Threshold),
			"message": pgutil.TextOrEmpty(e.Message), "created_at": e.CreatedAt.Time.Format(time.RFC3339),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": items})
}

// Acknowledge handles POST /api/alerts/:id/acknowledge (Admin-only).
func (h *AlertsHandler) Acknowledge(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		httpx.WriteError(w, http.StatusForbidden, "only an Admin can acknowledge an alert")
		return
	}
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "alert not found")
		return
	}
	updated, err := h.alerts.Acknowledge(r.Context(), alertID, user.ID)
	if err != nil {
		writeAlertError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": updated.ID.String(), "status": updated.Status})
}

type suppressAlertRequest struct {
	DurationMinutes int32  `json:"duration_minutes"`
	Reason          string `json:"reason"`
}

// Suppress handles POST /api/alerts/:id/suppress (Admin-only, spec §30).
func (h *AlertsHandler) Suppress(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		httpx.WriteError(w, http.StatusForbidden, "only an Admin can suppress an alert")
		return
	}
	alertID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "alert not found")
		return
	}
	var req suppressAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DurationMinutes <= 0 || req.Reason == "" {
		httpx.WriteError(w, http.StatusBadRequest, "duration_minutes and reason are required")
		return
	}
	updated, err := h.alerts.Suppress(r.Context(), alertID, time.Duration(req.DurationMinutes)*time.Minute, req.Reason, user.ID)
	if err != nil {
		writeAlertError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": updated.ID.String(), "status": updated.Status})
}

func writeAlertError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, services.ErrAlertNotFound):
		httpx.WriteError(w, http.StatusNotFound, "alert not found")
	case errors.Is(err, services.ErrAlertNotActive), errors.Is(err, services.ErrAlertNotOpen):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	default:
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
	}
}

func formatTimestamptzOrEmpty(t pgtype.Timestamptz) string {
	if !t.Valid {
		return ""
	}
	return t.Time.Format(time.RFC3339)
}

// Stream handles GET /api/alerts/stream (spec §35): a WebSocket that
// periodically pushes the caller's own currently-open (ACTIVE/
// ACKNOWLEDGED) alerts -- authorization is resolved once at connect time
// from the same resource-access computation List uses, never trusting a
// client-supplied filter, and every subsequent push re-applies that same
// resource_ids scope server-side (spec §70: "verify user + resource +
// workspace/direct access" before sending). Mirrors the
// gorilla/websocket + ticker-polls-the-store pattern used everywhere
// else in this project (Docker stats, operation logs) rather than a new
// pub-sub broker -- "Do not send alerts to every connected browser" is
// satisfied by scoping the query itself, not by a fan-out list.
func (h *AlertsHandler) Stream(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		ids, err := services.GetUserAlertAccessResourceIDs(r.Context(), h.authz, user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = ids
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

	ctx := r.Context()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	interval := h.streamInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	push := func() bool {
		activeStatus := pgutil.Text("ACTIVE")
		rows, err := h.store.ListAlertsFiltered(ctx, generated.ListAlertsFilteredParams{Limit: 50, ResourceIds: resourceIDs, Status: activeStatus})
		if err != nil {
			return true
		}
		items := make([]alertDTO, 0, len(rows))
		for _, row := range rows {
			items = append(items, toAlertListDTO(row))
		}
		return conn.WriteJSON(map[string]any{"type": "alerts", "alerts": items}) == nil
	}

	if !push() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			if !push() {
				return
			}
		}
	}
}
