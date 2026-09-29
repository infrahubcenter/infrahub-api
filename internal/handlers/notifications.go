package handlers

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// NotificationsHandler implements Step 16's per-user notification center
// (spec §20/§34). Every endpoint is scoped to the caller's own
// notifications by construction (user_id = the authenticated caller,
// never taken from the request) -- there is no way to read or mark read
// another user's notification (spec §57).
type NotificationsHandler struct {
	store *repository.Store
}

// NewNotificationsHandler creates a NotificationsHandler.
func NewNotificationsHandler(store *repository.Store) *NotificationsHandler {
	return &NotificationsHandler{store: store}
}

type notificationDTO struct {
	ID        string  `json:"id"`
	AlertID   *string `json:"alert_id,omitempty"`
	Category  string  `json:"category"`
	Channel   string  `json:"channel"`
	Severity  string  `json:"severity,omitempty"`
	Title     string  `json:"title"`
	Body      string  `json:"body,omitempty"`
	Status    string  `json:"status"`
	ReadAt    *string `json:"read_at,omitempty"`
	CreatedAt string  `json:"created_at"`
}

func toNotificationDTO(n generated.Notification) notificationDTO {
	dto := notificationDTO{
		ID: n.ID.String(), Category: n.Category, Channel: n.Channel, Severity: pgutil.TextOrEmpty(n.Severity),
		Title: n.Title, Body: pgutil.TextOrEmpty(n.Body), Status: n.Status, CreatedAt: n.CreatedAt.Time.Format(time.RFC3339),
		ReadAt: formatTimestamptz(n.ReadAt),
	}
	if n.AlertID.Valid {
		id := pgutil.UUID(n.AlertID).String()
		dto.AlertID = &id
	}
	return dto
}

// List handles GET /api/notifications?unread_only=&limit=&offset=.
func (h *NotificationsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	limit, offset := parsePagination(r, 20, 100)
	unreadOnly := r.URL.Query().Get("unread_only") == "true"

	rows, err := h.store.ListNotificationsForUser(r.Context(), generated.ListNotificationsForUserParams{
		UserID: pgutil.NullUUID(&user.ID), Limit: limit, Offset: offset, UnreadOnly: pgutil.Bool(unreadOnly),
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load notifications")
		return
	}
	unread, _ := h.store.CountUnreadNotifications(r.Context(), pgutil.NullUUID(&user.ID))
	items := make([]notificationDTO, 0, len(rows))
	for _, n := range rows {
		items = append(items, toNotificationDTO(n))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"notifications": items, "unread_count": unread})
}

// MarkRead handles POST /api/notifications/:id/read.
func (h *NotificationsHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	notifID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "notification not found")
		return
	}
	updated, err := h.store.MarkNotificationRead(r.Context(), generated.MarkNotificationReadParams{ID: notifID, UserID: pgutil.NullUUID(&user.ID)})
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "notification not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toNotificationDTO(updated))
}

// MarkAllRead handles POST /api/notifications/read-all.
func (h *NotificationsHandler) MarkAllRead(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if err := h.store.MarkAllNotificationsRead(r.Context(), pgutil.NullUUID(&user.ID)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to mark notifications read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"marked_read": true})
}
