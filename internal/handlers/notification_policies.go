package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// NotificationPoliciesHandler implements Step 16's Admin-only
// notification policy management API (spec §27).
type NotificationPoliciesHandler struct {
	store         *repository.Store
	policies      *services.NotificationPolicyService
	notifications *services.NotificationService
	audit         *services.AuditService
}

// NewNotificationPoliciesHandler creates a NotificationPoliciesHandler.
func NewNotificationPoliciesHandler(store *repository.Store, policies *services.NotificationPolicyService, notifications *services.NotificationService, audit *services.AuditService) *NotificationPoliciesHandler {
	return &NotificationPoliciesHandler{store: store, policies: policies, notifications: notifications, audit: audit}
}

type notificationPolicyDTO struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	IsDefault          bool     `json:"is_default"`
	InfoChannels       []string `json:"info_channels"`
	WarningChannels    []string `json:"warning_channels"`
	CriticalChannels   []string `json:"critical_channels"`
	QuietHoursStart    string   `json:"quiet_hours_start,omitempty"`
	QuietHoursEnd      string   `json:"quiet_hours_end,omitempty"`
	QuietHoursTimezone string   `json:"quiet_hours_timezone,omitempty"`
	WebhookURL         string   `json:"webhook_url,omitempty"`
	SlackWebhookURL    string   `json:"slack_webhook_url,omitempty"`
	TeamsWebhookURL    string   `json:"teams_webhook_url,omitempty"`
	CreatedAt          string   `json:"created_at"`
}

func formatClockTime(t pgtype.Time) string {
	if !t.Valid {
		return ""
	}
	total := t.Microseconds / 1_000_000
	hh := total / 3600
	mm := (total % 3600) / 60
	return fmt.Sprintf("%02d:%02d", hh, mm)
}

func toNotificationPolicyDTO(p generated.NotificationPolicy) notificationPolicyDTO {
	return notificationPolicyDTO{
		ID: p.ID.String(), Name: p.Name, IsDefault: p.IsDefault, InfoChannels: p.InfoChannels,
		WarningChannels: p.WarningChannels, CriticalChannels: p.CriticalChannels,
		QuietHoursStart: formatClockTime(p.QuietHoursStart), QuietHoursEnd: formatClockTime(p.QuietHoursEnd),
		QuietHoursTimezone: pgutil.TextOrEmpty(p.QuietHoursTimezone), WebhookURL: pgutil.TextOrEmpty(p.WebhookUrl),
		SlackWebhookURL: pgutil.TextOrEmpty(p.SlackWebhookUrl), TeamsWebhookURL: pgutil.TextOrEmpty(p.TeamsWebhookUrl),
		CreatedAt: formatTimestamptzOrEmpty(p.CreatedAt),
	}
}

type notificationPolicyRequest struct {
	Name               string   `json:"name"`
	InfoChannels       []string `json:"info_channels"`
	WarningChannels    []string `json:"warning_channels"`
	CriticalChannels   []string `json:"critical_channels"`
	QuietHoursStart    *string  `json:"quiet_hours_start,omitempty"`
	QuietHoursEnd      *string  `json:"quiet_hours_end,omitempty"`
	QuietHoursTimezone string   `json:"quiet_hours_timezone,omitempty"`
	WebhookURL         string   `json:"webhook_url,omitempty"`
	SlackWebhookURL    string   `json:"slack_webhook_url,omitempty"`
	TeamsWebhookURL    string   `json:"teams_webhook_url,omitempty"`
}

// List handles GET /api/notification-policies (Admin-only).
func (h *NotificationPoliciesHandler) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdminActor(w, r); !ok {
		return
	}
	rows, err := h.store.ListNotificationPolicies(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load notification policies")
		return
	}
	items := make([]notificationPolicyDTO, 0, len(rows))
	for _, p := range rows {
		items = append(items, toNotificationPolicyDTO(p))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"notification_policies": items})
}

// Create handles POST /api/notification-policies (Admin-only).
func (h *NotificationPoliciesHandler) Create(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAdminActor(w, r)
	if !ok {
		return
	}
	var req notificationPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	policy, err := h.policies.Create(r.Context(), services.PolicyInput{
		Name: req.Name, InfoChannels: req.InfoChannels, WarningChannels: req.WarningChannels, CriticalChannels: req.CriticalChannels,
		QuietHoursStart: req.QuietHoursStart, QuietHoursEnd: req.QuietHoursEnd, QuietHoursTimezone: req.QuietHoursTimezone, WebhookURL: req.WebhookURL,
		SlackWebhookURL: req.SlackWebhookURL, TeamsWebhookURL: req.TeamsWebhookURL,
	}, actor.ID)
	if err != nil {
		writeNotificationPolicyError(w, err)
		return
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditNotificationPolicyChanged,
		ResourceType: "NOTIFICATION_POLICY", ResourceID: &policy.ID,
		Metadata: map[string]any{"action": "created", "name": policy.Name},
	})
	httpx.WriteJSON(w, http.StatusCreated, toNotificationPolicyDTO(policy))
}

// Update handles PUT /api/notification-policies/:id (Admin-only).
func (h *NotificationPoliciesHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAdminActor(w, r)
	if !ok {
		return
	}
	policyID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "notification policy not found")
		return
	}
	var req notificationPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	policy, err := h.policies.Update(r.Context(), policyID, services.PolicyInput{
		Name: req.Name, InfoChannels: req.InfoChannels, WarningChannels: req.WarningChannels, CriticalChannels: req.CriticalChannels,
		QuietHoursStart: req.QuietHoursStart, QuietHoursEnd: req.QuietHoursEnd, QuietHoursTimezone: req.QuietHoursTimezone, WebhookURL: req.WebhookURL,
		SlackWebhookURL: req.SlackWebhookURL, TeamsWebhookURL: req.TeamsWebhookURL,
	})
	if err != nil {
		writeNotificationPolicyError(w, err)
		return
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditNotificationPolicyChanged,
		ResourceType: "NOTIFICATION_POLICY", ResourceID: &policy.ID,
		Metadata: map[string]any{"action": "updated", "name": policy.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, toNotificationPolicyDTO(policy))
}

// Delete handles DELETE /api/notification-policies/:id (Admin-only).
func (h *NotificationPoliciesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAdminActor(w, r)
	if !ok {
		return
	}
	policyID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "notification policy not found")
		return
	}
	if err := h.policies.Delete(r.Context(), policyID); err != nil {
		writeNotificationPolicyError(w, err)
		return
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditNotificationPolicyChanged,
		ResourceType: "NOTIFICATION_POLICY", ResourceID: &policyID,
		Metadata: map[string]any{"action": "deleted"},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

type testNotificationRequest struct {
	Channel string `json:"channel"`
}

// SendTest handles POST /api/notification-policies/:id/test (Admin-only)
// -- sends exactly one synthetic notification over the given channel right
// now, bypassing dedup/cooldown/retry and never touching the notifications
// table (see NotificationService.SendTest). An operation endpoint: always
// 200 with a structured outcome (never a 500 for "the send itself
// failed" -- a misconfigured Slack URL is an expected, correctable
// outcome, not a server error), mirroring TestConnection-style endpoints
// elsewhere in this app. EMAIL delivers to the caller's own account
// email, so they can confirm receipt themselves.
func (h *NotificationPoliciesHandler) SendTest(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAdminActor(w, r)
	if !ok {
		return
	}
	policyID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "notification policy not found")
		return
	}
	var req testNotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	channel := services.NotificationChannel(req.Channel)

	policy, err := h.store.GetNotificationPolicyByID(r.Context(), policyID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "notification policy not found")
		return
	}

	sendErr := h.notifications.SendTest(r.Context(), channel, policy, actor.Email)

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditNotificationTestSent,
		ResourceType: "NOTIFICATION_POLICY", ResourceID: &policyID,
		Metadata: map[string]any{"channel": req.Channel, "succeeded": sendErr == nil},
	})

	if sendErr != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "failed", "message": sendErr.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "sent"})
}

func writeNotificationPolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, services.ErrNotificationPolicyNotFound):
		httpx.WriteError(w, http.StatusNotFound, "notification policy not found")
	case errors.Is(err, services.ErrNotificationPolicyInvalidChannel):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrValidation):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	default:
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
	}
}
