// Package handlers: me_settings.go implements Step 21's Personal Settings
// (GET/PUT /api/me/settings) -- always self-service: the target user is
// always the caller (from context), never a request/path parameter, so
// there is no ID for a Member to substitute to reach another user's
// settings. Display name reuses AuthService.UpdateUserAccount (Step 3),
// the exact same last-active-admin/self-demotion-safe path
// PATCH /api/users/:id already uses, called with actor==target and
// Role/IsActive always nil -- structurally incapable of touching role or
// active status no matter what a caller sends, since those fields are
// never populated from this handler's request body.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

type MeSettingsHandler struct {
	auth  *services.AuthService
	prefs *services.UserPreferencesService
	audit *services.AuditService
}

func NewMeSettingsHandler(auth *services.AuthService, prefs *services.UserPreferencesService, audit *services.AuditService) *MeSettingsHandler {
	return &MeSettingsHandler{auth: auth, prefs: prefs, audit: audit}
}

type meSettingsDTO struct {
	Name                        string   `json:"name"`
	Email                       string   `json:"email"`
	Theme                       string   `json:"theme"`
	Timezone                    string   `json:"timezone"`
	DateFormat                  string   `json:"date_format"`
	MutedNotificationCategories []string `json:"muted_notification_categories"`
}

// Get handles GET /api/me/settings (any authenticated role).
func (h *MeSettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	prefs, err := h.prefs.Get(r.Context(), user.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load settings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, meSettingsDTO{
		Name: user.Name, Email: user.Email, Theme: prefs.Theme, Timezone: prefs.Timezone,
		DateFormat: prefs.DateFormat, MutedNotificationCategories: prefs.MutedNotificationCategories,
	})
}

type updateMeSettingsRequest struct {
	Name                        *string   `json:"name,omitempty"`
	Theme                       *string   `json:"theme,omitempty"`
	Timezone                    *string   `json:"timezone,omitempty"`
	DateFormat                  *string   `json:"date_format,omitempty"`
	MutedNotificationCategories *[]string `json:"muted_notification_categories,omitempty"`
}

// Update handles PUT /api/me/settings (any authenticated role). Every
// field is optional -- a request touching only theme, say, leaves name and
// every other preference untouched.
func (h *MeSettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req updateMeSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	changedFields := make([]string, 0, 5)
	name := user.Name

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			httpx.WriteError(w, http.StatusBadRequest, "name cannot be empty")
			return
		}
		if _, _, err := h.auth.UpdateUserAccount(r.Context(), user.ID, user.ID, services.UpdateUserAccountInput{Name: &trimmed}); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to update name")
			return
		}
		name = trimmed
		changedFields = append(changedFields, "name")
	}

	prefs, err := h.prefs.Update(r.Context(), user.ID, services.UpdateUserPreferencesInput{
		Theme: req.Theme, Timezone: req.Timezone, DateFormat: req.DateFormat, MutedNotificationCategories: req.MutedNotificationCategories,
	})
	if err != nil {
		if errors.Is(err, services.ErrValidation) {
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update settings")
		return
	}
	if req.Theme != nil {
		changedFields = append(changedFields, "theme")
	}
	if req.Timezone != nil {
		changedFields = append(changedFields, "timezone")
	}
	if req.DateFormat != nil {
		changedFields = append(changedFields, "date_format")
	}
	if req.MutedNotificationCategories != nil {
		changedFields = append(changedFields, "muted_notification_categories")
	}

	if len(changedFields) > 0 {
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &user.ID, Action: services.AuditUserSettingsUpdated, ResourceType: "USER", ResourceID: &user.ID,
			Metadata: map[string]any{"fields_changed": changedFields},
		})
	}

	httpx.WriteJSON(w, http.StatusOK, meSettingsDTO{
		Name: name, Email: user.Email, Theme: prefs.Theme, Timezone: prefs.Timezone,
		DateFormat: prefs.DateFormat, MutedNotificationCategories: prefs.MutedNotificationCategories,
	})
}

type changeMyPasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword handles PUT /api/me/password (any authenticated role) --
// self-service only, same as Get/Update above: the target is always the
// caller, never a request/path parameter.
func (h *MeSettingsHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req changeMyPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		httpx.WriteError(w, http.StatusBadRequest, "current_password and new_password are both required")
		return
	}

	if err := h.auth.ChangePassword(r.Context(), user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, services.ErrIncorrectCurrentPassword):
			httpx.WriteError(w, http.StatusBadRequest, "current password is incorrect")
		case errors.Is(err, services.ErrValidation):
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to change password")
		}
		return
	}

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &user.ID, Action: services.AuditUserPasswordChanged, ResourceType: "USER", ResourceID: &user.ID,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"changed": true})
}
