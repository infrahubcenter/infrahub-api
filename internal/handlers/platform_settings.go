// Package handlers: platform_settings.go implements Step 21's Platform/
// Monitoring/Security Settings tabs (Admin-only) plus the Owner-exclusive
// Sign-in Methods edit surface. Monitoring/Security fields remain a
// read-only echo of internal/config.Config -- those really are baked into
// a scheduler/ticker/middleware at process startup, so there is
// deliberately no PUT for them (spec §22/§23's "no fake setting that
// doesn't affect application behavior"). Sign-in Methods is the one
// exception: GitHub/Google/SMTP are now backed by
// services.PlatformSettingsService (migration 047), read fresh from
// Postgres on every request, editable ONLY by an Owner (requireOwnerActor)
// -- an Admin still sees the existing read-only configured-or-not booleans
// on GET /api/settings/platform, now computed live instead of frozen at
// startup, but never the edit surface below.
package handlers

import (
	"encoding/json"
	"net/http"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

// PlatformConfigView is the safe, curated subset of config.Config exposed
// to GET /api/settings/platform -- built once in cmd/server/main.go from
// the same *config.Config the rest of the application already uses, never
// re-read from the environment here. Sign-in-method status is NOT part of
// this frozen struct (see signinMethodsStatus in Get) since that's now
// live/DB-backed, not a startup snapshot.
type PlatformConfigView struct {
	PlatformName string `json:"platform_name"`

	// Monitoring tab
	VMMonitorInterval            string `json:"vm_monitor_interval"`
	VMMonitorRetentionDays       int32  `json:"vm_monitor_retention_days"`
	DockerMetricsInterval        string `json:"docker_metrics_interval"`
	DatabaseMetricsInterval      string `json:"database_metrics_interval"`
	DatabaseMetricsRetentionDays int32  `json:"database_metrics_retention_days"`
	ObjectStorageMetricsInterval string `json:"object_storage_metrics_interval"`
	AlertEvalInterval            string `json:"alert_eval_interval"`

	// Security tab
	AccessTokenTTLMinutes  int32  `json:"access_token_ttl_minutes"`
	RefreshTokenTTLDays    int32  `json:"refresh_token_ttl_days"`
	CookieSecure           bool   `json:"cookie_secure"`
	LoginRateLimitAttempts int32  `json:"login_rate_limit_attempts"`
	LoginRateLimitWindow   string `json:"login_rate_limit_window"`
	MaxRequestBodyBytes    int64  `json:"max_request_body_bytes"`
}

// platformSettingsResponse is GET /api/settings/platform's full body --
// the frozen view above plus live-computed sign-in-method status.
type platformSettingsResponse struct {
	PlatformConfigView
	GitHubOAuthConfigured bool `json:"github_oauth_configured"`
	GoogleOAuthConfigured bool `json:"google_oauth_configured"`
	SMTPConfigured        bool `json:"smtp_configured"`
	// IsOwner tells the frontend whether to render the Sign-in Methods
	// edit surface at all -- the backend independently enforces this on
	// every write/test route regardless (requireOwnerActor), this is
	// purely a UI hint so a non-Owner Admin doesn't see a form that would
	// just 403.
	IsOwner bool `json:"is_owner"`
}

type PlatformSettingsHandler struct {
	view     PlatformConfigView
	settings *services.PlatformSettingsService
	audit    *services.AuditService
}

func NewPlatformSettingsHandler(view PlatformConfigView, settings *services.PlatformSettingsService, audit *services.AuditService) *PlatformSettingsHandler {
	return &PlatformSettingsHandler{view: view, settings: settings, audit: audit}
}

// Get handles GET /api/settings/platform (Admin-only, Owner included since
// Owner satisfies IsAdmin()).
func (h *PlatformSettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireAdminActor(w, r)
	if !ok {
		return
	}
	live, err := h.settings.Get(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load settings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, platformSettingsResponse{
		PlatformConfigView: h.view, GitHubOAuthConfigured: live.GitHubConfigured,
		GoogleOAuthConfigured: live.GoogleConfigured, SMTPConfigured: live.SMTPConfigured,
		IsOwner: actor.IsOwner(),
	})
}

// requireOwnerActor mirrors requireAdminActor exactly, but for the
// handful of genuinely Owner-exclusive routes below (editing sign-in
// methods) -- an authenticated Admin who is not an Owner gets 403, same
// shape/wording convention as every other actor-role gate in this app.
func requireOwnerActor(w http.ResponseWriter, r *http.Request) (services.AuthenticatedUser, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return services.AuthenticatedUser{}, false
	}
	if !user.IsOwner() {
		httpx.WriteError(w, http.StatusForbidden, "Owner only")
		return services.AuthenticatedUser{}, false
	}
	return user, true
}

// signInMethodsResponse is GET /api/settings/signin-methods' body (Owner-
// only) -- the full editable view: Client IDs/SMTP non-secret fields in
// plaintext (safe to show back, an Owner just set them), secrets NEVER
// echoed back, only a "configured" boolean per secret, matching this
// app's established masked-credential-display convention everywhere else.
type signInMethodsResponse struct {
	GitHubClientID       string `json:"github_client_id"`
	GitHubSecretSet      bool   `json:"github_secret_set"`
	GoogleClientID       string `json:"google_client_id"`
	GoogleSecretSet      bool   `json:"google_secret_set"`
	SMTPHost             string `json:"smtp_host"`
	SMTPPort             int32  `json:"smtp_port"`
	SMTPUsername         string `json:"smtp_username"`
	SMTPPasswordSet      bool   `json:"smtp_password_set"`
	SMTPFromEmail        string `json:"smtp_from_email"`
	SMTPUseTLS           bool   `json:"smtp_use_tls"`
}

// GetSignInMethods handles GET /api/settings/signin-methods (Owner-only).
func (h *PlatformSettingsHandler) GetSignInMethods(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireOwnerActor(w, r); !ok {
		return
	}
	live, err := h.settings.Get(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load settings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, signInMethodsResponse{
		GitHubClientID: live.GitHubClientID, GitHubSecretSet: live.GitHubClientSecret != "",
		GoogleClientID: live.GoogleClientID, GoogleSecretSet: live.GoogleClientSecret != "",
		SMTPHost: live.SMTPHost, SMTPPort: live.SMTPPort, SMTPUsername: live.SMTPUsername,
		SMTPPasswordSet: live.SMTPPassword != "", SMTPFromEmail: live.SMTPFromEmail, SMTPUseTLS: live.SMTPUseTLS,
	})
}

type updateOAuthRequest struct {
	ClientID     string  `json:"client_id"`
	ClientSecret *string `json:"client_secret,omitempty"`
}

// UpdateGitHub handles PUT /api/settings/github (Owner-only). ClientSecret
// omitted/empty means "leave the currently stored secret unchanged."
func (h *PlatformSettingsHandler) UpdateGitHub(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireOwnerActor(w, r)
	if !ok {
		return
	}
	var req updateOAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.settings.UpdateGitHub(r.Context(), actor.ID, req.ClientID, req.ClientSecret); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save GitHub settings")
		return
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditPlatformSigninMethodUpdated, Metadata: map[string]any{"method": "github"}})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// UpdateGoogle handles PUT /api/settings/google (Owner-only).
func (h *PlatformSettingsHandler) UpdateGoogle(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireOwnerActor(w, r)
	if !ok {
		return
	}
	var req updateOAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.settings.UpdateGoogle(r.Context(), actor.ID, req.ClientID, req.ClientSecret); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save Google settings")
		return
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditPlatformSigninMethodUpdated, Metadata: map[string]any{"method": "google"}})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"saved": true})
}

type updateSMTPRequest struct {
	Host      string  `json:"host"`
	Port      int32   `json:"port"`
	Username  string  `json:"username"`
	Password  *string `json:"password,omitempty"`
	FromEmail string  `json:"from_email"`
	UseTLS    bool    `json:"use_tls"`
}

// UpdateSMTP handles PUT /api/settings/smtp (Owner-only). Password
// omitted/empty means "leave the currently stored password unchanged."
func (h *PlatformSettingsHandler) UpdateSMTP(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireOwnerActor(w, r)
	if !ok {
		return
	}
	var req updateSMTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	err := h.settings.UpdateSMTP(r.Context(), actor.ID, services.SMTPUpdateInput{
		Host: req.Host, Port: req.Port, Username: req.Username, Password: req.Password,
		FromEmail: req.FromEmail, UseTLS: req.UseTLS,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save SMTP settings")
		return
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditPlatformSigninMethodUpdated, Metadata: map[string]any{"method": "smtp"}})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"saved": true})
}

type testConnectionResponse struct {
	ConnectionStatus string `json:"connection_status"`
}

type testSMTPRequest struct {
	Host      string  `json:"host"`
	Port      int32   `json:"port"`
	Username  string  `json:"username"`
	Password  *string `json:"password,omitempty"`
	FromEmail string  `json:"from_email"`
	UseTLS    bool    `json:"use_tls"`
}

// TestSMTP handles POST /api/settings/smtp/test (Owner-only). Deliberately
// accepts the candidate settings in the request body -- unlike the
// resource-scoped Test Connection convention elsewhere in this app, there
// is no saved "resource" to test yet, and testing before committing
// avoids saving broken credentials. Password omitted means "use the
// currently-saved password" (so testing after a save, without re-entering
// it, still works). Sends one real email to the caller's own address --
// always 200 with a connection_status, matching every other Test
// Connection endpoint's convention (never a non-2xx for a normal failed
// probe).
func (h *PlatformSettingsHandler) TestSMTP(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireOwnerActor(w, r)
	if !ok {
		return
	}
	var req testSMTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	password := ""
	if req.Password != nil {
		password = *req.Password
	} else if current, err := h.settings.Get(r.Context()); err == nil {
		password = current.SMTPPassword
	}
	status := services.TestSMTP(r.Context(), services.SMTPUpdateInput{
		Host: req.Host, Port: req.Port, Username: req.Username, FromEmail: req.FromEmail, UseTLS: req.UseTLS,
	}, password, actor.Email)
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditPlatformSigninMethodTested, Metadata: map[string]any{"method": "smtp", "connection_status": status}})
	httpx.WriteJSON(w, http.StatusOK, testConnectionResponse{ConnectionStatus: string(status)})
}

type testOAuthRequest struct {
	ClientID     string  `json:"client_id"`
	ClientSecret *string `json:"client_secret,omitempty"`
}

// TestOAuth handles POST /api/settings/oauth/{provider}/test (Owner-only,
// provider = github|google). See this file's own doc comment for exactly
// what this can and cannot verify. ClientSecret omitted means "use the
// currently-saved secret."
func (h *PlatformSettingsHandler) TestOAuth(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireOwnerActor(w, r)
	if !ok {
		return
	}
	provider := r.PathValue("provider")
	if provider != "github" && provider != "google" {
		httpx.WriteError(w, http.StatusNotFound, "unknown provider")
		return
	}
	var req testOAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	secret := ""
	if req.ClientSecret != nil {
		secret = *req.ClientSecret
	} else if current, err := h.settings.Get(r.Context()); err == nil {
		if provider == "github" {
			secret = current.GitHubClientSecret
		} else {
			secret = current.GoogleClientSecret
		}
	}
	var status services.ConnectionTestStatus
	if provider == "github" {
		status = services.TestGitHubOAuthCredentials(r.Context(), req.ClientID, secret)
	} else {
		status = services.TestGoogleOAuthCredentials(r.Context(), req.ClientID, secret)
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{UserID: &actor.ID, Action: services.AuditPlatformSigninMethodTested, Metadata: map[string]any{"method": provider, "connection_status": status}})
	httpx.WriteJSON(w, http.StatusOK, testConnectionResponse{ConnectionStatus: string(status)})
}
