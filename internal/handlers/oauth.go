// Package handlers: oauth.go implements GitHub/Google OAuth login --
// Start redirects the browser to the provider's consent screen, Callback
// completes the round trip and establishes a session exactly like
// password login does (same setAuthCookies helper), invite-only (see
// services.AuthService.LoginWithVerifiedEmail: never creates a new user).
// Both routes are public (mounted outside requireAuth in router.go,
// mirroring /api/auth/login) and rate-limited the same way login is,
// since Callback triggers real outbound HTTP per request.
//
// The Client ID/Secret pair is resolved live, per request, from
// services.PlatformSettingsService (Owner-editable, migration 047) rather
// than fixed at startup -- provider() below builds a fresh, cheap
// GitHubOAuthProvider/GoogleOAuthProvider on every call, so a credential
// an Owner just saved through Settings takes effect on the very next
// login attempt, no restart needed.
package handlers

import (
	"context"
	"errors"
	"net/http"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

type OAuthHandler struct {
	settings        *services.PlatformSettingsService
	redirectBaseURL string
	auth            *services.AuthService
	audit           *services.AuditService
	cookieSecure    bool
	appBaseURL      string
}

// NewOAuthHandler creates an OAuthHandler. redirectBaseURL is this
// backend's own externally-reachable origin (config.OAuthRedirectBaseURL)
// -- distinct from appBaseURL (the frontend's origin, where the browser
// ends up after Callback) and, unlike Client ID/Secret, not something an
// Owner edits through the UI (it's about where this backend itself is
// reachable from, not a provider credential).
func NewOAuthHandler(settings *services.PlatformSettingsService, redirectBaseURL string, auth *services.AuthService, audit *services.AuditService, cookieSecure bool, appBaseURL string) *OAuthHandler {
	return &OAuthHandler{settings: settings, redirectBaseURL: redirectBaseURL, auth: auth, audit: audit, cookieSecure: cookieSecure, appBaseURL: appBaseURL}
}

// provider builds a fresh OAuthProvider for providerName from whatever is
// currently configured (DB-backed, falling back to .env) -- see this
// file's package doc for why this is constructed per-call rather than
// once at startup. Returns nil for an unrecognized name or if settings
// can't be loaded.
func (h *OAuthHandler) provider(ctx context.Context, providerName string) services.OAuthProvider {
	live, err := h.settings.Get(ctx)
	if err != nil {
		return nil
	}
	switch providerName {
	case string(services.OAuthProviderGitHub):
		return services.NewGitHubOAuthProvider(live.GitHubClientID, live.GitHubClientSecret, h.redirectBaseURL)
	case string(services.OAuthProviderGoogle):
		return services.NewGoogleOAuthProvider(live.GoogleClientID, live.GoogleClientSecret, h.redirectBaseURL)
	default:
		return nil
	}
}

// oauthStateCookieName is provider-specific (not one shared name) so two
// sign-in attempts started in different tabs never clobber each other's
// pending state.
func oauthStateCookieName(providerName string) string {
	return "oauth_state_" + providerName
}

// Providers handles GET /api/auth/oauth/providers (public) -- lets the
// login page know which "Continue with..." buttons to actually render,
// without exposing anything beyond a plain configured/not boolean.
func (h *OAuthHandler) Providers(w http.ResponseWriter, r *http.Request) {
	github := h.provider(r.Context(), string(services.OAuthProviderGitHub))
	google := h.provider(r.Context(), string(services.OAuthProviderGoogle))
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{
		"github": github != nil && github.Configured(),
		"google": google != nil && google.Configured(),
	})
}

// Start handles GET /api/auth/oauth/{provider}/start.
func (h *OAuthHandler) Start(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	provider := h.provider(r.Context(), providerName)
	if provider == nil || !provider.Configured() {
		http.Redirect(w, r, h.appBaseURL+"/login?oauth_error=failed", http.StatusFound)
		return
	}

	state, err := services.GenerateOAuthState()
	if err != nil {
		http.Redirect(w, r, h.appBaseURL+"/login?oauth_error=failed", http.StatusFound)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oauthStateCookieName(providerName), Value: state, Path: "/api/auth/oauth",
		MaxAge: 600, HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, provider.AuthURL(state), http.StatusFound)
}

// Callback handles GET /api/auth/oauth/{provider}/callback.
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	provider := h.provider(r.Context(), providerName)
	if provider == nil || !provider.Configured() {
		http.Redirect(w, r, h.appBaseURL+"/login?oauth_error=failed", http.StatusFound)
		return
	}

	// Single-use: clear the state cookie no matter which path below is
	// taken, success or failure.
	defer http.SetCookie(w, &http.Cookie{
		Name: oauthStateCookieName(providerName), Value: "", Path: "/api/auth/oauth",
		MaxAge: -1, HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode,
	})

	cookie, cookieErr := r.Cookie(oauthStateCookieName(providerName))
	state := r.URL.Query().Get("state")
	if cookieErr != nil || cookie.Value == "" || state == "" || cookie.Value != state {
		h.logFailure(r, providerName, "", "state_mismatch")
		http.Redirect(w, r, h.appBaseURL+"/login?oauth_error=failed", http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.logFailure(r, providerName, "", "no_code")
		http.Redirect(w, r, h.appBaseURL+"/login?oauth_error=failed", http.StatusFound)
		return
	}

	email, err := provider.Exchange(r.Context(), code)
	if err != nil {
		h.logFailure(r, providerName, "", "exchange_failed")
		http.Redirect(w, r, h.appBaseURL+"/login?oauth_error=failed", http.StatusFound)
		return
	}

	session, err := h.auth.LoginWithVerifiedEmail(r.Context(), email)
	if err != nil {
		errCode := "failed"
		switch {
		case errors.Is(err, services.ErrNoAccountForEmail):
			errCode = "no_account"
		case errors.Is(err, services.ErrAccountDisabled):
			errCode = "disabled"
		}
		h.logFailure(r, providerName, email, errCode)
		http.Redirect(w, r, h.appBaseURL+"/login?oauth_error="+errCode, http.StatusFound)
		return
	}

	setAuthCookies(w, session, h.cookieSecure)
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &session.User.ID, Action: services.AuditUserLoginSuccess,
		Metadata: map[string]any{"method": "oauth", "provider": providerName},
	})
	http.Redirect(w, r, h.appBaseURL+"/", http.StatusFound)
}

func (h *OAuthHandler) logFailure(r *http.Request, providerName, email, reason string) {
	metadata := map[string]any{"method": "oauth", "provider": providerName, "reason": reason}
	if email != "" {
		metadata["email"] = email
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{Action: services.AuditUserLoginFailed, Metadata: metadata})
}
