package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

// AuthHandler implements login/refresh/logout/me.
type AuthHandler struct {
	auth         *services.AuthService
	audit        *services.AuditService
	cookieSecure bool
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(auth *services.AuthService, audit *services.AuditService, cookieSecure bool) *AuthHandler {
	return &AuthHandler{auth: auth, audit: audit, cookieSecure: cookieSecure}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func toUserResponse(u services.AuthenticatedUser) userResponse {
	return userResponse{ID: u.ID.String(), Name: u.Name, Email: u.Email, Role: u.Role}
}

// Login handles POST /api/auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	session, err := h.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		h.logLoginFailure(r, req.Email, err)
		// Same generic message regardless of cause (unknown email, wrong
		// password, disabled account) -- see services.ErrInvalidCredentials.
		httpx.WriteError(w, http.StatusUnauthorized, "Invalid email or password.")
		return
	}

	setAuthCookies(w, session, h.cookieSecure)

	h.logAudit(r, services.AuditEvent{
		UserID: &session.User.ID,
		Action: services.AuditUserLoginSuccess,
	})

	httpx.WriteJSON(w, http.StatusOK, toUserResponse(session.User))
}

func (h *AuthHandler) logLoginFailure(r *http.Request, email string, err error) {
	metadata := map[string]any{"email": email}
	if errors.Is(err, services.ErrAccountDisabled) {
		metadata["reason"] = "account_disabled"
	} else {
		metadata["reason"] = "invalid_credentials"
	}
	h.logAudit(r, services.AuditEvent{
		Action:   services.AuditUserLoginFailed,
		Metadata: metadata,
	})
}

// Refresh handles POST /api/auth/refresh.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := refreshTokenFromRequest(r)
	if refreshToken == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "no refresh token")
		return
	}

	session, err := h.auth.Refresh(r.Context(), refreshToken)
	if err != nil {
		clearAuthCookies(w, h.cookieSecure)
		httpx.WriteError(w, http.StatusUnauthorized, "session expired, please log in again")
		return
	}

	setAuthCookies(w, session, h.cookieSecure)
	httpx.WriteJSON(w, http.StatusOK, toUserResponse(session.User))
}

// Logout handles POST /api/auth/logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	refreshToken := refreshTokenFromRequest(r)
	if err := h.auth.Logout(r.Context(), refreshToken); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "logout failed")
		return
	}

	if user, ok := services.UserFromContext(r.Context()); ok {
		h.logAudit(r, services.AuditEvent{UserID: &user.ID, Action: services.AuditUserLogout})
	}

	clearAuthCookies(w, h.cookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Me handles GET /api/auth/me. Requires RequireAuthentication.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toUserResponse(user))
}

func (h *AuthHandler) logAudit(r *http.Request, event services.AuditEvent) {
	_ = h.audit.LogFrom(r, event) // best-effort: never block the request on audit-log failure
}
