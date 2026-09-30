package middleware

import (
	"net/http"
	"strings"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

// Cookie names shared between the login/refresh/logout handlers (which set
// them) and RequireAuthentication (which reads them).
const (
	AccessTokenCookie  = "vmcc_access_token"
	RefreshTokenCookie = "vmcc_refresh_token"
)

// RequireAuthentication validates the access token (cookie, falling back to
// an Authorization: Bearer header for non-browser API clients), re-loads
// the user's live state (so a role change or deactivation takes effect
// immediately rather than trusting stale JWT claims), and attaches the
// identity to the request context via services.WithUser. Any failure is
// 401 Unauthorized.
func RequireAuthentication(tokens *services.TokenService, auth *services.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, fromTicket := accessTokenFromRequest(r)
			if tokenString == "" {
				httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			claims, err := tokens.ParseAccessToken(tokenString)
			if err != nil {
				httpx.WriteError(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}
			// A WebSocket ticket is only valid as ?ws_ticket= on a WebSocket
			// upgrade, and a ?ws_ticket= must actually be a ticket -- so a
			// leaked ticket can't be replayed as a normal login, and a
			// normal session token can't be passed around in URLs.
			if fromTicket != services.IsWSTicket(claims) {
				httpx.WriteError(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}

			user, err := auth.Me(r.Context(), claims.UserID)
			if err != nil {
				httpx.WriteError(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}

			ctx := services.WithUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// accessTokenFromRequest returns the request's token and whether it came
// from a ?ws_ticket= query parameter (accepted on WebSocket upgrades only).
func accessTokenFromRequest(r *http.Request) (string, bool) {
	if cookie, err := r.Cookie(AccessTokenCookie); err == nil && cookie.Value != "" {
		return cookie.Value, false
	}
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), false
	}
	if ticket := r.URL.Query().Get("ws_ticket"); ticket != "" && IsWebSocketUpgrade(r) {
		return ticket, true
	}
	return "", false
}

// IsWebSocketUpgrade reports whether r asks to upgrade to a WebSocket.
func IsWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// RequireRole allows the request through only if the authenticated user
// (attached by RequireAuthentication, which must run first) holds role
// exactly. Anything more granular than a single role check belongs in
// services.AuthorizationService, not here -- see CanAccessVM. Use
// RequireAnyRole instead when a hierarchy applies (e.g. Owner satisfying
// an Admin-only route) -- this exact-match version is for the rare
// genuinely role-exclusive gate (see requireOwner in router.go).
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := services.UserFromContext(r.Context())
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if user.Role != role {
				httpx.WriteError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole allows the request through if the authenticated user
// holds any one of roles -- the router's requireAdmin closure uses this
// with (RoleAdmin, RoleOwner) so Owner (a strict superset of Admin)
// passes every one of the ~138 existing Admin-gated routes without
// touching each route individually.
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := services.UserFromContext(r.Context())
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			for _, role := range roles {
				if user.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			httpx.WriteError(w, http.StatusForbidden, "insufficient permissions")
		})
	}
}
