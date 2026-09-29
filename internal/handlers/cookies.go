package handlers

import (
	"net/http"

	"vmcontrolcenter/backend/internal/middleware"
	"vmcontrolcenter/backend/internal/services"
)

// setAuthCookies writes the access and refresh tokens as HttpOnly cookies.
// The access token cookie is scoped to the whole API (Path=/); the refresh
// token cookie is scoped narrowly to /api/auth so it is only ever sent on
// refresh/logout requests, limiting its exposure. SameSite=Lax is enough
// here because the frontend and backend are same-site (both "localhost",
// differing only by port) even in production-like same-domain deployments;
// it is not sent cross-site, unlike SameSite=None would require.
func setAuthCookies(w http.ResponseWriter, session services.Session, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.AccessTokenCookie,
		Value:    session.AccessToken,
		Path:     "/",
		Expires:  session.AccessTokenExpiresAt,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.RefreshTokenCookie,
		Value:    session.RefreshToken,
		Path:     "/api/auth",
		Expires:  session.RefreshTokenExpiresAt,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearAuthCookies expires both auth cookies (logout).
func clearAuthCookies(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.AccessTokenCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.RefreshTokenCookie,
		Value:    "",
		Path:     "/api/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func refreshTokenFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(middleware.RefreshTokenCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}
