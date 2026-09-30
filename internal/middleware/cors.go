package middleware

import (
	"net/http"

	"vmcontrolcenter/backend/internal/httpx"
)

// CORS allows the configured frontend origin to call the API with
// credentials (cookies). Cookie *sending* between localhost:3000 and
// localhost:8080 is governed by SameSite, not CORS (they're same-site,
// different origin) -- this middleware is what lets the browser's fetch()
// actually read the response.
func CORS(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// allowedOrigin may list several origins (comma-separated): echo
			// the request's Origin only when it is one of them.
			origin := r.Header.Get("Origin")
			if httpx.OriginAllowed(allowedOrigin, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else {
				w.Header().Set("Access-Control-Allow-Origin", httpx.FirstOrigin(allowedOrigin))
			}
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
