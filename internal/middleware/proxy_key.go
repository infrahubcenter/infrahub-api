package middleware

import (
	"crypto/subtle"
	"net/http"

	"vmcontrolcenter/backend/internal/httpx"
)

// ProxyKeyHeader carries the shared secret between the hosted console's
// server-side proxy (or the gateway) and this API.
const ProxyKeyHeader = "X-Infrahub-Proxy-Key"

// RequireProxyKey, when key is set (INFRAHUB_PROXY_KEY), rejects every
// request that doesn't carry it -- so a publicly reachable backend URL
// (e.g. the laptop's ngrok domain) can't be used for REST calls or logins
// by anyone except the configured proxies. Exempt:
//   - WebSocket upgrades: agents authenticate with their own tokens, and
//     browser sockets with a WebSocket ticket plus the Origin allow-list.
//   - /api/health and /api/live, so uptime checks keep working.
//
// An empty key disables the check (single-origin deployments).
func RequireProxyKey(key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if key == "" {
			return next
		}
		want := []byte(key)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsWebSocketUpgrade(r) || r.URL.Path == "/api/health" || r.URL.Path == "/api/live" {
				next.ServeHTTP(w, r)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.Header.Get(ProxyKeyHeader)), want) != 1 {
				httpx.WriteError(w, http.StatusForbidden, "direct access to this API is not allowed")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
