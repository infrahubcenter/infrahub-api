package middleware

import "net/http"

// SecurityHeaders sets a minimal set of always-safe, zero-compatibility-risk
// hardening headers appropriate for a JSON API -- the frontend, a separate
// Next.js app, is responsible for its own page-level CSP. hstsEnabled
// mirrors CookieSecure's own "are we in a production/HTTPS context" signal:
// Strict-Transport-Security is meaningless (and actively wrong to promise)
// over a plain-HTTP local development server.
func SecurityHeaders(hstsEnabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			if hstsEnabled {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBody wraps the request body in http.MaxBytesReader so a handler's
// json.NewDecoder(r.Body).Decode (or any other Body read) can never be
// forced to buffer an unbounded/oversized payload into memory. Handlers
// that read strictly small, well-shaped JSON bodies (every write endpoint
// in this project) never need more than maxBytes; a request that exceeds
// it fails with a body-read error, which existing decode-error handling
// already turns into a 400.
func MaxBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
