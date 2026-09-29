package middleware

import (
	"log/slog"
	"net/http"

	"vmcontrolcenter/backend/internal/httpx"
)

// Recovery recovers from panics in downstream handlers, logs the panic, and
// returns a JSON 500 response instead of crashing the server.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered",
						"error", err,
						"path", r.URL.Path,
						"method", r.Method,
					)
					httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
