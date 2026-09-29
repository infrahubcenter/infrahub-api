package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vmcontrolcenter/backend/internal/httpx"
)

// HealthHandler reports application and database liveness.
type HealthHandler struct {
	pool *pgxpool.Pool
}

// NewHealthHandler creates a HealthHandler backed by pool.
func NewHealthHandler(pool *pgxpool.Pool) *HealthHandler {
	return &HealthHandler{pool: pool}
}

// Live responds 200 with {"status":"ok"} unconditionally: it never touches
// the database or any other dependency, so an orchestrator's liveness
// probe (which should only ask "is the process alive, or does it need a
// restart") can never be failed by a database outage or a slow/unreachable
// VM/database/object-storage resource elsewhere in the system -- that is
// exactly what Health (the readiness check) below is for instead.
func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Health responds 200 with {"status":"ok","database":"ok"} when the database
// is reachable, or 503 with {"status":"degraded","database":"unavailable"}
// when it is not. This is a readiness check, not a liveness one -- it
// deliberately checks only this application's own database connection
// pool, never any VM/database/object-storage resource the application
// merely monitors, so one unreachable piece of managed infrastructure can
// never make the platform itself report unhealthy (Step 20 spec §29).
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := h.pool.Ping(ctx); err != nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status":   "degraded",
			"database": "unavailable",
		})
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"status":   "ok",
		"database": "ok",
	})
}
