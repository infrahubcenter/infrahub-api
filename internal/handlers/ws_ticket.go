package handlers

import (
	"net/http"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

// WSTicket handles POST /api/auth/ws-ticket: issues a short-lived WebSocket
// ticket for the signed-in user. A console hosted on another site (whose
// session cookie can't reach this backend's domain) calls this through its
// own server-side proxy, then opens WebSockets directly to this API with
// ?ws_ticket=<ticket>. See services.WSTicketAudience.
func WSTicket(tokens *services.TokenService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := services.UserFromContext(r.Context())
		if !ok {
			httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		ticket, err := tokens.IssueWSTicket(user.ID, user.Role)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to issue ticket")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"ticket":     ticket,
			"expires_in": int(services.WSTicketTTL.Seconds()),
		})
	}
}
