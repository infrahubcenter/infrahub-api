// Package handlers: k8s_agent.go is the in-cluster K8s agent's own
// inbound connection point (GET /api/k8s/agent/connect) -- the other end
// of every K8s command in this app (discovery, connection-test, live-tail
// and captured logs all flow through whatever agent is currently
// registered for a cluster; see services.K8sAgentHub). There is no human
// at the other end of this endpoint, so it is authenticated by a bearer
// token (services.K8sAgentTokenService), never the session-cookie model
// every other route in this app uses, and is deliberately mounted outside
// requireAuth/requireAdmin in router.go.
package handlers

import (
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

type K8sAgentHandler struct {
	hub    *services.K8sAgentHub
	tokens *services.K8sAgentTokenService
}

func NewK8sAgentHandler(hub *services.K8sAgentHub, tokens *services.K8sAgentTokenService) *K8sAgentHandler {
	return &K8sAgentHandler{hub: hub, tokens: tokens}
}

// Connect handles GET /api/k8s/agent/connect. Blocks, serving the
// connection, until the agent disconnects.
func (h *K8sAgentHandler) Connect(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	clusterID, err := h.tokens.ClusterIDForToken(r.Context(), token)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid agent token")
		return
	}

	upgrader := websocket.Upgrader{
		// The caller here is our own agent binary, authenticated by the
		// bearer token above -- never a browser, so there is no
		// cookie/CSRF-style same-origin concern the way there is for
		// every other WebSocket endpoint in this app (VM Console, Docker
		// Logs, the pod-logs live-tail below).
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	conn := h.hub.Register(clusterID, ws)
	_ = h.tokens.MarkConnected(r.Context(), clusterID)
	defer func() {
		h.hub.Unregister(clusterID, conn)
		_ = ws.Close()
	}()

	h.hub.Serve(conn)
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, prefix) {
		return strings.TrimPrefix(auth, prefix)
	}
	return ""
}
