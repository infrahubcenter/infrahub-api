package handlers

import (
	"net/http"
	"time"
	"vmcontrolcenter/backend/internal/httpx"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Stream handles GET
// /api/vms/:id/docker/containers/:containerId/stats/stream (spec §49-54):
// a WebSocket that pushes the container's latest cached metrics sample
// once per DOCKER_STATS_STREAM_INTERVAL. It never opens an SSH connection
// itself and never triggers DockerMetricsService directly -- every tick
// only reads DockerMetricsCache, which DockerMetricsScheduler populates
// independently on its own cadence. Multiple browser viewers of the same
// container therefore share one collector: each gets its own lightweight
// per-connection goroutine here, never its own SSH session (spec's "don't
// open a new SSH connection per viewer/per tick" mandate). This is a
// read-only metrics feed, not a console -- no Docker exec/attach of any
// kind is implemented here or anywhere else in this step.
func (h *DockerHandler) Stream(w http.ResponseWriter, r *http.Request) {
	_, vm, ok := h.authorizeVMView(w, r)
	if !ok {
		return
	}
	container, ok := h.authorizeContainer(w, r, vm.ID)
	if !ok {
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			// Same-origin tools (no Origin header at all) and the
			// configured frontend origin are allowed; anything else is
			// cross-site WebSocket hijacking and is refused, mirroring
			// middleware.CORS's single allowed origin for regular
			// requests.
			return origin == "" || httpx.OriginAllowed(h.frontendOrigin, origin)
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote its own HTTP error response
	}
	defer conn.Close()

	ctx := r.Context()
	closed := make(chan struct{})
	go func() {
		// gorilla/websocket requires a continuous reader to process
		// control frames (ping/pong/close) and to detect the client
		// going away -- this connection is otherwise server-push-only,
		// so any inbound message is unexpected and just treated as
		// "the client is done".
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	interval := h.streamInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if !h.pushCurrentSample(conn, container.ID, container.Name) {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			if !h.pushCurrentSample(conn, container.ID, container.Name) {
				return
			}
		}
	}
}

// pushCurrentSample writes the container's latest cached sample (or a
// "waiting" frame if nothing has been collected for it yet) as one JSON
// frame. Returns false on a write failure (connection gone), so the
// caller's loop can stop.
func (h *DockerHandler) pushCurrentSample(conn *websocket.Conn, containerID uuid.UUID, containerName string) bool {
	entry, ok := h.cache.Get(containerID)
	if !ok {
		return conn.WriteJSON(map[string]any{"type": "waiting", "reason": "no metrics collected yet for this container"}) == nil
	}
	dto := statsToMetricDTO(containerID, containerName, entry.Stats, entry.CapturedAt, time.Since(entry.CapturedAt) > h.staleAfter)
	return conn.WriteJSON(dto) == nil
}
