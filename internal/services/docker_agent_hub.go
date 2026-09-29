// Package services: docker_agent_hub.go is the in-memory registry of
// currently-connected Docker agent WebSocket connections, and the
// request/response (and streaming) correlation layer on top of them. One
// agent connects per VM (see handlers.DockerAgentHandler for the
// WebSocket endpoint itself); the hub is purely transport plumbing --
// nothing here decides what a command means, that's DockerAgentService.
// Mirrors k8s_agent_hub.go field-for-field and method-for-method, keyed
// by vm_resource_id instead of k8s_cluster_id.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ErrDockerAgentOffline means no agent is currently connected for this
// VM -- either one was never installed, or it's since disconnected
// (crashed, was uninstalled, lost network, etc.).
var ErrDockerAgentOffline = errors.New("no agent is currently connected for this VM")

type dockerAgentConnection struct {
	ws      *websocket.Conn
	writeMu sync.Mutex

	mu      sync.Mutex
	waiters map[string]chan DockerAgentMessage
	streams map[string]chan DockerAgentMessage
}

func newDockerAgentConnection(ws *websocket.Conn) *dockerAgentConnection {
	return &dockerAgentConnection{ws: ws, waiters: map[string]chan DockerAgentMessage{}, streams: map[string]chan DockerAgentMessage{}}
}

func (c *dockerAgentConnection) send(cmd DockerAgentCommand) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.WriteJSON(cmd)
}

// readLoop demultiplexes inbound messages by ID until the connection
// closes (including a liveness timeout -- see agentPongWait, the same
// constant k8s_agent_hub.go uses), at which point every still-pending
// waiter/stream is unblocked rather than left hanging forever.
func (c *dockerAgentConnection) readLoop() {
	defer c.closeAllPending()

	_ = c.ws.SetReadDeadline(time.Now().Add(agentPongWait))
	c.ws.SetPingHandler(func(string) error {
		// Overriding the handler replaces gorilla's default (which just
		// writes a pong) -- reproduce that here in addition to the deadline
		// bump, or the agent's own liveness check on OUR side would starve.
		_ = c.ws.SetReadDeadline(time.Now().Add(agentPongWait))
		c.writeMu.Lock()
		err := c.ws.WriteControl(websocket.PongMessage, nil, time.Now().Add(writeWait))
		c.writeMu.Unlock()
		if err != nil && errors.Is(err, websocket.ErrCloseSent) {
			return nil
		}
		return err
	})

	for {
		var msg DockerAgentMessage
		if err := c.ws.ReadJSON(&msg); err != nil {
			return
		}
		_ = c.ws.SetReadDeadline(time.Now().Add(agentPongWait))
		c.dispatch(msg)
	}
}

func (c *dockerAgentConnection) dispatch(msg DockerAgentMessage) {
	c.mu.Lock()
	waiter, isWaiter := c.waiters[msg.ID]
	if isWaiter {
		delete(c.waiters, msg.ID)
	}
	stream, isStream := c.streams[msg.ID]
	c.mu.Unlock()

	switch {
	case isWaiter:
		waiter <- msg
		close(waiter)
	case isStream:
		select {
		case stream <- msg:
		case <-time.After(5 * time.Second):
			// A stalled consumer must never wedge the whole connection's
			// read loop -- drop the message and move on.
		}
	}
}

func (c *dockerAgentConnection) closeAllPending() {
	c.mu.Lock()
	defer c.mu.Unlock()
	closedErr := DockerAgentMessage{Type: DockerAgentMsgError, Message: "agent connection closed"}
	for id, ch := range c.waiters {
		msg := closedErr
		msg.ID = id
		ch <- msg
		close(ch)
	}
	c.waiters = map[string]chan DockerAgentMessage{}
	for _, ch := range c.streams {
		close(ch)
	}
	c.streams = map[string]chan DockerAgentMessage{}
}

func (c *dockerAgentConnection) registerWaiter(id string) chan DockerAgentMessage {
	ch := make(chan DockerAgentMessage, 1)
	c.mu.Lock()
	c.waiters[id] = ch
	c.mu.Unlock()
	return ch
}

func (c *dockerAgentConnection) forgetWaiter(id string) {
	c.mu.Lock()
	delete(c.waiters, id)
	c.mu.Unlock()
}

func (c *dockerAgentConnection) registerStream(id string) chan DockerAgentMessage {
	ch := make(chan DockerAgentMessage, streamBufferSize)
	c.mu.Lock()
	c.streams[id] = ch
	c.mu.Unlock()
	return ch
}

func (c *dockerAgentConnection) forgetStream(id string) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

// DockerAgentHub is the process-wide registry of live agent connections,
// keyed by the VM's resources.id. Safe for concurrent use.
type DockerAgentHub struct {
	mu    sync.RWMutex
	conns map[uuid.UUID]*dockerAgentConnection
}

// NewDockerAgentHub creates an empty DockerAgentHub.
func NewDockerAgentHub() *DockerAgentHub {
	return &DockerAgentHub{conns: map[uuid.UUID]*dockerAgentConnection{}}
}

// Register starts serving vmResourceID's agent traffic through ws,
// replacing any previous connection for the same VM (a new agent
// connecting -- e.g. after the VM rebooted -- always supersedes an old
// one, never stacks). The caller must run the returned connection's read
// loop (Serve) and eventually call Unregister when it ends.
func (h *DockerAgentHub) Register(vmResourceID uuid.UUID, ws *websocket.Conn) *dockerAgentConnection {
	conn := newDockerAgentConnection(ws)
	h.mu.Lock()
	h.conns[vmResourceID] = conn
	h.mu.Unlock()
	return conn
}

// Serve runs conn's read loop until the WebSocket closes. Blocking --
// call in its own goroutine.
func (h *DockerAgentHub) Serve(conn *dockerAgentConnection) {
	conn.readLoop()
}

// Unregister removes vmResourceID's entry, but only if conn is still the
// current one for that VM -- a newer connection that already replaced it
// via Register must never be evicted by the old one's own (now-
// irrelevant) cleanup.
func (h *DockerAgentHub) Unregister(vmResourceID uuid.UUID, conn *dockerAgentConnection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[vmResourceID] == conn {
		delete(h.conns, vmResourceID)
	}
}

// IsConnected reports whether a live agent connection currently exists
// for vmResourceID.
func (h *DockerAgentHub) IsConnected(vmResourceID uuid.UUID) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.conns[vmResourceID]
	return ok
}

func (h *DockerAgentHub) get(vmResourceID uuid.UUID) (*dockerAgentConnection, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	conn, ok := h.conns[vmResourceID]
	if !ok {
		return nil, ErrDockerAgentOffline
	}
	return conn, nil
}

// SendCommand sends a one-shot command (never stream_logs -- see
// StreamLogs) and waits for exactly one result/error response, ctx
// cancellation, or the connection closing, whichever comes first.
func (h *DockerAgentHub) SendCommand(ctx context.Context, vmResourceID uuid.UUID, cmd DockerAgentCommand) (json.RawMessage, error) {
	conn, err := h.get(vmResourceID)
	if err != nil {
		return nil, err
	}
	cmd.ID = uuid.NewString()
	waiter := conn.registerWaiter(cmd.ID)
	defer conn.forgetWaiter(cmd.ID)

	if err := conn.send(cmd); err != nil {
		return nil, fmt.Errorf("send command to agent: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg, ok := <-waiter:
		if !ok {
			return nil, errors.New("agent connection closed before responding")
		}
		if msg.Type == DockerAgentMsgError {
			return nil, fmt.Errorf("agent error: %s", msg.Message)
		}
		return msg.Data, nil
	}
}

// StreamLogs starts a stream_logs command and returns a channel of
// incoming messages (zero or more log_line, then exactly one done or
// error) plus a cleanup func the caller MUST call exactly once when
// finished (whether the stream ran to "done" or the caller gave up
// early) -- it tells the agent to stop and releases the subscription.
func (h *DockerAgentHub) StreamLogs(vmResourceID uuid.UUID, containerID, since string) (<-chan DockerAgentMessage, func(), error) {
	conn, err := h.get(vmResourceID)
	if err != nil {
		return nil, nil, err
	}
	id := uuid.NewString()
	stream := conn.registerStream(id)

	cleanup := func() {
		conn.forgetStream(id)
		_ = conn.send(DockerAgentCommand{ID: id, Type: DockerAgentCmdStopStream})
	}

	if err := conn.send(DockerAgentCommand{ID: id, Type: DockerAgentCmdStreamLogs, ContainerID: containerID, Since: since}); err != nil {
		conn.forgetStream(id)
		return nil, nil, fmt.Errorf("send command to agent: %w", err)
	}
	return stream, cleanup, nil
}
