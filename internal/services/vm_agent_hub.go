// Package services: vm_agent_hub.go is the in-memory registry of
// currently-connected VM Agent WebSocket connections, and the
// request/response (and streaming) correlation layer on top of them --
// structurally mirrors docker_agent_hub.go field-for-field and
// method-for-method, keyed by vm_resource_id.
//
// The one real difference: this agent also sends metrics_push messages
// the backend never asked for (always empty ID -- see
// vm_agent_protocol.go). dispatch() checks msg.Type for that case before
// the normal waiter/stream lookup, and routes it to a small BOUNDED worker
// pool with non-blocking, drop-on-full enqueue -- deliberately not
// synchronous and not unbounded: a slow DB write must never stall this
// connection's own read loop (which also handles ping/pong liveness and
// any concurrent log stream for the same VM), and a dropped metrics
// sample is harmless since another one arrives on the next push interval.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ErrVMAgentOffline means no VM Agent is currently connected for this VM
// -- either one was never installed, or it's since disconnected.
var ErrVMAgentOffline = errors.New("no agent is currently connected for this VM")

// vmAgentPushQueueSize bounds how many not-yet-processed metrics_push
// messages the hub will buffer across all connections before it starts
// dropping new ones -- generous relative to the expected push interval
// (tens of seconds) and worker count, so it only ever engages under a
// genuine backend-side stall, not normal jitter.
const vmAgentPushQueueSize = 256

// vmAgentPushWorkers is the fixed size of the bounded worker pool that
// persists metrics_push payloads -- small on purpose (this is a DB
// insert, not CPU work); NewVMAgentHub starts exactly this many goroutines
// for the lifetime of the process.
const vmAgentPushWorkers = 4

type vmAgentPushJob struct {
	vmResourceID uuid.UUID
	data         VMAgentMetricsPushData
}

type vmAgentConnection struct {
	ws      *websocket.Conn
	writeMu sync.Mutex

	mu      sync.Mutex
	waiters map[string]chan VMAgentMessage
	streams map[string]chan VMAgentMessage
}

func newVMAgentConnection(ws *websocket.Conn) *vmAgentConnection {
	return &vmAgentConnection{ws: ws, waiters: map[string]chan VMAgentMessage{}, streams: map[string]chan VMAgentMessage{}}
}

func (c *vmAgentConnection) send(cmd VMAgentCommand) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.WriteJSON(cmd)
}

// readLoop demultiplexes inbound messages until the connection closes
// (including a liveness timeout -- agentPongWait, the same constant
// docker_agent_hub.go/k8s_agent_hub.go use), at which point every
// still-pending waiter/stream is unblocked rather than left hanging
// forever.
func (c *vmAgentConnection) readLoop(vmResourceID uuid.UUID, hub *VMAgentHub) {
	defer c.closeAllPending()

	_ = c.ws.SetReadDeadline(time.Now().Add(agentPongWait))
	c.ws.SetPingHandler(func(string) error {
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
		var msg VMAgentMessage
		if err := c.ws.ReadJSON(&msg); err != nil {
			return
		}
		_ = c.ws.SetReadDeadline(time.Now().Add(agentPongWait))
		c.dispatch(vmResourceID, msg, hub)
	}
}

func (c *vmAgentConnection) dispatch(vmResourceID uuid.UUID, msg VMAgentMessage, hub *VMAgentHub) {
	if msg.Type == VMAgentMsgMetricsPush {
		hub.enqueuePush(vmResourceID, msg)
		return
	}

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

func (c *vmAgentConnection) closeAllPending() {
	c.mu.Lock()
	defer c.mu.Unlock()
	closedErr := VMAgentMessage{Type: VMAgentMsgError, Message: "agent connection closed"}
	for id, ch := range c.waiters {
		msg := closedErr
		msg.ID = id
		ch <- msg
		close(ch)
	}
	c.waiters = map[string]chan VMAgentMessage{}
	for _, ch := range c.streams {
		close(ch)
	}
	c.streams = map[string]chan VMAgentMessage{}
}

func (c *vmAgentConnection) registerWaiter(id string) chan VMAgentMessage {
	ch := make(chan VMAgentMessage, 1)
	c.mu.Lock()
	c.waiters[id] = ch
	c.mu.Unlock()
	return ch
}

func (c *vmAgentConnection) forgetWaiter(id string) {
	c.mu.Lock()
	delete(c.waiters, id)
	c.mu.Unlock()
}

func (c *vmAgentConnection) registerStream(id string) chan VMAgentMessage {
	ch := make(chan VMAgentMessage, streamBufferSize)
	c.mu.Lock()
	c.streams[id] = ch
	c.mu.Unlock()
	return ch
}

func (c *vmAgentConnection) forgetStream(id string) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

// VMAgentHub is the process-wide registry of live VM Agent connections,
// keyed by the VM's resources.id, plus the bounded push-processing pool
// described in this file's doc comment. Safe for concurrent use.
type VMAgentHub struct {
	mu    sync.RWMutex
	conns map[uuid.UUID]*vmAgentConnection

	pushQueue chan vmAgentPushJob
	onPush    func(ctx context.Context, vmResourceID uuid.UUID, data VMAgentMetricsPushData) error
	logger    *slog.Logger
}

// NewVMAgentHub creates a VMAgentHub and starts its fixed-size push-worker
// pool. onPush is called from a worker goroutine (never the connection's
// own read loop) for every successfully decoded metrics_push message --
// typically VMAgentService.HandleMetricsPush, wired here rather than
// looked up per-message so the hub itself never needs to know about
// PackageService/repository types. Its error return is logged, never
// propagated -- there is no request to fail back to an agent that never
// expects an answer to a push.
func NewVMAgentHub(logger *slog.Logger, onPush func(ctx context.Context, vmResourceID uuid.UUID, data VMAgentMetricsPushData) error) *VMAgentHub {
	if logger == nil {
		logger = slog.Default()
	}
	h := &VMAgentHub{
		conns:     map[uuid.UUID]*vmAgentConnection{},
		pushQueue: make(chan vmAgentPushJob, vmAgentPushQueueSize),
		onPush:    onPush,
		logger:    logger,
	}
	for i := 0; i < vmAgentPushWorkers; i++ {
		go h.pushWorker()
	}
	return h
}

func (h *VMAgentHub) pushWorker() {
	for job := range h.pushQueue {
		// A bounded, per-job timeout -- not tied to any connection's
		// lifetime -- so one slow write can't pin a worker indefinitely
		// and starve the rest of the queue.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := h.onPush(ctx, job.vmResourceID, job.data); err != nil {
			h.logger.Warn("vm agent: failed to process metrics_push", "vm_resource_id", job.vmResourceID, "error", err)
		}
		cancel()
	}
}

// enqueuePush decodes msg.Data and enqueues it for background processing.
// Non-blocking: if the queue is already full, the sample is dropped (with
// a log line) rather than blocking this connection's readLoop, which
// would otherwise stall ping/pong liveness handling and any concurrent
// log stream sharing this same connection.
func (h *VMAgentHub) enqueuePush(vmResourceID uuid.UUID, msg VMAgentMessage) {
	var data VMAgentMetricsPushData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		h.logger.Warn("vm agent: malformed metrics_push payload", "vm_resource_id", vmResourceID, "error", err)
		return
	}
	select {
	case h.pushQueue <- vmAgentPushJob{vmResourceID: vmResourceID, data: data}:
	default:
		h.logger.Warn("vm agent: dropped metrics_push, worker queue full", "vm_resource_id", vmResourceID)
	}
}

// Register starts serving vmResourceID's agent traffic through ws,
// replacing any previous connection for the same VM. The caller must run
// the returned connection's read loop (Serve) and eventually call
// Unregister when it ends.
func (h *VMAgentHub) Register(vmResourceID uuid.UUID, ws *websocket.Conn) *vmAgentConnection {
	conn := newVMAgentConnection(ws)
	h.mu.Lock()
	h.conns[vmResourceID] = conn
	h.mu.Unlock()
	return conn
}

// Serve runs conn's read loop until the WebSocket closes. Blocking --
// call in its own goroutine.
func (h *VMAgentHub) Serve(vmResourceID uuid.UUID, conn *vmAgentConnection) {
	conn.readLoop(vmResourceID, h)
}

// Unregister removes vmResourceID's entry, but only if conn is still the
// current one for that VM.
func (h *VMAgentHub) Unregister(vmResourceID uuid.UUID, conn *vmAgentConnection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[vmResourceID] == conn {
		delete(h.conns, vmResourceID)
	}
}

// IsConnected reports whether a live agent connection currently exists
// for vmResourceID.
func (h *VMAgentHub) IsConnected(vmResourceID uuid.UUID) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.conns[vmResourceID]
	return ok
}

func (h *VMAgentHub) get(vmResourceID uuid.UUID) (*vmAgentConnection, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	conn, ok := h.conns[vmResourceID]
	if !ok {
		return nil, ErrVMAgentOffline
	}
	return conn, nil
}

// SendCommand sends a one-shot command (never stream_logs -- see
// StreamLogs) and waits for exactly one result/error response, ctx
// cancellation, or the connection closing, whichever comes first.
func (h *VMAgentHub) SendCommand(ctx context.Context, vmResourceID uuid.UUID, cmd VMAgentCommand) (json.RawMessage, error) {
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
		if msg.Type == VMAgentMsgError {
			return nil, fmt.Errorf("agent error: %s", msg.Message)
		}
		return msg.Data, nil
	}
}

// StreamLogs starts a stream_logs command and returns a channel of
// incoming messages (zero or more log_line, then exactly one done or
// error) plus a cleanup func the caller MUST call exactly once when
// finished -- mirrors DockerAgentHub.StreamLogs's contract exactly.
func (h *VMAgentHub) StreamLogs(vmResourceID uuid.UUID, since string) (<-chan VMAgentMessage, func(), error) {
	conn, err := h.get(vmResourceID)
	if err != nil {
		return nil, nil, err
	}
	id := uuid.NewString()
	stream := conn.registerStream(id)

	cleanup := func() {
		conn.forgetStream(id)
		_ = conn.send(VMAgentCommand{ID: id, Type: VMAgentCmdStopStream})
	}

	if err := conn.send(VMAgentCommand{ID: id, Type: VMAgentCmdStreamLogs, Since: since}); err != nil {
		conn.forgetStream(id)
		return nil, nil, fmt.Errorf("send command to agent: %w", err)
	}
	return stream, cleanup, nil
}
