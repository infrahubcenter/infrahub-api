// This file unit-tests VMAgentHub's two real design decisions in
// isolation (no DB, no real WebSocket needed -- metrics_push routing
// never touches the connection's own ws field): that a decoded
// metrics_push is routed to onPush rather than the waiter/stream lookup,
// and that the bounded push-worker pool's non-blocking, drop-on-full
// enqueue genuinely never blocks the caller (the connection's own read
// loop, in production) no matter how backed up the workers are. The full
// end-to-end path (a real fake agent pushing over a real WebSocket, the
// sample landing in vm_agent_metric_snapshots) is covered by
// server_test's TestVMAgentToken_ConnectAndPushMetrics_Success.
package services

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestVMAgentHub_MetricsPush_RoutedToOnPush_NeverToWaiters(t *testing.T) {
	var received atomic.Bool
	var gotVMID uuid.UUID
	var gotCPU *float64
	done := make(chan struct{})
	var closeOnce sync.Once

	hub := NewVMAgentHub(nil, func(_ context.Context, vmResourceID uuid.UUID, data VMAgentMetricsPushData) error {
		received.Store(true)
		gotVMID = vmResourceID
		gotCPU = data.CPUPercent
		closeOnce.Do(func() { close(done) })
		return nil
	})

	conn := newVMAgentConnection(nil)
	vmID := uuid.New()
	// A push carries an empty ID by protocol (vm_agent_protocol.go) --
	// exercised here exactly as an agent would send it, to prove dispatch
	// routes on Type, not on ID happening to miss the waiter/stream maps.
	data, _ := json.Marshal(VMAgentMetricsPushData{CPUPercent: floatPtr(42.5)})
	conn.dispatch(vmID, VMAgentMessage{ID: "", Type: VMAgentMsgMetricsPush, Data: data}, hub)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onPush was never called for a metrics_push message")
	}

	if !received.Load() {
		t.Fatal("onPush was not invoked")
	}
	if gotVMID != vmID {
		t.Errorf("onPush vmResourceID = %v, want %v", gotVMID, vmID)
	}
	if gotCPU == nil || *gotCPU != 42.5 {
		t.Errorf("onPush data.CPUPercent = %v, want 42.5", gotCPU)
	}

	// A push must never be treated as a reply to some in-flight command --
	// registering a waiter for the same (empty) ID and then dispatching
	// another push must leave that waiter untouched.
	waiter := conn.registerWaiter("")
	defer conn.forgetWaiter("")
	conn.dispatch(vmID, VMAgentMessage{ID: "", Type: VMAgentMsgMetricsPush, Data: data}, hub)
	select {
	case <-waiter:
		t.Fatal("a metrics_push was incorrectly delivered to a registered waiter")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestVMAgentHub_MalformedPushPayload_DroppedNotCrashed(t *testing.T) {
	called := make(chan struct{}, 1)
	hub := NewVMAgentHub(nil, func(_ context.Context, _ uuid.UUID, _ VMAgentMetricsPushData) error {
		called <- struct{}{}
		return nil
	})
	conn := newVMAgentConnection(nil)

	// Malformed JSON must be dropped during decode, before ever reaching
	// the worker pool -- this must not panic.
	conn.dispatch(uuid.New(), VMAgentMessage{Type: VMAgentMsgMetricsPush, Data: []byte(`not json`)}, hub)

	select {
	case <-called:
		t.Fatal("onPush must not be called for an undecodable payload")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestVMAgentHub_PushQueueFull_NeverBlocksEnqueue is the core proof of
// this feature's one real backend-side design decision (see
// vm_agent_hub.go's doc comment): enqueuePush must be non-blocking even
// when every worker is stuck and the queue is completely full. If this
// were a blocking (or unbounded) design, a slow onPush (a stalled DB
// write, in production) would eventually stall the connection's own read
// loop -- which also handles ping/pong liveness and any concurrent log
// stream for the same VM -- turning one slow metrics write into a
// connection-wide outage.
func TestVMAgentHub_PushQueueFull_NeverBlocksEnqueue(t *testing.T) {
	blockForever := make(chan struct{}) // deliberately never closed
	hub := NewVMAgentHub(nil, func(_ context.Context, _ uuid.UUID, _ VMAgentMetricsPushData) error {
		<-blockForever // every one of the vmAgentPushWorkers workers parks here immediately
		return nil
	})

	conn := newVMAgentConnection(nil)
	vmID := uuid.New()
	data, _ := json.Marshal(VMAgentMetricsPushData{})
	msg := VMAgentMessage{Type: VMAgentMsgMetricsPush, Data: data}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Enough sends to occupy every worker AND fill vmAgentPushQueueSize
		// AND then some more on top -- if enqueue ever blocked on a full
		// queue instead of dropping, this loop would hang forever and the
		// select below would time out.
		for i := 0; i < vmAgentPushWorkers+vmAgentPushQueueSize+100; i++ {
			conn.dispatch(vmID, msg, hub)
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("enqueueing metrics_push messages past the bounded queue blocked -- drop-on-full must never stall the caller")
	}
}

func floatPtr(v float64) *float64 { return &v }
