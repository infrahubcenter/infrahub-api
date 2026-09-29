// This file exercises the push-based VM Agent's transport layer end to
// end: the agent WebSocket endpoint's bearer-token authentication, the
// hub's connect/disconnect bookkeeping, a real metrics_push landing in
// vm_agent_metric_snapshots (proving the whole push pipeline -- hub
// worker pool, VMAgentService.HandleMetricsPush, the DB insert -- works
// against a real database, not just VMAgentHub in isolation), and the
// logs command round trip. Mirrors docker_agent_test.go's fake-agent
// coverage exactly. Install itself (the SSH-based installer) is not
// covered here -- it requires a real SSH-reachable VM, same as the Docker
// agent's own install tests.
package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/services"
)

// fakeVMAgentOptions configures startFakeVMAgent's canned responses.
type fakeVMAgentOptions struct {
	logLine string
}

// startFakeVMAgent connects to the test server's own GET /api/vm-agent/connect
// endpoint as a real WebSocket client authenticating with token -- the
// true end-to-end counterpart to VMAgentHub on the backend side, mirroring
// startFakeDockerAgent.
func startFakeVMAgent(t *testing.T, baseURL, token string, opts fakeVMAgentOptions) *websocket.Conn {
	t.Helper()
	url := wsURL(baseURL, "/api/vm-agent/connect")
	conn, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer " + token}})
	if err != nil {
		t.Fatalf("fake agent dial failed (status %v): %v", statusOf(resp), err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		for {
			var cmd services.VMAgentCommand
			if err := conn.ReadJSON(&cmd); err != nil {
				return
			}
			switch cmd.Type {
			case services.VMAgentCmdFetchLogsSince:
				line := time.Now().UTC().Format(time.RFC3339Nano) + " " + opts.logLine
				data, _ := json.Marshal(map[string]string{"output": line})
				_ = conn.WriteJSON(services.VMAgentMessage{ID: cmd.ID, Type: services.VMAgentMsgResult, Data: data})
			case services.VMAgentCmdStreamLogs:
				_ = conn.WriteJSON(services.VMAgentMessage{ID: cmd.ID, Type: services.VMAgentMsgLogLine, Line: opts.logLine})
				_ = conn.WriteJSON(services.VMAgentMessage{ID: cmd.ID, Type: services.VMAgentMsgDone})
			case services.VMAgentCmdStopStream:
				// no-op: nothing left running server-side to stop in this fake
			}
		}
	}()
	return conn
}

// pushMetrics sends one unsolicited metrics_push message -- always an
// empty ID, exactly like the real agent (vm-agent/metrics.go).
func pushMetrics(t *testing.T, conn *websocket.Conn, data services.VMAgentMetricsPushData) {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal push data: %v", err)
	}
	if err := conn.WriteJSON(services.VMAgentMessage{Type: services.VMAgentMsgMetricsPush, Data: raw}); err != nil {
		t.Fatalf("write metrics_push: %v", err)
	}
}

func (e *testEnv) waitForVMAgentConnected(t *testing.T, adminClient *http.Client, vmResourceID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resp, body := e.get(t, adminClient, "/api/vms/"+vmResourceID+"/vm-agent/status")
		if resp.StatusCode == http.StatusOK && body["connected"] == true {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake vm agent never showed as connected for vm %s", vmResourceID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestVMAgentConnect_InvalidToken_Unauthorized(t *testing.T) {
	e := setup(t)
	url := wsURL(e.baseURL, "/api/vm-agent/connect")
	_, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer not-a-real-token"}})
	if err == nil {
		t.Fatal("expected the handshake to fail for an invalid agent token")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid agent token connect status = %v, want 401", statusOf(resp))
	}
}

func TestVMAgentStatus_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/vm-agent/status")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member get vm agent status = %d, want 403", resp.StatusCode)
	}
}

func TestVMAgentMetrics_CurrentAndHistory_NotFoundBeforeAnyPush(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/vm-agent/metrics/current")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("metrics/current before any push = %d, want 404 (never fabricated data)", resp.StatusCode)
	}

	histResp, histBody := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/vm-agent/metrics/history")
	if histResp.StatusCode != http.StatusOK {
		t.Fatalf("metrics/history before any push = %d, want 200", histResp.StatusCode)
	}
	metrics, _ := histBody["metrics"].([]any)
	if len(metrics) != 0 {
		t.Errorf("expected an empty history before any push, got %d entries", len(metrics))
	}
}

// TestVMAgentToken_ConnectAndPushMetrics_Success is the full-pipeline
// proof: a real fake agent connects over a real WebSocket, pushes one
// unsolicited metrics_push, and that sample lands in
// vm_agent_metric_snapshots and is readable via the real HTTP API --
// exercising VMAgentHub's push-worker pool and VMAgentService.
// HandleMetricsPush against the real database, not just the unit-level
// proof in services.TestVMAgentHub_*.
func TestVMAgentToken_ConnectAndPushMetrics_Success(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// No standalone "issue token" HTTP endpoint exists for the VM agent
	// (mirrors the Docker agent's own token fixture pattern exactly) --
	// the only production path that issues one is the SSH installer.
	token, err := e.vmAgentTokens.GenerateToken(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("generate vm agent token fixture: %v", err)
	}

	agentConn := startFakeVMAgent(t, e.baseURL, token, fakeVMAgentOptions{logLine: "hello from vm"})
	e.waitForVMAgentConnected(t, client, vmResourceID.String(), 5*time.Second)

	cpu := 37.25
	cores := int32(4)
	memUsed := int64(1024 * 1024 * 512)
	pushMetrics(t, agentConn, services.VMAgentMetricsPushData{CPUPercent: &cpu, CPUCores: &cores, MemoryUsedBytes: &memUsed})

	// The push is processed asynchronously by a hub worker -- poll for it
	// to land rather than assuming it's instantaneous.
	deadline := time.Now().Add(5 * time.Second)
	var currentBody map[string]any
	for {
		resp, body := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/vm-agent/metrics/current")
		if resp.StatusCode == http.StatusOK {
			currentBody = body
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pushed metrics never became visible via metrics/current (last status %d)", resp.StatusCode)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if currentBody["cpu_percent"] != 37.25 {
		t.Errorf("cpu_percent = %v, want 37.25", currentBody["cpu_percent"])
	}
	if currentBody["cpu_cores"] != float64(4) {
		t.Errorf("cpu_cores = %v, want 4", currentBody["cpu_cores"])
	}
	if currentBody["memory_used_bytes"] != float64(1024*1024*512) {
		t.Errorf("memory_used_bytes = %v, want %d", currentBody["memory_used_bytes"], 1024*1024*512)
	}

	histResp, histBody := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/vm-agent/metrics/history")
	if histResp.StatusCode != http.StatusOK {
		t.Fatalf("metrics/history = %d, want 200", histResp.StatusCode)
	}
	metrics, _ := histBody["metrics"].([]any)
	if len(metrics) != 1 {
		t.Fatalf("history entries = %d, want 1", len(metrics))
	}

	// The heartbeat must also reflect the push, not just the initial
	// connect (VMAgentTokenService.MarkConnected deliberately does NOT
	// update it -- see that method's doc comment).
	statusResp, statusBody := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/vm-agent/status")
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", statusResp.StatusCode)
	}
	if statusBody["last_heartbeat_at"] == nil {
		t.Error("expected a non-nil last_heartbeat_at after a metrics_push")
	}

	// Disconnecting the agent must be reflected immediately.
	_ = agentConn.Close()
	deadline = time.Now().Add(5 * time.Second)
	for {
		getResp, getBody := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/vm-agent/status")
		if getResp.StatusCode == http.StatusOK && getBody["connected"] == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected connected to become false after the agent disconnected")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestVMAgentLogs_RecentAndStream_ReturnsAgentData(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	token, err := e.vmAgentTokens.GenerateToken(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("generate vm agent token fixture: %v", err)
	}
	startFakeVMAgent(t, e.baseURL, token, fakeVMAgentOptions{logLine: "systemd[1]: Started a unit."})
	e.waitForVMAgentConnected(t, client, vmResourceID.String(), 5*time.Second)

	recentResp, recentBody := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/vm-agent/logs/recent")
	if recentResp.StatusCode != http.StatusOK {
		t.Fatalf("logs/recent = %d, want 200", recentResp.StatusCode)
	}
	if recentBody["agent_connected"] != true {
		t.Errorf("agent_connected = %v, want true", recentBody["agent_connected"])
	}
	lines, _ := recentBody["lines"].([]any)
	if len(lines) != 1 {
		t.Fatalf("logs/recent lines = %d, want 1", len(lines))
	}

	url := wsURL(e.baseURL, "/api/vms/"+vmResourceID.String()+"/vm-agent/logs/stream")
	conn, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err != nil {
		t.Fatalf("logs stream handshake failed (status %v): %v", statusOf(resp), err)
	}
	defer conn.Close()

	sawLog, sawClosed := false, false
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 5 && !sawClosed; i++ {
		var frame map[string]any
		if err := conn.ReadJSON(&frame); err != nil {
			t.Fatalf("read stream frame: %v", err)
		}
		switch frame["type"] {
		case "log":
			sawLog = true
		case "closed":
			sawClosed = true
		}
	}
	if !sawLog || !sawClosed {
		t.Errorf("expected a log frame followed by a closed frame, sawLog=%v sawClosed=%v", sawLog, sawClosed)
	}
}
