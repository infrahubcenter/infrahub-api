// This file exercises the per-VM Docker agent's transport layer (Docker+
// Kubernetes monitoring rework, Phase 1): the agent WebSocket endpoint's
// bearer-token authentication, the hub's connect/disconnect bookkeeping,
// and the command round trip through DockerAgentService -- mirrors
// k8s_test.go's fake-agent coverage exactly, since docker_agent_hub.go is
// a structural mirror of k8s_agent_hub.go. Install itself (the SSH-based
// installer) is not covered here -- it requires a real SSH-reachable VM
// and is exercised manually, not in this integration suite.
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

// fakeDockerAgentOptions configures startFakeDockerAgent's canned
// responses.
type fakeDockerAgentOptions struct {
	engineVersion string
	apiVersion    string
	containers    []services.AgentContainerInfo
	stats         []services.AgentContainerStats
	logLine       string
}

// startFakeDockerAgent connects to the test server's own
// GET /api/docker-agent/connect endpoint as a real WebSocket client
// authenticating with token -- the true end-to-end counterpart to
// DockerAgentHub on the backend side, mirroring startFakeK8sAgent.
func startFakeDockerAgent(t *testing.T, baseURL, token string, opts fakeDockerAgentOptions) *websocket.Conn {
	t.Helper()
	url := wsURL(baseURL, "/api/docker-agent/connect")
	conn, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer " + token}})
	if err != nil {
		t.Fatalf("fake agent dial failed (status %v): %v", statusOf(resp), err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		for {
			var cmd services.DockerAgentCommand
			if err := conn.ReadJSON(&cmd); err != nil {
				return
			}
			switch cmd.Type {
			case services.DockerAgentCmdEngineVersion:
				data, _ := json.Marshal(services.AgentEngineVersionResult{Version: opts.engineVersion, APIVersion: opts.apiVersion})
				_ = conn.WriteJSON(services.DockerAgentMessage{ID: cmd.ID, Type: services.DockerAgentMsgResult, Data: data})
			case services.DockerAgentCmdListContainers:
				data, _ := json.Marshal(opts.containers)
				_ = conn.WriteJSON(services.DockerAgentMessage{ID: cmd.ID, Type: services.DockerAgentMsgResult, Data: data})
			case services.DockerAgentCmdContainerStats:
				data, _ := json.Marshal(opts.stats)
				_ = conn.WriteJSON(services.DockerAgentMessage{ID: cmd.ID, Type: services.DockerAgentMsgResult, Data: data})
			case services.DockerAgentCmdFetchLogsSince:
				line := time.Now().UTC().Format(time.RFC3339Nano) + " " + opts.logLine
				data, _ := json.Marshal(map[string]string{"output": line})
				_ = conn.WriteJSON(services.DockerAgentMessage{ID: cmd.ID, Type: services.DockerAgentMsgResult, Data: data})
			case services.DockerAgentCmdStreamLogs:
				_ = conn.WriteJSON(services.DockerAgentMessage{ID: cmd.ID, Type: services.DockerAgentMsgLogLine, Line: opts.logLine})
				_ = conn.WriteJSON(services.DockerAgentMessage{ID: cmd.ID, Type: services.DockerAgentMsgDone})
			case services.DockerAgentCmdStopStream:
				// no-op: nothing left running server-side to stop in this fake
			}
		}
	}()
	return conn
}

// waitForDockerAgentConnected polls GET /api/vms/:id/docker-agent/status
// until connected is true -- the fake agent's WebSocket handshake
// completing is asynchronous from the test's own goroutine's perspective.
func (e *testEnv) waitForDockerAgentConnected(t *testing.T, adminClient *http.Client, vmResourceID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resp, body := e.get(t, adminClient, "/api/vms/"+vmResourceID+"/docker-agent/status")
		if resp.StatusCode == http.StatusOK && body["connected"] == true {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake docker agent never showed as connected for vm %s", vmResourceID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDockerAgentConnect_InvalidToken_Unauthorized proves the agent
// WebSocket endpoint's own bearer-token authentication -- a token that
// was never issued must never be allowed to register as any VM's agent.
func TestDockerAgentConnect_InvalidToken_Unauthorized(t *testing.T) {
	e := setup(t)
	url := wsURL(e.baseURL, "/api/docker-agent/connect")
	_, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer not-a-real-token"}})
	if err == nil {
		t.Fatal("expected the handshake to fail for an invalid agent token")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid agent token connect status = %v, want 401", statusOf(resp))
	}
}

func TestDockerAgentConnectionTest_NoAgentConnected_StructuredFailure(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vmResourceID.String()+"/docker-agent/connection-test", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connection-test (no agent) = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "failed" || body["error_code"] != "DOCKER_AGENT_OFFLINE" {
		t.Errorf("expected a structured DOCKER_AGENT_OFFLINE failure, got %v", body)
	}
}

func TestDockerAgentToken_ConnectAndTestConnection_Success(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// No standalone "issue token" HTTP endpoint exists for the Docker
	// agent (unlike K8s's POST .../agent-token) -- by design, the only
	// production path that issues one is the automated SSH installer
	// (services.DockerAgentInstallService.Install), which this fake-agent
	// test deliberately doesn't run. Generating one directly here mirrors
	// createVM/createProject's direct-store-write convention for pure test
	// setup.
	token, err := e.dockerAgentTokens.GenerateToken(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("generate docker agent token fixture: %v", err)
	}

	agentConn := startFakeDockerAgent(t, e.baseURL, token, fakeDockerAgentOptions{engineVersion: "27.5.1", apiVersion: "1.47"})
	e.waitForDockerAgentConnected(t, client, vmResourceID.String(), 5*time.Second)

	testResp, testBody := e.do(t, client, http.MethodPost, "/api/vms/"+vmResourceID.String()+"/docker-agent/connection-test", nil)
	if testResp.StatusCode != http.StatusOK {
		t.Fatalf("connection-test = %d, want 200", testResp.StatusCode)
	}
	if testBody["status"] != "connected" {
		t.Fatalf("expected a successful connection against the fake agent, got %v", testBody)
	}
	if testBody["engine_version"] != "27.5.1" {
		t.Errorf("expected the fake agent's reported engine version, got %v", testBody["engine_version"])
	}

	statusResp, statusBody := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/docker-agent/status")
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", statusResp.StatusCode)
	}
	if statusBody["connected"] != true || statusBody["token_configured"] != true {
		t.Errorf("expected connected=true, token_configured=true, got %v", statusBody)
	}

	// Disconnecting the agent must be reflected immediately -- no
	// lingering "connected" state once the underlying WebSocket is
	// actually gone.
	_ = agentConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		getResp, getBody := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/docker-agent/status")
		if getResp.StatusCode == http.StatusOK && getBody["connected"] == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected connected to become false after the agent disconnected")
		}
		time.Sleep(20 * time.Millisecond)
	}

	afterResp, afterBody := e.do(t, client, http.MethodPost, "/api/vms/"+vmResourceID.String()+"/docker-agent/connection-test", nil)
	if afterResp.StatusCode != http.StatusOK || afterBody["error_code"] != "DOCKER_AGENT_OFFLINE" {
		t.Fatalf("connection-test after agent disconnect = %v, want a DOCKER_AGENT_OFFLINE failure", afterBody)
	}
}

func TestDockerAgentStatus_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/docker-agent/status")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member get docker agent status = %d, want 403", resp.StatusCode)
	}
}

func TestDockerAgentListContainersAndStats_ReturnsAgentData(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	token, err := e.dockerAgentTokens.GenerateToken(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("generate docker agent token fixture: %v", err)
	}
	startFakeDockerAgent(t, e.baseURL, token, fakeDockerAgentOptions{
		engineVersion: "27.5.1",
		containers:    []services.AgentContainerInfo{{ContainerID: "abc123", Name: "web", Image: "nginx:latest", Status: "Up 2 hours", State: "RUNNING"}},
		stats:         []services.AgentContainerStats{{ContainerID: "abc123", CPUPercent: 1.5, MemoryUsageBytes: 1024, HasMemoryLimit: false}},
	})
	e.waitForDockerAgentConnected(t, client, vmResourceID.String(), 5*time.Second)

	containers, err := e.dockerAgent.ListContainers(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) != 1 || containers[0].Name != "web" {
		t.Errorf("expected the fake agent's container list to round-trip, got %v", containers)
	}

	stats, err := e.dockerAgent.ContainerStats(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("ContainerStats: %v", err)
	}
	if len(stats) != 1 || stats[0].CPUPercent != 1.5 {
		t.Errorf("expected the fake agent's stats to round-trip, got %v", stats)
	}
}
