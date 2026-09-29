// This file exercises Step 25's Kubernetes surface: cluster CRUD
// (Admin-only), kubeconfig credential configure/test-connection, the
// cross-cluster MonitoringOverview endpoint's Workspace-scoped
// filtering, and the pod-logs live-tail WebSocket's authorization --
// mirrors docker_access_test.go's coverage exactly, since K8s reuses the
// exact same docker_access_grants table/model (see
// services.DockerAccessService's doc comment) for its own
// k8s.monitor/k8s.logs permissions.
package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/services"
)

// createK8sClusterFixture creates a resource+k8s_clusters row directly
// (bypassing the HTTP Configure endpoint), mirroring createVM/createWorkspace's
// direct-store-write convention for pure test setup.
func (e *testEnv) createK8sClusterFixture(t *testing.T, workspaceID uuid.UUID, name string) (clusterID, resourceID uuid.UUID) {
	t.Helper()
	resource, err := e.store.CreateResource(context.Background(), generated.CreateResourceParams{
		WorkspaceID: workspaceID, Name: name, ResourceType: "K8S_CLUSTER",
	})
	if err != nil {
		t.Fatalf("create k8s cluster resource fixture: %v", err)
	}
	cluster, err := e.store.CreateK8sCluster(context.Background(), generated.CreateK8sClusterParams{ResourceID: resource.ID})
	if err != nil {
		t.Fatalf("create k8s cluster fixture: %v", err)
	}
	return cluster.ID, resource.ID
}

// regenerateK8sAgentToken is a thin wrapper around the real POST
// /api/k8s/clusters/:id/agent-token endpoint (as admin), used as test
// setup throughout this file -- exercises the actual HTTP/audit path
// rather than calling the service directly, mirroring
// docker_access_test.go's grantDockerAccess helper.
func (e *testEnv) regenerateK8sAgentToken(t *testing.T, adminClient *http.Client, clusterID uuid.UUID) string {
	t.Helper()
	resp, body := e.do(t, adminClient, http.MethodPost, "/api/k8s/clusters/"+clusterID.String()+"/agent-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("regenerate agent token = %d, want 200: %v", resp.StatusCode, body)
	}
	token, _ := body["agent_token"].(string)
	if token == "" {
		t.Fatal("expected a non-empty agent_token in the response")
	}
	return token
}

// createK8sPodFixture inserts a pod row for clusterID (a k8s_clusters.id)
// directly, bypassing discovery -- mirrors createDockerContainerFixture.
func (e *testEnv) createK8sPodFixture(t *testing.T, clusterID uuid.UUID, namespace, podName string) uuid.UUID {
	t.Helper()
	row, err := e.store.UpsertK8sPod(context.Background(), generated.UpsertK8sPodParams{
		K8sClusterID: clusterID, Namespace: namespace, PodName: podName, Phase: "RUNNING",
	})
	if err != nil {
		t.Fatalf("create k8s pod fixture: %v", err)
	}
	return row.ID
}

// fakeK8sAgentOptions configures startFakeK8sAgent's canned responses.
type fakeK8sAgentOptions struct {
	version         string
	pods            []services.AgentPodInfo
	nodes           []services.AgentNodeInfo
	resourceSummary *services.AgentClusterResourceSummary
	logLine         string
}

// startFakeK8sAgent connects to the test server's own
// GET /api/k8s/agent/connect endpoint as a real WebSocket client
// authenticating with token -- the true end-to-end counterpart to
// K8sAgentHub on the backend side, mirroring vm_console_test.go's fake
// SSH server rigor: a real WebSocket connection actually established,
// real JSON commands actually received and answered, not a mocked
// interface.
func startFakeK8sAgent(t *testing.T, baseURL, token string, opts fakeK8sAgentOptions) *websocket.Conn {
	t.Helper()
	url := wsURL(baseURL, "/api/k8s/agent/connect")
	conn, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer " + token}})
	if err != nil {
		t.Fatalf("fake agent dial failed (status %v): %v", statusOf(resp), err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		for {
			var cmd services.K8sAgentCommand
			if err := conn.ReadJSON(&cmd); err != nil {
				return
			}
			switch cmd.Type {
			case services.K8sAgentCmdServerVersion:
				data, _ := json.Marshal(services.AgentServerVersionResult{Version: opts.version})
				_ = conn.WriteJSON(services.K8sAgentMessage{ID: cmd.ID, Type: services.K8sAgentMsgResult, Data: data})
			case services.K8sAgentCmdListPods:
				data, _ := json.Marshal(opts.pods)
				_ = conn.WriteJSON(services.K8sAgentMessage{ID: cmd.ID, Type: services.K8sAgentMsgResult, Data: data})
			case services.K8sAgentCmdListNodes:
				data, _ := json.Marshal(opts.nodes)
				_ = conn.WriteJSON(services.K8sAgentMessage{ID: cmd.ID, Type: services.K8sAgentMsgResult, Data: data})
			case services.K8sAgentCmdClusterResourceSummary:
				summary := services.AgentClusterResourceSummary{}
				if opts.resourceSummary != nil {
					summary = *opts.resourceSummary
				}
				data, _ := json.Marshal(summary)
				_ = conn.WriteJSON(services.K8sAgentMessage{ID: cmd.ID, Type: services.K8sAgentMsgResult, Data: data})
			case services.K8sAgentCmdFetchLogsSince:
				line := time.Now().UTC().Format(time.RFC3339Nano) + " " + opts.logLine
				data, _ := json.Marshal(map[string]string{"output": line})
				_ = conn.WriteJSON(services.K8sAgentMessage{ID: cmd.ID, Type: services.K8sAgentMsgResult, Data: data})
			case services.K8sAgentCmdStreamLogs:
				_ = conn.WriteJSON(services.K8sAgentMessage{ID: cmd.ID, Type: services.K8sAgentMsgLogLine, Line: opts.logLine})
				_ = conn.WriteJSON(services.K8sAgentMessage{ID: cmd.ID, Type: services.K8sAgentMsgDone})
			case services.K8sAgentCmdStopStream:
				// no-op: nothing left running server-side to stop in this fake
			}
		}
	}()
	return conn
}

// waitForAgentConnected polls GET /api/k8s/clusters/:id until
// agent_connected is true -- the fake agent's WebSocket handshake
// completing is asynchronous from the test's own goroutine's perspective.
func (e *testEnv) waitForAgentConnected(t *testing.T, adminClient *http.Client, clusterID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resp, body := e.get(t, adminClient, "/api/k8s/clusters/"+clusterID)
		if resp.StatusCode == http.StatusOK && body["agent_connected"] == true {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake agent never showed as connected for cluster %s", clusterID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// === Cluster CRUD ===

func TestK8sCluster_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/k8s/clusters", map[string]string{
		"workspace_id": project.String(), "name": "member-attempt",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member create k8s cluster = %d, want 403", resp.StatusCode)
	}
}

func TestK8sCluster_UnknownWorkspace_NotFound(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/k8s/clusters", map[string]string{
		"workspace_id": uuid.NewString(), "name": "orphan-cluster",
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("create cluster for nonexistent workspace = %d, want 404", resp.StatusCode)
	}
}

func TestK8sCluster_CreateGetDelete_RoundTrip(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/k8s/clusters", map[string]string{
		"workspace_id": project.String(), "name": "roundtrip-cluster",
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create cluster = %d, want 201: %v", createResp.StatusCode, createBody)
	}
	clusterID, _ := createBody["id"].(string)
	if clusterID == "" {
		t.Fatal("expected a cluster id in the create response")
	}
	assertAuditEventExists(t, e, "K8S_CLUSTER", uuid.MustParse(createBody["resource_id"].(string)), services.AuditK8sClusterCreated)

	getResp, getBody := e.get(t, client, "/api/k8s/clusters/"+clusterID)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get cluster = %d, want 200", getResp.StatusCode)
	}
	if getBody["name"] != "roundtrip-cluster" {
		t.Errorf("expected name roundtrip-cluster, got %v", getBody["name"])
	}

	// Wrong confirmation name must be rejected, never silently ignored.
	wrongDelResp, _ := e.do(t, client, http.MethodDelete, "/api/k8s/clusters/"+clusterID, map[string]string{"confirmation_name": "not-the-right-name"})
	if wrongDelResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete with wrong confirmation name = %d, want 400", wrongDelResp.StatusCode)
	}

	delResp, _ := e.do(t, client, http.MethodDelete, "/api/k8s/clusters/"+clusterID, map[string]string{"confirmation_name": "roundtrip-cluster"})
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete cluster = %d, want 200", delResp.StatusCode)
	}
	assertAuditEventExists(t, e, "K8S_CLUSTER", uuid.MustParse(getBody["resource_id"].(string)), services.AuditK8sClusterDeleted)

	afterResp, _ := e.get(t, client, "/api/k8s/clusters/"+clusterID)
	if afterResp.StatusCode != http.StatusNotFound {
		t.Fatalf("get deleted cluster = %d, want 404", afterResp.StatusCode)
	}
}

// === Agent token + connection test ===

// TestK8sAgentConnect_InvalidToken_Unauthorized proves the agent
// WebSocket endpoint's own bearer-token authentication -- a token that
// was never issued (or was since superseded by a regenerate) must never
// be allowed to register as any cluster's agent.
func TestK8sAgentConnect_InvalidToken_Unauthorized(t *testing.T) {
	e := setup(t)
	url := wsURL(e.baseURL, "/api/k8s/agent/connect")
	_, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": {"Bearer not-a-real-token"}})
	if err == nil {
		t.Fatal("expected the handshake to fail for an invalid agent token")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid agent token connect status = %v, want 401", statusOf(resp))
	}
}

func TestK8sConnectionTest_NoAgentConnected_StructuredFailure(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "no-agent-cluster")
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// An operation endpoint: never a non-200 for "the operation itself
	// failed", only for a request-level problem (see K8sHandler.TestConnection's
	// doc comment).
	resp, body := e.do(t, client, http.MethodPost, "/api/k8s/clusters/"+clusterID.String()+"/connection-test", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connection-test (no agent) = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "failed" || body["error_code"] != "K8S_AGENT_OFFLINE" {
		t.Errorf("expected a structured K8S_AGENT_OFFLINE failure, got %v", body)
	}
}

func TestK8sAgentToken_ConnectAndTestConnection_Success(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "real-fake-cluster")
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	token := e.regenerateK8sAgentToken(t, client, clusterID)
	assertAuditEventExists(t, e, "K8S_CLUSTER", clusterID, services.AuditK8sCredentialReplaced)

	agentConn := startFakeK8sAgent(t, e.baseURL, token, fakeK8sAgentOptions{version: "v1.29.0"})
	e.waitForAgentConnected(t, client, clusterID.String(), 5*time.Second)

	testResp, testBody := e.do(t, client, http.MethodPost, "/api/k8s/clusters/"+clusterID.String()+"/connection-test", nil)
	if testResp.StatusCode != http.StatusOK {
		t.Fatalf("connection-test = %d, want 200", testResp.StatusCode)
	}
	if testBody["status"] != "connected" {
		t.Fatalf("expected a successful connection against the fake agent, got %v", testBody)
	}
	if testBody["kubernetes_version"] != "v1.29.0" {
		t.Errorf("expected the fake agent's reported version, got %v", testBody["kubernetes_version"])
	}

	// Disconnecting the agent must be reflected immediately -- no lingering
	// "connected" state once the underlying WebSocket is actually gone.
	_ = agentConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		getResp, getBody := e.get(t, client, "/api/k8s/clusters/"+clusterID.String())
		if getResp.StatusCode == http.StatusOK && getBody["agent_connected"] == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected agent_connected to become false after the agent disconnected")
		}
		time.Sleep(20 * time.Millisecond)
	}

	afterResp, afterBody := e.do(t, client, http.MethodPost, "/api/k8s/clusters/"+clusterID.String()+"/connection-test", nil)
	if afterResp.StatusCode != http.StatusOK || afterBody["error_code"] != "K8S_AGENT_OFFLINE" {
		t.Fatalf("connection-test after agent disconnect = %v, want a K8S_AGENT_OFFLINE failure", afterBody)
	}
}

// === Cluster-level node detail + resource summary ===

func TestK8sClusterNodes_NoAgentConnected_StructuredOffline(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "nodes-no-agent-cluster")
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/k8s/clusters/"+clusterID.String()+"/nodes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list nodes (no agent) = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "agent_offline" {
		t.Errorf("expected status agent_offline, got %v", body)
	}
	nodes, _ := body["nodes"].([]any)
	if len(nodes) != 0 {
		t.Errorf("expected an empty nodes list when no agent is connected, got %v", nodes)
	}
}

func TestK8sClusterNodes_ListNodes_ReturnsAgentNodeData(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "nodes-cluster")
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	token := e.regenerateK8sAgentToken(t, client, clusterID)
	cpuUsage := int64(500)
	memUsage := int64(1_000_000_000)
	startFakeK8sAgent(t, e.baseURL, token, fakeK8sAgentOptions{
		nodes: []services.AgentNodeInfo{{
			Name: "node-1", Ready: true, Roles: []string{"control-plane"},
			CPUCapacityMillicores: 2000, CPUAllocatableMillicores: 1900, CPUUsageMillicores: &cpuUsage,
			MemoryCapacityBytes: 4_000_000_000, MemoryAllocatableBytes: 3_800_000_000, MemoryUsageBytes: &memUsage,
			PodCount: 12, PodCapacity: 110,
		}},
	})
	e.waitForAgentConnected(t, client, clusterID.String(), 5*time.Second)

	resp, body := e.get(t, client, "/api/k8s/clusters/"+clusterID.String()+"/nodes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list nodes = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body)
	}
	nodes, _ := body["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("expected exactly 1 node, got %d (%v)", len(nodes), body)
	}
	node := nodes[0].(map[string]any)
	if node["name"] != "node-1" || node["ready"] != true || node["pod_count"] != float64(12) {
		t.Errorf("expected node-1's fields to round-trip, got %v", node)
	}
	cpuPct, _ := node["cpu_usage_percent"].(float64)
	if cpuPct <= 0 || cpuPct > 100 {
		t.Errorf("expected a derived cpu_usage_percent in (0, 100], got %v", node["cpu_usage_percent"])
	}
}

func TestK8sClusterResources_ResourceSummary_ReturnsAgentCounts(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "resources-cluster")
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	token := e.regenerateK8sAgentToken(t, client, clusterID)
	startFakeK8sAgent(t, e.baseURL, token, fakeK8sAgentOptions{
		resourceSummary: &services.AgentClusterResourceSummary{
			Namespaces: 5, Nodes: 3, Pods: 42, Deployments: 10, StatefulSets: 2, DaemonSets: 3, Services: 8, PersistentVolumeClaims: 4,
		},
	})
	e.waitForAgentConnected(t, client, clusterID.String(), 5*time.Second)

	resp, body := e.get(t, client, "/api/k8s/clusters/"+clusterID.String()+"/resources")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resource summary = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body)
	}
	if body["namespaces"] != float64(5) || body["pods"] != float64(42) || body["deployments"] != float64(10) {
		t.Errorf("expected the fake agent's counts to round-trip, got %v", body)
	}
}

// === Monitoring overview scoping ===

func TestK8sOverview_AdminSeesAllWithoutAnyGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "admin-visible-cluster")
	e.createK8sPodFixture(t, clusterID, "default", "web-1")
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/k8s/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin overview = %d, want 200", resp.StatusCode)
	}
	pods, _ := body["pods"].([]any)
	if len(pods) == 0 {
		t.Error("admin should see pods with no grant needed")
	}
}

func TestK8sOverview_MemberSeesNothingWithoutGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "ungranted-cluster")
	e.createK8sPodFixture(t, clusterID, "default", "web-1")
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/k8s/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	pods, _ := body["pods"].([]any)
	if len(pods) != 0 {
		t.Errorf("member with no grant should see 0 pods, got %d", len(pods))
	}
}

func TestK8sOverview_MemberSeesViaProjectGrant(t *testing.T) {
	e := setup(t)
	projectA := e.createWorkspace(t)
	projectB := e.createWorkspace(t)
	clusterA, _ := e.createK8sClusterFixture(t, projectA, "cluster-a")
	clusterB, _ := e.createK8sClusterFixture(t, projectB, "cluster-b")
	podA := e.createK8sPodFixture(t, clusterA, "default", "a-web")
	e.createK8sPodFixture(t, clusterB, "default", "b-web")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, projectA, services.PermK8sMonitor)
	// A Member is never shown the real pod_name (see the redaction rule in
	// k8s_overview.go) -- naming it is what makes it possible to confirm
	// from the Member's own response that this is project A's app.
	e.setK8sPodDisplayName(t, adminClient, podA, "app-a")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/k8s/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	pods, _ := body["pods"].([]any)
	if len(pods) != 1 {
		t.Fatalf("expected exactly 1 pod (project A only), got %d", len(pods))
	}
	if pods[0].(map[string]any)["display_name"] != "app-a" {
		t.Errorf("expected project A's app, got %v", pods[0])
	}
}

// The optional cluster_resource_id filter narrows the overview to one
// cluster's pods -- used by a Dashboard's Monitoring/Logs tabs (see
// handlers/dashboards.go) so a Member with access to several clusters in a
// Project only ever sees the one this Dashboard is bound to, even though
// cluster_resource_id itself is redacted from their normal (unfiltered)
// response. Mirrors TestDockerOverview_VMResourceIDFilterNarrowsToOneVM.
func TestK8sOverview_ClusterResourceIDFilterNarrowsToOneCluster(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	cluster1, cluster1Resource := e.createK8sClusterFixture(t, project, "cluster-1")
	cluster2, _ := e.createK8sClusterFixture(t, project, "cluster-2")
	e.createK8sPodFixture(t, cluster1, "default", "web-1")
	e.createK8sPodFixture(t, cluster2, "default", "web-2")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermK8sMonitor)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	unfilteredResp, unfilteredBody := e.get(t, memberClient, "/api/k8s/overview")
	if unfilteredResp.StatusCode != http.StatusOK {
		t.Fatalf("member overview (unfiltered) = %d, want 200", unfilteredResp.StatusCode)
	}
	if pods, _ := unfilteredBody["pods"].([]any); len(pods) != 2 {
		t.Fatalf("expected 2 visible pods unfiltered, got %d", len(pods))
	}

	filteredResp, filteredBody := e.get(t, memberClient, "/api/k8s/overview?cluster_resource_id="+cluster1Resource.String())
	if filteredResp.StatusCode != http.StatusOK {
		t.Fatalf("member overview (filtered) = %d, want 200", filteredResp.StatusCode)
	}
	if pods, _ := filteredBody["pods"].([]any); len(pods) != 1 {
		t.Fatalf("expected exactly 1 pod filtered to cluster1, got %d", len(pods))
	}

	// A cluster the Member was never granted access to must return empty.
	otherProject := e.createWorkspace(t)
	otherCluster, otherClusterResource := e.createK8sClusterFixture(t, otherProject, "other-cluster")
	e.createK8sPodFixture(t, otherCluster, "default", "other")
	deniedResp, deniedBody := e.get(t, memberClient, "/api/k8s/overview?cluster_resource_id="+otherClusterResource.String())
	if deniedResp.StatusCode != http.StatusOK {
		t.Fatalf("member overview (filtered, unauthorized cluster) = %d, want 200", deniedResp.StatusCode)
	}
	if pods, _ := deniedBody["pods"].([]any); len(pods) != 0 {
		t.Errorf("expected 0 pods for an unauthorized cluster_resource_id filter, got %d", len(pods))
	}
}

func TestK8sOverview_MemberSeesViaGroupGrant(t *testing.T) {
	e := setup(t)
	groupA := e.createWorkspace(t)
	groupB := e.createWorkspace(t)
	clusterA, _ := e.createK8sClusterFixture(t, groupA, "cluster-a")
	clusterB, _ := e.createK8sClusterFixture(t, groupB, "cluster-b")
	podA := e.createK8sPodFixture(t, clusterA, "default", "a-web")
	e.createK8sPodFixture(t, clusterB, "default", "b-web")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, groupA, services.PermK8sMonitor)
	e.setK8sPodDisplayName(t, adminClient, podA, "app-a")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/k8s/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	pods, _ := body["pods"].([]any)
	if len(pods) != 1 || pods[0].(map[string]any)["display_name"] != "app-a" {
		t.Fatalf("expected exactly group A's app, got %v", pods)
	}
}

// TestK8sOverview_GroupGrant_ExtendsToNewClusterAutomatically proves the
// grant is dynamic, not a point-in-time snapshot: a cluster added to an
// already-granted group becomes visible with no separate re-grant --
// mirrors TestDockerOverview_GroupGrant_ExtendsToNewVMAutomatically.
func TestK8sOverview_GroupGrant_ExtendsToNewClusterAutomatically(t *testing.T) {
	e := setup(t)
	group := e.createWorkspace(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, group, services.PermK8sMonitor)

	// The cluster (and its pod) is created AFTER the grant.
	lateCluster, _ := e.createK8sClusterFixture(t, group, "late-cluster")
	latePod := e.createK8sPodFixture(t, lateCluster, "default", "late-web")
	e.setK8sPodDisplayName(t, adminClient, latePod, "late-app")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/k8s/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	pods, _ := body["pods"].([]any)
	if len(pods) != 1 || pods[0].(map[string]any)["display_name"] != "late-app" {
		t.Fatalf("expected the late-added cluster's app to already be visible, got %v", pods)
	}
}

// === Logs stream authorization ===

func TestK8sLogsStream_Unauthenticated_PreUpgrade401(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "auth-test-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	client := newClient()

	url := wsURL(e.baseURL, "/api/k8s/pods/"+podID.String()+"/logs/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail for an unauthenticated caller")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated logs stream status = %v, want 401", statusOf(resp))
	}
}

func TestK8sLogsStream_UnauthorizedMember_PreUpgrade404(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "auth-test-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/k8s/pods/"+podID.String()+"/logs/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail for an unauthorized member")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member logs stream status = %v, want 404", statusOf(resp))
	}
}

// TestK8sLogsStream_MonitorGrantAlone_DoesNotGrantLogs proves the
// deliberate separation: k8s.monitor and k8s.logs are independent
// permissions, exactly like docker.monitor/docker.logs.
func TestK8sLogsStream_MonitorGrantAlone_DoesNotGrantLogs(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "monitor-only-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermK8sMonitor) // NOT k8s.logs

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	url := wsURL(e.baseURL, "/api/k8s/pods/"+podID.String()+"/logs/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail: k8s.monitor must not imply k8s.logs")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("k8s.monitor-only member logs stream status = %v, want 404", statusOf(resp))
	}
}

func TestK8sLogsStream_AuthorizedMember_ForeignOrigin_Forbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "foreign-origin-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermK8sLogs)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	url := wsURL(e.baseURL, "/api/k8s/pods/"+podID.String()+"/logs/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {"http://evil.example.com"}})
	if err == nil {
		t.Fatal("expected handshake to be rejected for a foreign Origin")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign-origin logs stream status = %v, want 403", statusOf(resp))
	}
}

// TestK8sLogsStream_FullSession_RealAPIAndAudit is the end-to-end proof: a
// real (fake) Kubernetes API server, a real GetLogs(...).Stream(ctx) call
// actually executed and its output actually relayed line-by-line, and both
// audit events recorded -- mirrors TestDockerLogsStream_FullSession_RealSSHAndAudit.
func TestK8sLogsStream_FullSession_RealAPIAndAudit(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, resourceID := e.createK8sClusterFixture(t, project, "full-session-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	token := e.regenerateK8sAgentToken(t, adminClient, clusterID)
	startFakeK8sAgent(t, e.baseURL, token, fakeK8sAgentOptions{logLine: "hello from pod"})
	e.waitForAgentConnected(t, adminClient, clusterID.String(), 5*time.Second)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermK8sLogs)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	url := wsURL(e.baseURL, "/api/k8s/pods/"+podID.String()+"/logs/stream")
	conn, resp, err := dialerFor(memberClient).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err != nil {
		t.Fatalf("logs stream handshake failed (status %v): %v", statusOf(resp), err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	found := false
	for i := 0; i < 20 && !found; i++ {
		var frame map[string]any
		if err := conn.ReadJSON(&frame); err != nil {
			t.Fatalf("read log frame: %v", err)
		}
		if frame["type"] == "log" && frame["line"] == "hello from pod" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a log line 'hello from pod' from the fake pod logs endpoint, never received one")
	}
	_ = conn.SetReadDeadline(time.Time{})

	assertAuditEventExists(t, e, "K8S_CLUSTER", resourceID, services.AuditK8sLogsOpened)
	conn.Close()
	if !waitForAuditEvent(t, e, resourceID, services.AuditK8sLogsClosed, 5*time.Second) {
		t.Error("expected a K8S_LOGS_CLOSED audit event after disconnect, never observed one")
	}
}

// === Access grant reuse: correct audit-action routing ===

// TestK8sAccessGrant_AuditedUnderK8sActions_NotDocker proves the shared
// docker_access_grants endpoint (POST/DELETE /api/docker/access-grants)
// still records the correct feature-specific audit action for a k8s.*
// permission, despite going through the same handler/service as Docker
// grants (see docker_access.go handler's accessGrantedAction/
// accessRevokedAction).
func TestK8sAccessGrant_AuditedUnderK8sActions_NotDocker(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, _, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	e.grantDockerAccess(t, client, memberID, project, services.PermK8sMonitor)
	assertAuditEventExists(t, e, "USER", memberID, services.AuditK8sAccessGranted)

	listResp, listBody := e.get(t, client, "/api/docker/access-grants")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list grants = %d, want 200", listResp.StatusCode)
	}
	grants, _ := listBody["grants"].([]any)
	var grantID string
	for _, g := range grants {
		grant := g.(map[string]any)
		if grant["user_id"] == memberID.String() && grant["permission"] == services.PermK8sMonitor {
			grantID = grant["id"].(string)
		}
	}
	if grantID == "" {
		t.Fatal("could not find the k8s.monitor grant just created")
	}

	revokeResp, _ := e.do(t, client, http.MethodDelete, "/api/docker/access-grants/"+grantID, nil)
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d, want 200", revokeResp.StatusCode)
	}
	assertAuditEventExists(t, e, "USER", memberID, services.AuditK8sAccessRevoked)
}
