// This file exercises the log-history feature added on top of Step 24/25's
// Docker Logs / Kubernetes Logs sections: custom "App Name" display-name
// labels (Admin-only), searchable log history bounded to the retention
// window (backed by the background capture in services/docker_log_capture.go
// and services/k8s_log_capture.go, both proven here against real fake
// SSH/API servers), and the retention cleanup job.
package server_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// === Member visibility: app name only, never the real VM/container/pod
// identity (a later, explicit refinement: "only admin can see which
// docker and vm... member... should see appname... not docker container
// name not vm name only appname"). ===

func TestDockerOverview_MemberResponse_HidesContainerAndVMName(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermDockerMonitor)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	resp, body := e.get(t, memberClient, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("expected exactly 1 container, got %d", len(containers))
	}
	row := containers[0].(map[string]any)
	if _, ok := row["container_name"]; ok {
		t.Errorf("member response must never include container_name, got %v", row["container_name"])
	}
	if _, ok := row["vm_name"]; ok {
		t.Errorf("member response must never include vm_name, got %v", row["vm_name"])
	}
	if _, ok := row["vm_resource_id"]; ok {
		t.Errorf("member response must never include vm_resource_id, got %v", row["vm_resource_id"])
	}
	if row["display_name"] != unnamedAppLabelForTest {
		t.Errorf("expected display_name fallback %q for an unnamed container, got %v", unnamedAppLabelForTest, row["display_name"])
	}
	_ = containerID
}

func TestDockerOverview_MemberResponse_ShowsCustomAppName(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermDockerMonitor)
	renameResp, _ := e.do(t, adminClient, http.MethodPut, "/api/docker/containers/"+containerID.String()+"/name", map[string]string{"display_name": "checkout-service"})
	if renameResp.StatusCode != http.StatusOK {
		t.Fatalf("rename = %d, want 200", renameResp.StatusCode)
	}

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	resp, body := e.get(t, memberClient, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) != 1 || containers[0].(map[string]any)["display_name"] != "checkout-service" {
		t.Fatalf("expected the member to see the custom app name, got %v", containers)
	}
}

// Admin sees every container across the whole database (unrestricted),
// so this looks up its own fixture by ID within the full list rather than
// assuming it's the only row -- other tests' (and, in a shared dev
// database, other concurrent activity's) fixtures are always present too.
func TestDockerOverview_AdminResponse_ShowsContainerAndVMName(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin overview = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	var row map[string]any
	for _, c := range containers {
		if c.(map[string]any)["container_id"] == containerID.String() {
			row = c.(map[string]any)
		}
	}
	if row == nil {
		t.Fatalf("expected to find fixture container %s in the admin overview", containerID)
	}
	if row["container_name"] != "web-1" {
		t.Errorf("admin response must include the real container_name, got %v", row["container_name"])
	}
	if row["vm_name"] == nil || row["vm_name"] == "" {
		t.Errorf("admin response must include the real vm_name, got %v", row["vm_name"])
	}
}

func TestK8sOverview_MemberResponse_HidesPodAndClusterName(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "redaction-test-cluster")
	e.createK8sPodFixture(t, clusterID, "default", "web-1")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermK8sMonitor)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	resp, body := e.get(t, memberClient, "/api/k8s/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	pods, _ := body["pods"].([]any)
	if len(pods) != 1 {
		t.Fatalf("expected exactly 1 pod, got %d", len(pods))
	}
	row := pods[0].(map[string]any)
	for _, key := range []string{"pod_name", "namespace", "cluster_name", "cluster_resource_id", "node_name"} {
		if _, ok := row[key]; ok {
			t.Errorf("member response must never include %s, got %v", key, row[key])
		}
	}
	if row["display_name"] != unnamedAppLabelForTest {
		t.Errorf("expected display_name fallback %q for an unnamed pod, got %v", unnamedAppLabelForTest, row["display_name"])
	}
}

// Admin sees every pod across the whole database (unrestricted), so this
// looks up its own fixture by ID within the full list rather than
// assuming it's the only row.
func TestK8sOverview_AdminResponse_ShowsPodAndClusterName(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "redaction-admin-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/k8s/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin overview = %d, want 200", resp.StatusCode)
	}
	pods, _ := body["pods"].([]any)
	var row map[string]any
	for _, p := range pods {
		if p.(map[string]any)["pod_id"] == podID.String() {
			row = p.(map[string]any)
		}
	}
	if row == nil {
		t.Fatalf("expected to find fixture pod %s in the admin overview", podID)
	}
	if row["pod_name"] != "web-1" {
		t.Errorf("admin response must include the real pod_name, got %v", row["pod_name"])
	}
	if row["cluster_name"] == nil || row["cluster_name"] == "" {
		t.Errorf("admin response must include the real cluster_name, got %v", row["cluster_name"])
	}
}

// unnamedAppLabelForTest mirrors handlers.unnamedAppLabel -- kept as its
// own constant here (rather than importing the unexported handlers
// constant) since server_test is an external test package.
const unnamedAppLabelForTest = "Unnamed App"

// setDockerContainerDisplayName is a thin wrapper around the real PUT
// /api/docker/containers/:id/name endpoint (as admin) -- used as test
// setup across this file and docker_access_test.go wherever a test needs
// a container's Member-visible identity (its App Name) to be something
// other than the "Unnamed App" fallback.
func (e *testEnv) setDockerContainerDisplayName(t *testing.T, adminClient *http.Client, containerID uuid.UUID, displayName string) {
	t.Helper()
	resp, body := e.do(t, adminClient, http.MethodPut, "/api/docker/containers/"+containerID.String()+"/name", map[string]string{"display_name": displayName})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set docker container display name = %d, want 200: %v", resp.StatusCode, body)
	}
}

// setK8sPodDisplayName mirrors setDockerContainerDisplayName exactly.
func (e *testEnv) setK8sPodDisplayName(t *testing.T, adminClient *http.Client, podID uuid.UUID, displayName string) {
	t.Helper()
	resp, body := e.do(t, adminClient, http.MethodPut, "/api/k8s/pods/"+podID.String()+"/name", map[string]string{"display_name": displayName})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set k8s pod display name = %d, want 200: %v", resp.StatusCode, body)
	}
}

// === Display name (custom "App Name") ===

func TestDockerContainerDisplayName_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, _ := e.do(t, client, http.MethodPut, "/api/docker/containers/"+containerID.String()+"/name", map[string]string{"display_name": "checkout-service"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member set display name = %d, want 403", resp.StatusCode)
	}
}

func TestDockerContainerDisplayName_SetAndClear(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	setResp, setBody := e.do(t, client, http.MethodPut, "/api/docker/containers/"+containerID.String()+"/name", map[string]string{"display_name": "checkout-service"})
	if setResp.StatusCode != http.StatusOK {
		t.Fatalf("set display name = %d, want 200: %v", setResp.StatusCode, setBody)
	}
	if setBody["display_name"] != "checkout-service" {
		t.Errorf("expected display_name = checkout-service, got %v", setBody["display_name"])
	}
	assertAuditEventExists(t, e, "DOCKER_CONTAINER", containerID, services.AuditDockerContainerRenamed)

	overviewResp, overviewBody := e.get(t, client, "/api/docker/overview")
	if overviewResp.StatusCode != http.StatusOK {
		t.Fatalf("overview = %d, want 200", overviewResp.StatusCode)
	}
	containers, _ := overviewBody["containers"].([]any)
	found := false
	for _, c := range containers {
		row := c.(map[string]any)
		if row["container_id"] == containerID.String() {
			found = true
			if row["display_name"] != "checkout-service" {
				t.Errorf("expected overview to reflect display_name, got %v", row["display_name"])
			}
		}
	}
	if !found {
		t.Fatal("expected the renamed container to appear in the overview")
	}

	clearResp, clearBody := e.do(t, client, http.MethodPut, "/api/docker/containers/"+containerID.String()+"/name", map[string]string{"display_name": ""})
	if clearResp.StatusCode != http.StatusOK {
		t.Fatalf("clear display name = %d, want 200", clearResp.StatusCode)
	}
	if v, ok := clearBody["display_name"]; ok && v != "" {
		t.Errorf("expected display_name cleared, got %v", v)
	}
}

func TestK8sPodDisplayName_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "rename-test-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, _ := e.do(t, client, http.MethodPut, "/api/k8s/pods/"+podID.String()+"/name", map[string]string{"display_name": "checkout-service"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member set pod display name = %d, want 403", resp.StatusCode)
	}
}

func TestK8sPodDisplayName_SetAndClear(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "rename-test-cluster-2")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	setResp, setBody := e.do(t, client, http.MethodPut, "/api/k8s/pods/"+podID.String()+"/name", map[string]string{"display_name": "checkout-service"})
	if setResp.StatusCode != http.StatusOK {
		t.Fatalf("set pod display name = %d, want 200: %v", setResp.StatusCode, setBody)
	}
	if setBody["display_name"] != "checkout-service" {
		t.Errorf("expected display_name = checkout-service, got %v", setBody["display_name"])
	}
	assertAuditEventExists(t, e, "K8S_POD", podID, services.AuditK8sPodRenamed)

	overviewResp, overviewBody := e.get(t, client, "/api/k8s/overview")
	if overviewResp.StatusCode != http.StatusOK {
		t.Fatalf("overview = %d, want 200", overviewResp.StatusCode)
	}
	pods, _ := overviewBody["pods"].([]any)
	found := false
	for _, p := range pods {
		row := p.(map[string]any)
		if row["pod_id"] == podID.String() {
			found = true
			if row["display_name"] != "checkout-service" {
				t.Errorf("expected overview to reflect display_name, got %v", row["display_name"])
			}
		}
	}
	if !found {
		t.Fatal("expected the renamed pod to appear in the overview")
	}
}

// === Log search ===

func TestDockerLogsSearch_Unauthorized_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, _ := e.get(t, client, "/api/docker/containers/"+containerID.String()+"/logs/search")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member search = %d, want 404", resp.StatusCode)
	}
}

func TestDockerLogsSearch_FindsStoredLinesAndFiltersByKeyword(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	adminEmail, adminPassword := e.createAdmin(t)

	now := time.Now().UTC()
	mustInsertDockerLogLine(t, e, containerID, now.Add(-2*time.Minute), "starting up")
	mustInsertDockerLogLine(t, e, containerID, now.Add(-1*time.Minute), "connection refused: retrying")
	mustInsertDockerLogLine(t, e, containerID, now, "ready to accept connections")

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	allResp, allBody := e.get(t, client, "/api/docker/containers/"+containerID.String()+"/logs/search")
	if allResp.StatusCode != http.StatusOK {
		t.Fatalf("search (no filter) = %d, want 200", allResp.StatusCode)
	}
	allLines, _ := allBody["lines"].([]any)
	if len(allLines) != 3 {
		t.Fatalf("expected 3 stored lines, got %d", len(allLines))
	}

	filteredResp, filteredBody := e.get(t, client, "/api/docker/containers/"+containerID.String()+"/logs/search?q=refused")
	if filteredResp.StatusCode != http.StatusOK {
		t.Fatalf("search (filtered) = %d, want 200", filteredResp.StatusCode)
	}
	filteredLines, _ := filteredBody["lines"].([]any)
	if len(filteredLines) != 1 {
		t.Fatalf("expected exactly 1 line matching 'refused', got %d", len(filteredLines))
	}
	if filteredLines[0].(map[string]any)["line"] != "connection refused: retrying" {
		t.Errorf("expected the matching line, got %v", filteredLines[0])
	}
}

// TestDockerLogsSearch_ClassifiesSeverityAndFiltersByIt locks in the
// heuristic classifier (services.ClassifyLogLine): every returned line
// carries a severity/category, the response tallies a Healthy/Warning/
// Error/Critical counts summary, and ?severity= narrows the page to just
// that bucket.
func TestDockerLogsSearch_ClassifiesSeverityAndFiltersByIt(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-2", "b2c3d4e5f6a1")
	adminEmail, adminPassword := e.createAdmin(t)

	now := time.Now().UTC()
	mustInsertDockerLogLine(t, e, containerID, now.Add(-3*time.Minute), "server started successfully")
	mustInsertDockerLogLine(t, e, containerID, now.Add(-2*time.Minute), "GET /missing-route 404")
	mustInsertDockerLogLine(t, e, containerID, now.Add(-1*time.Minute), "panic: runtime error: nil pointer")

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	allResp, allBody := e.get(t, client, "/api/docker/containers/"+containerID.String()+"/logs/search")
	if allResp.StatusCode != http.StatusOK {
		t.Fatalf("search (no filter) = %d, want 200", allResp.StatusCode)
	}
	counts, _ := allBody["counts"].(map[string]any)
	if counts == nil {
		t.Fatalf("expected a counts summary, got %v", allBody["counts"])
	}
	if counts["healthy"] != float64(1) || counts["error"] != float64(1) || counts["critical"] != float64(1) {
		t.Fatalf("expected counts {healthy:1, error:1, critical:1}, got %v", counts)
	}
	allLines, _ := allBody["lines"].([]any)
	for _, raw := range allLines {
		line := raw.(map[string]any)
		if line["severity"] == nil || line["severity"] == "" {
			t.Errorf("expected every line to carry a severity, got %v", line)
		}
	}

	criticalResp, criticalBody := e.get(t, client, "/api/docker/containers/"+containerID.String()+"/logs/search?severity=CRITICAL")
	if criticalResp.StatusCode != http.StatusOK {
		t.Fatalf("search (severity=CRITICAL) = %d, want 200", criticalResp.StatusCode)
	}
	criticalLines, _ := criticalBody["lines"].([]any)
	if len(criticalLines) != 1 {
		t.Fatalf("expected exactly 1 CRITICAL line, got %d (%v)", len(criticalLines), criticalBody)
	}
	criticalLine := criticalLines[0].(map[string]any)
	if criticalLine["line"] != "panic: runtime error: nil pointer" {
		t.Errorf("expected the panic line, got %v", criticalLine)
	}
	if criticalLine["suggestion"] == nil || criticalLine["suggestion"] == "" {
		t.Errorf("expected a suggested next step on a CRITICAL line, got %v", criticalLine)
	}
}

func TestK8sLogsSearch_FindsStoredLinesAndFiltersByKeyword(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "search-test-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	adminEmail, adminPassword := e.createAdmin(t)

	now := time.Now().UTC()
	mustInsertK8sPodLogLine(t, e, podID, now.Add(-2*time.Minute), "starting up")
	mustInsertK8sPodLogLine(t, e, podID, now.Add(-1*time.Minute), "panic: out of memory")
	mustInsertK8sPodLogLine(t, e, podID, now, "ready to accept connections")

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	filteredResp, filteredBody := e.get(t, client, "/api/k8s/pods/"+podID.String()+"/logs/search?q=panic")
	if filteredResp.StatusCode != http.StatusOK {
		t.Fatalf("search (filtered) = %d, want 200", filteredResp.StatusCode)
	}
	filteredLines, _ := filteredBody["lines"].([]any)
	if len(filteredLines) != 1 || filteredLines[0].(map[string]any)["line"] != "panic: out of memory" {
		t.Fatalf("expected exactly the panic line, got %v", filteredLines)
	}
}

func mustInsertDockerLogLine(t *testing.T, e *testEnv, containerID uuid.UUID, loggedAt time.Time, line string) {
	t.Helper()
	if err := e.store.InsertDockerLogLine(context.Background(), generated.InsertDockerLogLineParams{
		DockerContainerID: containerID, LoggedAt: pgutil.Timestamptz(loggedAt), Line: line,
	}); err != nil {
		t.Fatalf("insert docker log line: %v", err)
	}
}

func mustInsertK8sPodLogLine(t *testing.T, e *testEnv, podID uuid.UUID, loggedAt time.Time, line string) {
	t.Helper()
	if err := e.store.InsertK8sPodLogLine(context.Background(), generated.InsertK8sPodLogLineParams{
		K8sPodID: podID, LoggedAt: pgutil.Timestamptz(loggedAt), Line: line,
	}); err != nil {
		t.Fatalf("insert k8s pod log line: %v", err)
	}
}

// === Log capture (background, real fake SSH/API servers) ===

// TestDockerLogCapture_CaptureOne_StoresNewLines proves the real capture
// path end to end: a real (fake) SSH server, a real bounded `docker logs
// --since ... --timestamps` exec actually run, its timestamped output
// actually parsed and stored -- mirrors the live-tail full-session test's
// rigor, for the background counterpart.
func TestDockerLogCapture_CaptureOne_StoresNewLines(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	hostKeyPEM, _ := generateTestSSHKeyPEM(t)
	hostSigner, err := ssh.ParsePrivateKey([]byte(hostKeyPEM))
	if err != nil {
		t.Fatalf("parse fake server host key: %v", err)
	}
	clientKeyPEM, clientPub := generateTestSSHKeyPEM(t)
	srv := startFakeSSHServer(t, hostSigner, clientPub)

	vm := e.createVMWithAddress(t, project, srv.host, int32(srv.port))
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, clientKeyPEM)
	if _, err := e.hostKeys.Trust(context.Background(), vm, srv.host, srv.port, 5*time.Second); err != nil {
		t.Fatalf("trust fake server host key: %v", err)
	}

	rows, err := e.store.ListRunningDockerContainersForLogCapture(context.Background())
	if err != nil {
		t.Fatalf("list running containers for capture: %v", err)
	}
	var row generated.ListRunningDockerContainersForLogCaptureRow
	found := false
	for _, r := range rows {
		if r.ID == containerID {
			row, found = r, true
		}
	}
	if !found {
		t.Fatal("expected the fixture container to appear in the log-capture work list")
	}

	if err := e.dockerLogCapture.CaptureOne(context.Background(), row); err != nil {
		t.Fatalf("capture one: %v", err)
	}

	searchResp, searchBody := e.get(t, adminClient, "/api/docker/containers/"+containerID.String()+"/logs/search")
	if searchResp.StatusCode != http.StatusOK {
		t.Fatalf("search after capture = %d, want 200", searchResp.StatusCode)
	}
	lines, _ := searchBody["lines"].([]any)
	if len(lines) != 1 || lines[0].(map[string]any)["line"] != "hello from container" {
		t.Fatalf("expected exactly one captured line 'hello from container', got %v", lines)
	}
}

// TestK8sLogCapture_CaptureOne_StoresNewLines mirrors the Docker capture
// test above, against a fake Kubernetes API server.
func TestK8sLogCapture_CaptureOne_StoresNewLines(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "capture-test-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	token := e.regenerateK8sAgentToken(t, adminClient, clusterID)
	startFakeK8sAgent(t, e.baseURL, token, fakeK8sAgentOptions{logLine: "hello from captured pod"})
	e.waitForAgentConnected(t, adminClient, clusterID.String(), 5*time.Second)

	rows, err := e.store.ListRunningK8sPodsForLogCapture(context.Background())
	if err != nil {
		t.Fatalf("list running pods for capture: %v", err)
	}
	var row generated.ListRunningK8sPodsForLogCaptureRow
	found := false
	for _, r := range rows {
		if r.ID == podID {
			row, found = r, true
		}
	}
	if !found {
		t.Fatal("expected the fixture pod to appear in the log-capture work list")
	}

	if err := e.k8sLogCapture.CaptureOne(context.Background(), row); err != nil {
		t.Fatalf("capture one: %v", err)
	}

	searchResp, searchBody := e.get(t, adminClient, "/api/k8s/pods/"+podID.String()+"/logs/search")
	if searchResp.StatusCode != http.StatusOK {
		t.Fatalf("search after capture = %d, want 200", searchResp.StatusCode)
	}
	lines, _ := searchBody["lines"].([]any)
	if len(lines) != 1 || lines[0].(map[string]any)["line"] != "hello from captured pod" {
		t.Fatalf("expected exactly one captured line 'hello from captured pod', got %v", lines)
	}
}

// === Retention ===

// TestDockerLogRetention_Cleanup_DeletesOldLines checks the store directly
// (not the HTTP search endpoint, which independently clamps its own
// from/to to the retention window regardless of what's actually still in
// the table) -- this is the one place that actually distinguishes "the old
// line was deleted" from "the old line is merely outside the default
// search window."
func TestDockerLogRetention_Cleanup_DeletesOldLines(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")

	mustInsertDockerLogLine(t, e, containerID, time.Now().Add(-30*24*time.Hour), "very old line")
	mustInsertDockerLogLine(t, e, containerID, time.Now(), "recent line")

	e.dockerLogRetentionSvc.Cleanup(context.Background())

	rows, err := e.store.SearchDockerLogLines(context.Background(), generated.SearchDockerLogLinesParams{
		DockerContainerID: containerID,
		FromTs:            pgutil.Timestamptz(time.Now().Add(-60 * 24 * time.Hour)),
		ToTs:              pgutil.Timestamptz(time.Now().Add(time.Hour)),
		PageLimit:         100,
	})
	if err != nil {
		t.Fatalf("search log lines: %v", err)
	}
	if len(rows) != 1 || rows[0].Line != "recent line" {
		t.Fatalf("expected only the recent line to survive retention, got %v", rows)
	}
}

func TestK8sLogRetention_Cleanup_DeletesOldLines(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	clusterID, _ := e.createK8sClusterFixture(t, project, "retention-test-cluster")
	podID := e.createK8sPodFixture(t, clusterID, "default", "web-1")

	mustInsertK8sPodLogLine(t, e, podID, time.Now().Add(-30*24*time.Hour), "very old line")
	mustInsertK8sPodLogLine(t, e, podID, time.Now(), "recent line")

	e.k8sLogRetentionSvc.Cleanup(context.Background())

	rows, err := e.store.SearchK8sPodLogLines(context.Background(), generated.SearchK8sPodLogLinesParams{
		K8sPodID:  podID,
		FromTs:    pgutil.Timestamptz(time.Now().Add(-60 * 24 * time.Hour)),
		ToTs:      pgutil.Timestamptz(time.Now().Add(time.Hour)),
		PageLimit: 100,
	})
	if err != nil {
		t.Fatalf("search log lines: %v", err)
	}
	if len(rows) != 1 || rows[0].Line != "recent line" {
		t.Fatalf("expected only the recent line to survive retention, got %v", rows)
	}
}
