// This file exercises Step 24's new top-level Docker Monitoring/Logs
// section: docker_access_grants CRUD (Admin-only), the cross-VM
// MonitoringOverview endpoint's Project/Group-scoped filtering, and the
// Logs live-tail WebSocket's authorization (including the specific
// separation the spec calls for -- a docker.monitor grant does NOT imply
// docker.logs, and neither implies vm.view/vm.connect or vice versa).
package server_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/services"
)

// grantDockerAccess is a thin wrapper around the real
// POST /api/docker/access-grants endpoint (as admin), used as test setup
// throughout this file -- exercises the actual HTTP/authz/validation path
// rather than writing rows directly, so a bug in Grant itself would show
// up here too.
func (e *testEnv) grantDockerAccess(t *testing.T, adminClient *http.Client, userID, workspaceID uuid.UUID, permission string) {
	t.Helper()
	resp, body := e.do(t, adminClient, http.MethodPost, "/api/docker/access-grants", map[string]string{
		"user_id": userID.String(), "workspace_id": workspaceID.String(), "permission": permission,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grant docker access = %d, want 200: %v", resp.StatusCode, body)
	}
}

// === Access grant CRUD ===

func TestDockerAccessGrant_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, _, memberID := e.createMember(t)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/docker/access-grants", map[string]string{
		"user_id": memberID.String(), "workspace_id": project.String(), "permission": services.PermDockerMonitor,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member grant docker access = %d, want 403", resp.StatusCode)
	}
}

func TestDockerAccessGrant_UnknownProject_NotFound(t *testing.T) {
	e := setup(t)
	_, _, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/docker/access-grants", map[string]string{
		"user_id": memberID.String(), "workspace_id": uuid.NewString(), "permission": services.PermDockerMonitor,
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("grant for nonexistent workspace = %d, want 404", resp.StatusCode)
	}
}

func TestDockerAccessGrant_InvalidPermission_BadRequest(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, _, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/docker/access-grants", map[string]string{
		"user_id": memberID.String(), "workspace_id": project.String(), "permission": "docker.manage",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("grant with unknown permission = %d, want 400", resp.StatusCode)
	}
}

func TestDockerAccessGrant_IsIdempotent(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, _, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	e.grantDockerAccess(t, client, memberID, project, services.PermDockerMonitor)
	e.grantDockerAccess(t, client, memberID, project, services.PermDockerMonitor) // must not error or duplicate

	resp, body := e.get(t, client, "/api/docker/access-grants")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list grants = %d, want 200", resp.StatusCode)
	}
	grants, _ := body["grants"].([]any)
	count := 0
	for _, g := range grants {
		grant := g.(map[string]any)
		if grant["user_id"] == memberID.String() && grant["permission"] == services.PermDockerMonitor {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 grant after granting twice, found %d", count)
	}
}

func TestDockerAccessRevoke_RemovesAccess(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermDockerMonitor)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	resp, body := e.get(t, memberClient, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview (granted) = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("expected 1 visible container after grant, got %d", len(containers))
	}

	listResp, listBody := e.get(t, adminClient, "/api/docker/access-grants")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list grants = %d, want 200", listResp.StatusCode)
	}
	grants, _ := listBody["grants"].([]any)
	var grantID string
	for _, g := range grants {
		grant := g.(map[string]any)
		if grant["user_id"] == memberID.String() {
			grantID = grant["id"].(string)
		}
	}
	if grantID == "" {
		t.Fatal("could not find the grant just created")
	}

	revokeResp, _ := e.do(t, adminClient, http.MethodDelete, "/api/docker/access-grants/"+grantID, nil)
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d, want 200", revokeResp.StatusCode)
	}
	assertAuditEventExists(t, e, "USER", memberID, services.AuditDockerAccessRevoked)

	resp2, body2 := e.get(t, memberClient, "/api/docker/overview")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("member overview (revoked) = %d, want 200", resp2.StatusCode)
	}
	containers2, _ := body2["containers"].([]any)
	if len(containers2) != 0 {
		t.Errorf("expected 0 visible containers after revoke, got %d", len(containers2))
	}
}

// The optional vm_resource_id filter narrows the overview to one VM's
// containers -- used by a Dashboard's Monitoring/Logs tabs (see
// handlers/dashboards.go) so a Member with access to several VMs in a
// Project only ever sees the one this Dashboard is bound to, even though
// vm_resource_id itself is redacted from their normal (unfiltered)
// response.
func TestDockerOverview_VMResourceIDFilterNarrowsToOneVM(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm1 := e.createVM(t, project)
	vm2 := e.createVM(t, project)
	e.createDockerContainerFixture(t, vm1, "web-1", "a1b2c3d4e5f6")
	e.createDockerContainerFixture(t, vm2, "web-2", "b2c3d4e5f6a1")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermDockerMonitor)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	unfilteredResp, unfilteredBody := e.get(t, memberClient, "/api/docker/overview")
	if unfilteredResp.StatusCode != http.StatusOK {
		t.Fatalf("member overview (unfiltered) = %d, want 200", unfilteredResp.StatusCode)
	}
	if containers, _ := unfilteredBody["containers"].([]any); len(containers) != 2 {
		t.Fatalf("expected 2 visible containers unfiltered, got %d", len(containers))
	}

	filteredResp, filteredBody := e.get(t, memberClient, "/api/docker/overview?vm_resource_id="+vm1.String())
	if filteredResp.StatusCode != http.StatusOK {
		t.Fatalf("member overview (filtered) = %d, want 200", filteredResp.StatusCode)
	}
	containers, _ := filteredBody["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("expected exactly 1 container filtered to vm1, got %d", len(containers))
	}

	// A VM the Member was never granted access to must return empty, not
	// leak that VM's container, even though the caller already has SOME
	// docker.monitor grant elsewhere in this project.
	otherProject := e.createWorkspace(t)
	otherVM := e.createVM(t, otherProject)
	e.createDockerContainerFixture(t, otherVM, "other", "c3d4e5f6a1b2")
	deniedResp, deniedBody := e.get(t, memberClient, "/api/docker/overview?vm_resource_id="+otherVM.String())
	if deniedResp.StatusCode != http.StatusOK {
		t.Fatalf("member overview (filtered, unauthorized vm) = %d, want 200", deniedResp.StatusCode)
	}
	if containers, _ := deniedBody["containers"].([]any); len(containers) != 0 {
		t.Errorf("expected 0 containers for an unauthorized vm_resource_id filter, got %d", len(containers))
	}
}

// === Monitoring overview scoping ===

func TestDockerOverview_AdminSeesAllWithoutAnyGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	resp, body := e.get(t, client, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin overview = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) == 0 {
		t.Error("admin should see containers with no grant needed")
	}
}

func TestDockerOverview_MemberSeesNothingWithoutGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) != 0 {
		t.Errorf("member with no grant should see 0 containers, got %d", len(containers))
	}
}

// TestDockerOverview_VMViewGrantAlone_GrantsNothingHere proves the
// deliberate separation from vm.view/vm.connect: a member fully
// authorized on the VM (view+connect) still sees nothing in the new
// Docker section without a separate docker.monitor grant.
func TestDockerOverview_VMViewGrantAlone_GrantsNothingHere(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView, services.PermVMConnect)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) != 0 {
		t.Errorf("vm.view/vm.connect must not imply docker.monitor, got %d containers", len(containers))
	}
}

func TestDockerOverview_MemberSeesViaProjectGrant(t *testing.T) {
	e := setup(t)
	projectA := e.createWorkspace(t)
	projectB := e.createWorkspace(t)
	vmA := e.createVM(t, projectA)
	vmB := e.createVM(t, projectB)
	containerA := e.createDockerContainerFixture(t, vmA, "a-web", "aaaaaaaaaaaa")
	e.createDockerContainerFixture(t, vmB, "b-web", "bbbbbbbbbbbb")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, projectA, services.PermDockerMonitor)
	// A Member is never shown the real container_name (see the redaction
	// rule in docker_overview.go) -- naming it is what makes it possible to
	// confirm from the Member's own response that this is project A's app,
	// not project B's.
	e.setDockerContainerDisplayName(t, adminClient, containerA, "app-a")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("expected exactly 1 container (project A only), got %d", len(containers))
	}
	if containers[0].(map[string]any)["display_name"] != "app-a" {
		t.Errorf("expected project A's app, got %v", containers[0])
	}
}

func TestDockerOverview_MemberSeesViaGroupGrant(t *testing.T) {
	e := setup(t)
	groupA := e.createWorkspace(t)
	groupB := e.createWorkspace(t)
	vmA := e.createVM(t, groupA)
	vmB := e.createVM(t, groupB)
	containerA := e.createDockerContainerFixture(t, vmA, "a-web", "aaaaaaaaaaaa")
	e.createDockerContainerFixture(t, vmB, "b-web", "bbbbbbbbbbbb")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, groupA, services.PermDockerMonitor)
	e.setDockerContainerDisplayName(t, adminClient, containerA, "app-a")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) != 1 || containers[0].(map[string]any)["display_name"] != "app-a" {
		t.Fatalf("expected exactly group A's app, got %v", containers)
	}
}

// TestDockerOverview_GroupGrant_ExtendsToNewVMAutomatically proves the
// grant is dynamic (Step 24 decision), not a point-in-time snapshot: a VM
// added to an already-granted group becomes visible with no separate
// re-grant.
func TestDockerOverview_GroupGrant_ExtendsToNewVMAutomatically(t *testing.T) {
	e := setup(t)
	group := e.createWorkspace(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, group, services.PermDockerMonitor)

	// The VM (and its container) is created AFTER the grant.
	vm := e.createVM(t, group)
	containerID := e.createDockerContainerFixture(t, vm, "late-web", "cccccccccccc")
	e.setDockerContainerDisplayName(t, adminClient, containerID, "late-app")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	resp, body := e.get(t, client, "/api/docker/overview")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", resp.StatusCode)
	}
	containers, _ := body["containers"].([]any)
	if len(containers) != 1 || containers[0].(map[string]any)["display_name"] != "late-app" {
		t.Fatalf("expected the late-added VM's app to already be visible, got %v", containers)
	}
}

// TestDockerOverview_MemberSeesViaResourceScopedGrant proves the new
// per-resource grant scope (added alongside the existing workspace-wide
// scope): granting docker.monitor on one specific VM's resource_id
// exposes only that VM's containers, even when a second VM in the SAME
// workspace exists and has no grant of its own.
func TestDockerOverview_MemberSeesViaResourceScopedGrant(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vmA := e.createVM(t, workspace)
	vmB := e.createVM(t, workspace)
	containerA := e.createDockerContainerFixture(t, vmA, "a-web", "aaaaaaaaaaaa")
	e.createDockerContainerFixture(t, vmB, "b-web", "bbbbbbbbbbbb")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	resp, body := e.do(t, adminClient, http.MethodPost, "/api/docker/access-grants", map[string]any{
		"user_id": memberID.String(), "resource_id": vmA.String(), "permission": services.PermDockerMonitor,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grant resource-scoped docker access = %d, want 200: %v", resp.StatusCode, body)
	}
	e.setDockerContainerDisplayName(t, adminClient, containerA, "app-a")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	memberResp, memberBody := e.get(t, client, "/api/docker/overview")
	if memberResp.StatusCode != http.StatusOK {
		t.Fatalf("member overview = %d, want 200", memberResp.StatusCode)
	}
	containers, _ := memberBody["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("expected exactly 1 container (VM A only, not VM B despite same workspace), got %d: %v", len(containers), containers)
	}
	if containers[0].(map[string]any)["display_name"] != "app-a" {
		t.Errorf("expected VM A's app, got %v", containers[0])
	}
}

// === Logs stream authorization ===

func TestDockerLogsStream_Unauthenticated_PreUpgrade401(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	client := newClient()

	url := wsURL(e.baseURL, "/api/docker/containers/"+containerID.String()+"/logs/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail for an unauthenticated caller")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated logs stream status = %v, want 401", statusOf(resp))
	}
}

func TestDockerLogsStream_UnauthorizedMember_PreUpgrade404(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	url := wsURL(e.baseURL, "/api/docker/containers/"+containerID.String()+"/logs/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail for an unauthorized member")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member logs stream status = %v, want 404", statusOf(resp))
	}
}

// TestDockerLogsStream_MonitorGrantAlone_DoesNotGrantLogs proves the
// second deliberate separation: docker.monitor and docker.logs are
// independent permissions, exactly like vm.view and vm.connect.
func TestDockerLogsStream_MonitorGrantAlone_DoesNotGrantLogs(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermDockerMonitor) // NOT docker.logs

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	url := wsURL(e.baseURL, "/api/docker/containers/"+containerID.String()+"/logs/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {testFrontendOrigin}})
	if err == nil {
		t.Fatal("expected handshake to fail: docker.monitor must not imply docker.logs")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("docker.monitor-only member logs stream status = %v, want 404", statusOf(resp))
	}
}

func TestDockerLogsStream_AuthorizedMember_ForeignOrigin_Forbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	containerID := e.createDockerContainerFixture(t, vm, "web-1", "a1b2c3d4e5f6")
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermDockerLogs)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)
	url := wsURL(e.baseURL, "/api/docker/containers/"+containerID.String()+"/logs/stream")
	_, resp, err := dialerFor(client).Dial(url, http.Header{"Origin": {"http://evil.example.com"}})
	if err == nil {
		t.Fatal("expected handshake to be rejected for a foreign Origin")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign-origin logs stream status = %v, want 403", statusOf(resp))
	}
}

// TestDockerLogsStream_FullSession_RealSSHAndAudit is the end-to-end
// proof: a real (fake) SSH server, a real `docker logs` command actually
// executed and its output actually relayed line-by-line, and both audit
// events recorded -- mirrors vm_console_test.go's equivalent full-session
// test exactly.
func TestDockerLogsStream_FullSession_RealSSHAndAudit(t *testing.T) {
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
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, clientKeyPEM)
	if _, err := e.hostKeys.Trust(context.Background(), vm, srv.host, srv.port, 5*time.Second); err != nil {
		t.Fatalf("trust fake server host key: %v", err)
	}
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermDockerLogs)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	url := wsURL(e.baseURL, "/api/docker/containers/"+containerID.String()+"/logs/stream")
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
		if frame["type"] == "log" && frame["line"] == "hello from container" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a log line 'hello from container' from the fake docker logs command, never received one")
	}
	_ = conn.SetReadDeadline(time.Time{})

	assertAuditEventExists(t, e, "VM", vm, services.AuditDockerLogsOpened)
	conn.Close()
	if !waitForAuditEvent(t, e, vm, services.AuditDockerLogsClosed, 5*time.Second) {
		t.Error("expected a DOCKER_LOGS_CLOSED audit event after disconnect, never observed one")
	}
}
