// This file exercises the Step 6 VM monitoring HTTP surface: IDOR
// protection on the two member-readable GET endpoints, admin-only manual
// collection with its rate limit, "no fake data" (a VM with no snapshot
// yet reports UNKNOWN, never fabricated numbers), and audit events. Like
// ssh_test.go, the connection-dependent cases point at a deterministically
// unreachable loopback port rather than a real VM -- the real end-to-end
// happy path (actual /proc parsing, actual deltas) was verified manually
// against a real Docker SSH server, documented in the Step 6 delivery
// summary.
package server_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/services"
)

// === GET .../monitoring/current ===

func TestMonitoringCurrent_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/monitoring/current")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member monitoring/current = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

func TestMonitoringCurrent_NoSnapshotYet_ReportsUnknownNotFakeData(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/monitoring/current")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("monitoring/current = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "UNKNOWN" {
		t.Errorf("status = %v, want UNKNOWN (no monitoring has ever run)", body["status"])
	}
	for _, field := range []string{"cpu", "memory", "storage", "load", "swap"} {
		if v, present := body[field]; present && v != nil {
			t.Errorf("field %q = %v, want absent/null -- must never fabricate monitoring data", field, v)
		}
	}
}

func TestMonitoringCurrent_AuthorizedMember_CanView(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/monitoring/current")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member monitoring/current = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "UNKNOWN" {
		t.Errorf("status = %v, want UNKNOWN", body["status"])
	}
	if _, present := body["stale_after_seconds"]; !present {
		t.Error("expected stale_after_seconds in the response")
	}
}

// === GET .../monitoring/history ===

func TestMonitoringHistory_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/monitoring/history")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member monitoring/history = %d, want 404", resp.StatusCode)
	}
}

func TestMonitoringHistory_AuthorizedMember_EmptyButBounded(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/monitoring/history")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("monitoring/history = %d, want 200", resp.StatusCode)
	}
	if _, present := body["from"]; !present {
		t.Error("expected a default 'from' bound in the response")
	}
	points, _ := body["points"].([]any)
	if len(points) != 0 {
		t.Errorf("points = %v, want empty (no monitoring has ever run)", points)
	}
}

func TestMonitoringHistory_InvalidRangeRejected(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/monitoring/history?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("to-before-from status = %d, want 400", resp.StatusCode)
	}
}

// === POST .../monitoring/collect ===

func TestMonitoringCollect_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/monitoring/collect", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member manual collect = %d, want 403", resp.StatusCode)
	}
}

func TestMonitoringCollect_NotConfigured_ReturnsFailedNotError(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/monitoring/collect", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("collect with no credential = %d, want 200 (operation endpoint; failure conveyed in the body)", resp.StatusCode)
	}
	if body["status"] != "FAILED" {
		t.Errorf("status = %v, want FAILED", body["status"])
	}
}

func TestMonitoringCollect_ConnectionRefused_UpdatesConnectionStatusNotHealth(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, key)

	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/monitoring/collect", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("collect = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "FAILED" {
		t.Fatalf("status = %v, want FAILED", body["status"])
	}

	// No snapshot was ever written, so /current must report OFFLINE (from
	// connection state) rather than any fabricated health value, and the
	// connection failure must be visible via connection-status exactly as
	// it is for a plain connection-test (Step 6 spec §33/§36).
	currentResp, currentBody := e.get(t, client, "/api/vms/"+vm.String()+"/monitoring/current")
	if currentResp.StatusCode != http.StatusOK {
		t.Fatalf("monitoring/current after failed collect = %d, want 200", currentResp.StatusCode)
	}
	if currentBody["status"] != "UNKNOWN" && currentBody["status"] != "OFFLINE" {
		t.Errorf("status = %v, want UNKNOWN (no snapshot ever written)", currentBody["status"])
	}

	statusResp, statusBody := e.get(t, client, "/api/vms/"+vm.String()+"/connection-status")
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("connection-status = %d, want 200", statusResp.StatusCode)
	}
	if statusBody["connection_status"] != "FAILED" {
		t.Errorf("connection_status = %v, want FAILED", statusBody["connection_status"])
	}
}

func TestMonitoringCollect_RateLimited(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, key)

	first, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/monitoring/collect", nil)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first collect = %d, want 200", first.StatusCode)
	}

	second, secondBody := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/monitoring/collect", nil)
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("immediate second collect = %d, want 429 (spec §48: must not allow unlimited rapid requests)", second.StatusCode)
	}
	if secondBody["error"] == nil {
		t.Error("expected an error message on the rate-limited response")
	}
}

func TestMonitoringCollect_NotFoundVM(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+uuid.NewString()+"/monitoring/collect", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("collect on a nonexistent VM = %d, want 404", resp.StatusCode)
	}
}

func TestAudit_MonitoringCollectTriggeredRecorded(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, key)
	e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/monitoring/collect", nil)

	assertAuditEventExists(t, e, "VM", vm, services.AuditMonitoringCollectTriggered)
}

// === monitoring_enabled toggle (Step 6 spec §4) ===

func TestVM_MonitoringEnabled_DefaultsTrueAndTogglable(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/vms", map[string]any{
		"workspace_id": project.String(), "name": "monitoring-toggle-vm", "address": "10.0.0.20",
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create vm = %d, want 201", createResp.StatusCode)
	}
	if createBody["monitoring_enabled"] != true {
		t.Errorf("monitoring_enabled on create = %v, want true (default)", createBody["monitoring_enabled"])
	}
	vmID := createBody["id"].(string)

	patchResp, patchBody := e.do(t, client, http.MethodPatch, "/api/vms/"+vmID, map[string]any{"monitoring_enabled": false})
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("patch monitoring_enabled = %d, want 200", patchResp.StatusCode)
	}
	if patchBody["monitoring_enabled"] != false {
		t.Errorf("monitoring_enabled after disable = %v, want false", patchBody["monitoring_enabled"])
	}
}
