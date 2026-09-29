// This file exercises the Step 11 controlled-reboot HTTP surface. A real
// end-to-end reboot (Reboot -> WAITING_FOR_VM -> reconnect -> SUCCESS
// against a real VM) requires genuine SSH reachability and was verified
// manually against a disposable Ubuntu test container, documented in the
// Step 11 delivery summary -- these tests cover what's fully exercisable
// without a live VM: admin-only authorization end to end, IDOR protection
// on every operation-scoped endpoint, the reboot-required gate, and
// cross-operation exclusivity between updates and reboots (every fixture
// VM here has no SSH credential configured, so RunPrecheck's
// ssh_configured/vm_reachable checks always fail before any database
// claim is attempted -- exactly the "never reboot solely on trust"
// behavior under test for the happy-path claim itself).
package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// createRebootOperationFixture inserts a reboot_operations row directly
// (bypassing RequestReboot's real precheck, which needs a live VM), for
// exercising the read-only endpoints without a live VM.
func (e *testEnv) createRebootOperationFixture(t *testing.T, vmResourceID uuid.UUID, status string) uuid.UUID {
	t.Helper()
	vm, err := e.store.GetVMByResourceID(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("load vm for reboot fixture: %v", err)
	}
	op, err := e.store.CreateRebootOperation(context.Background(), generated.CreateRebootOperationParams{
		VmID: vm.ID, Reason: "ADMIN_REQUEST",
	})
	if err != nil {
		t.Fatalf("create reboot operation fixture: %v", err)
	}
	if status != "PENDING" {
		if _, err := e.store.UpdateRebootOperationStatus(context.Background(), generated.UpdateRebootOperationStatusParams{
			ID: op.ID, Status: status,
		}); err != nil {
			t.Fatalf("set reboot operation status: %v", err)
		}
	}
	return op.ID
}

func (e *testEnv) setRebootRequired(t *testing.T, vmResourceID uuid.UUID) {
	t.Helper()
	vm, err := e.store.GetVMByResourceID(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("load vm: %v", err)
	}
	if _, err := e.store.UpdateVMKernelStatus(context.Background(), generated.UpdateVMKernelStatusParams{
		ID: vm.ID, KernelVersion: pgutil.Text("6.8.0-31-generic"), KernelAvailable: pgutil.Text("6.8.0-40-generic"),
		RebootStatus: pgutil.Text("REQUIRED"), RebootReason: pgutil.Text("New kernel installed."),
	}); err != nil {
		t.Fatalf("set reboot required: %v", err)
	}
}

// === POST /api/vms/:id/reboot ===

func TestReboot_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.setRebootRequired(t, vm)

	memberEmail, memberPassword, _ := e.createMember(t)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, _ := e.do(t, memberClient, http.MethodPost, "/api/vms/"+vm.String()+"/reboot", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member reboot = %d, want 403", resp.StatusCode)
	}
}

func TestReboot_Unauthenticated(t *testing.T) {
	e := setup(t)
	client := newClient()
	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+uuid.NewString()+"/reboot", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated reboot = %d, want 401", resp.StatusCode)
	}
}

func TestReboot_MissingConfirmation_Rejected(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.setRebootRequired(t, vm)

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/vms/"+vm.String()+"/reboot", map[string]any{"confirmation": false})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reboot without confirmation = %d, want 400: %v", resp.StatusCode, body)
	}
}

func TestReboot_NotRequired_RejectedWithoutAdminRequestReason(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project) // reboot_status defaults to UNKNOWN, never REQUIRED

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/vms/"+vm.String()+"/reboot", map[string]any{"confirmation": true, "reason": "KERNEL_UPDATE"})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("reboot not required, reason=KERNEL_UPDATE = %d, want 409: %v", resp.StatusCode, body)
	}
}

func TestReboot_InvalidReason_Rejected(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/vms/"+vm.String()+"/reboot", map[string]any{"confirmation": true, "reason": "NOT_A_REAL_REASON"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid reason = %d, want 400: %v", resp.StatusCode, body)
	}
}

func TestReboot_UnreachableVM_FailsChecks(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.setRebootRequired(t, vm)

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/vms/"+vm.String()+"/reboot", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("reboot on unreachable vm = %d, want 409: %v", resp.StatusCode, body)
	}
}

func TestRebootPrecheck_NeverSendsReboot(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.setRebootRequired(t, vm)

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/vms/"+vm.String()+"/reboot/precheck", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("precheck = %d, want 200: %v", resp.StatusCode, body)
	}
	if _, present := body["ready"]; !present {
		t.Errorf("expected a 'ready' field, got %v", body)
	}
	// The VM must not have actually been rebooted -- no reboot_operations
	// row should exist for it.
	opsResp, opsBody := e.get(t, adminClient, "/api/vms/"+vm.String()+"/reboot-operations")
	if opsResp.StatusCode != http.StatusOK {
		t.Fatalf("list reboot operations = %d, want 200", opsResp.StatusCode)
	}
	if ops, _ := opsBody["reboot_operations"].([]any); len(ops) != 0 {
		t.Errorf("precheck must never create a reboot operation, found %d", len(ops))
	}
}

func TestRebootPrecheck_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)

	memberEmail, memberPassword, _ := e.createMember(t)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, _ := e.do(t, memberClient, http.MethodPost, "/api/vms/"+vm.String()+"/reboot/precheck", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member precheck = %d, want 403", resp.StatusCode)
	}
}

// === Cross-operation exclusivity (Step 10 <-> Step 11) ===

func TestReboot_RejectedWhileUpdateRunning(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	vm, planID := e.createDraftPlan(t, adminClient)
	e.setRebootRequired(t, vm)
	e.createOperationFixture(t, vm, planID, "RUNNING")

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/vms/"+vm.String()+"/reboot", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("reboot while update running = %d, want 409: %v", resp.StatusCode, body)
	}
	if body["error"] != "an update operation is currently running" {
		t.Errorf("error = %v, want the update-running message", body["error"])
	}
}

func TestExecute_RejectedWhileRebootRunning(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	vm, planID := e.createDraftPlan(t, adminClient)
	e.createRebootOperationFixture(t, vm, "REBOOTING")

	if _, err := e.store.SetUpdatePlanStatus(context.Background(), generated.SetUpdatePlanStatusParams{ID: planID, Status: "READY"}); err != nil {
		t.Fatalf("force plan ready: %v", err)
	}

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/update-plans/"+planID.String()+"/execute", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("execute while reboot running = %d, want 409: %v", resp.StatusCode, body)
	}
}

// === Operation-scoped GET endpoints: IDOR + authorization ===

func TestRebootOperationGet_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	opID := e.createRebootOperationFixture(t, vm, "SUCCESS")

	memberEmail, memberPassword, _ := e.createMember(t)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	for _, path := range []string{
		"/api/reboot-operations/" + opID.String(),
		"/api/reboot-operations/" + opID.String() + "/logs",
		"/api/reboot-operations/" + opID.String() + "/results",
	} {
		resp, _ := e.get(t, memberClient, path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s (unauthorized member) = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestRebootOperationGet_AuthorizedMember_Allowed(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	opID := e.createRebootOperationFixture(t, vm, "SUCCESS")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, body := e.get(t, memberClient, "/api/reboot-operations/"+opID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member get reboot operation = %d, want 200: %v", resp.StatusCode, body)
	}
	if body["status"] != "SUCCESS" {
		t.Errorf("status = %v, want SUCCESS", body["status"])
	}
}

func TestRebootOperationCancel_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	opID := e.createRebootOperationFixture(t, vm, "PENDING")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, _ := e.do(t, memberClient, http.MethodPost, "/api/reboot-operations/"+opID.String()+"/cancel", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member cancel reboot operation = %d, want 403", resp.StatusCode)
	}
}

func TestRebootOperationCancel_PendingSucceeds_RebootingRejected(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)

	pendingOp := e.createRebootOperationFixture(t, vm, "PENDING")
	resp, body := e.do(t, adminClient, http.MethodPost, "/api/reboot-operations/"+pendingOp.String()+"/cancel", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel pending reboot = %d, want 200: %v", resp.StatusCode, body)
	}
	if body["status"] != "CANCELLED" {
		t.Errorf("status after cancel = %v, want CANCELLED", body["status"])
	}

	rebootingOp := e.createRebootOperationFixture(t, vm, "PRECHECK")
	if _, err := e.store.UpdateRebootOperationStatus(context.Background(), generated.UpdateRebootOperationStatusParams{ID: rebootingOp, Status: "REBOOTING"}); err != nil {
		t.Fatalf("advance to rebooting: %v", err)
	}
	resp2, body2 := e.do(t, adminClient, http.MethodPost, "/api/reboot-operations/"+rebootingOp.String()+"/cancel", nil)
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("cancel rebooting operation = %d, want 409 (VM is already rebooting): %v", resp2.StatusCode, body2)
	}
}

func TestRebootOperationsList_MemberScoped_NoLeak(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	project := e.createWorkspace(t)
	authorizedVM := e.createVM(t, project)
	unauthorizedVM := e.createVM(t, project)
	e.createRebootOperationFixture(t, authorizedVM, "SUCCESS")
	e.createRebootOperationFixture(t, unauthorizedVM, "SUCCESS")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedVM, services.PermVMView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, body := e.get(t, memberClient, "/api/reboot-operations")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list reboot operations = %d, want 200: %v", resp.StatusCode, body)
	}
	ops, _ := body["reboot_operations"].([]any)
	for _, raw := range ops {
		op := raw.(map[string]any)
		if op["vm_id"] == unauthorizedVM.String() {
			t.Errorf("member's reboot operation list leaked an operation for an unauthorized VM: %v", op)
		}
	}
}

func TestRebootOperationsListForVM_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createRebootOperationFixture(t, vm, "SUCCESS")

	memberEmail, memberPassword, _ := e.createMember(t)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, _ := e.get(t, memberClient, "/api/vms/"+vm.String()+"/reboot-operations")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unauthorized member list-for-vm = %d, want 404", resp.StatusCode)
	}
}

func TestRebootOperationVerify_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	opID := e.createRebootOperationFixture(t, vm, "TIMEOUT")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, _ := e.do(t, memberClient, http.MethodPost, "/api/reboot-operations/"+opID.String()+"/verify", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member verify = %d, want 403", resp.StatusCode)
	}
}
