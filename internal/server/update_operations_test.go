// This file exercises the Step 10 execution-engine HTTP surface. A real
// end-to-end execution (Execute -> RUNNING -> SUCCESS against a real VM)
// requires genuine SSH reachability and was verified manually against a
// disposable Ubuntu test container, documented in the Step 10 delivery
// summary -- these tests instead cover what's fully exercisable without a
// live VM: admin-only authorization end to end, IDOR protection on every
// operation-scoped endpoint, and rejection of an execute request against
// a plan that isn't READY (every fixture VM here has no SSH credential
// configured, so ValidatePlan's revalidation always fails before any
// database claim is attempted -- exactly the "never execute solely
// because a plan was approved earlier" behavior under test).
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

// createDraftPlan creates a VM, one selectable package update, and a
// DRAFT plan for it via the real CreatePlan service call, returning the
// plan ID.
func (e *testEnv) createDraftPlan(t *testing.T, adminClient *http.Client) (vmResourceID uuid.UUID, planID uuid.UUID) {
	t.Helper()
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.setPackageManager(t, vm, "APT")
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]any{{"package_id": pkgID.String()}},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create draft plan = %d, want 201: %v", resp.StatusCode, body)
	}
	plan := body["plan"].(map[string]any)
	id, err := uuid.Parse(plan["id"].(string))
	if err != nil {
		t.Fatalf("parse plan id: %v", err)
	}
	return vm, id
}

// === POST /api/update-plans/:id/execute ===

func TestExecute_MemberForbidden(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	_, planID := e.createDraftPlan(t, adminClient)

	memberEmail, memberPassword, _ := e.createMember(t)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, _ := e.do(t, memberClient, http.MethodPost, "/api/update-plans/"+planID.String()+"/execute", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member execute = %d, want 403", resp.StatusCode)
	}
}

func TestExecute_Unauthenticated(t *testing.T) {
	e := setup(t)
	client := newClient()
	resp, _ := e.do(t, client, http.MethodPost, "/api/update-plans/"+uuid.NewString()+"/execute", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated execute = %d, want 401", resp.StatusCode)
	}
}

func TestExecute_MissingConfirmation_Rejected(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	_, planID := e.createDraftPlan(t, adminClient)

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/update-plans/"+planID.String()+"/execute", map[string]any{"confirmation": false})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("execute without confirmation = %d, want 400: %v", resp.StatusCode, body)
	}
}

func TestExecute_UnknownPlan_NotFound(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, _ := e.do(t, adminClient, http.MethodPost, "/api/update-plans/"+uuid.NewString()+"/execute", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("execute unknown plan = %d, want 404", resp.StatusCode)
	}
}

func TestExecute_DraftPlan_RejectedNotReady(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	_, planID := e.createDraftPlan(t, adminClient)

	// A DRAFT plan (never approved) must never be executed, regardless of
	// confirmation.
	resp, body := e.do(t, adminClient, http.MethodPost, "/api/update-plans/"+planID.String()+"/execute", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("execute draft plan = %d, want 409: %v", resp.StatusCode, body)
	}

	// The plan must be left exactly as it was -- still DRAFT, not silently
	// advanced or corrupted by the rejected attempt.
	plan, err := e.store.GetUpdatePlanByID(context.Background(), planID)
	if err != nil {
		t.Fatalf("reload plan: %v", err)
	}
	if plan.Status != "DRAFT" {
		t.Errorf("plan status after rejected execute = %s, want unchanged DRAFT", plan.Status)
	}
}

func TestExecute_ApprovedButUnreachableVM_MarksStale(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	_, planID := e.createDraftPlan(t, adminClient)

	// Force the plan straight to READY (bypassing ApprovePlan's own
	// precheck gate, which a fixture VM with no SSH credential could never
	// pass) so Execute's *own* fresh revalidation is what's under test --
	// exactly the "never execute solely because a plan was approved
	// earlier" requirement.
	if _, err := e.store.SetUpdatePlanStatus(context.Background(), generated.SetUpdatePlanStatusParams{ID: planID, Status: "READY"}); err != nil {
		t.Fatalf("force plan ready: %v", err)
	}

	resp, body := e.do(t, adminClient, http.MethodPost, "/api/update-plans/"+planID.String()+"/execute", map[string]any{"confirmation": true})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("execute unreachable-vm plan = %d, want 409: %v", resp.StatusCode, body)
	}

	plan, err := e.store.GetUpdatePlanByID(context.Background(), planID)
	if err != nil {
		t.Fatalf("reload plan: %v", err)
	}
	if plan.Status != "STALE" {
		t.Errorf("plan status after failed revalidation = %s, want STALE", plan.Status)
	}
}

// === Operation-scoped GET endpoints: IDOR + authorization ===

// createOperationFixture inserts an operations row directly (bypassing
// Execute's transactional claim, which needs a real revalidation pass) so
// the read-only endpoints below can be exercised against a known
// operation ID without a live VM.
func (e *testEnv) createOperationFixture(t *testing.T, vmResourceID, planID uuid.UUID, status string) uuid.UUID {
	t.Helper()
	op, err := e.store.CreateUpdateOperation(context.Background(), generated.CreateUpdateOperationParams{
		ResourceID: pgutil.NullUUID(&vmResourceID), OperationType: "PACKAGE_UPDATE",
		CommandPreview: pgutil.Text("apt-get install --only-upgrade nginx -y"), UpdatePlanID: pgutil.NullUUID(&planID),
	})
	if err != nil {
		t.Fatalf("create operation fixture: %v", err)
	}
	if status != "PENDING" {
		if _, err := e.store.UpdateOperationStatus(context.Background(), generated.UpdateOperationStatusParams{
			ID: op.ID, Status: status,
		}); err != nil {
			t.Fatalf("set operation status: %v", err)
		}
	}
	return op.ID
}

func TestOperationGet_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	vm, planID := e.createDraftPlan(t, adminClient)
	opID := e.createOperationFixture(t, vm, planID, "PENDING")

	memberEmail, memberPassword, _ := e.createMember(t)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	for _, path := range []string{
		"/api/update-operations/" + opID.String(),
		"/api/update-operations/" + opID.String() + "/logs",
		"/api/update-operations/" + opID.String() + "/results",
	} {
		resp, _ := e.get(t, memberClient, path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s (unauthorized member) = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestOperationGet_AuthorizedMember_Allowed(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	vm, planID := e.createDraftPlan(t, adminClient)
	opID := e.createOperationFixture(t, vm, planID, "SUCCESS")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, body := e.get(t, memberClient, "/api/update-operations/"+opID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member get operation = %d, want 200: %v", resp.StatusCode, body)
	}
	if body["status"] != "SUCCESS" {
		t.Errorf("status = %v, want SUCCESS", body["status"])
	}
}

func TestOperationCancel_MemberForbidden(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	vm, planID := e.createDraftPlan(t, adminClient)
	opID := e.createOperationFixture(t, vm, planID, "PENDING")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, _ := e.do(t, memberClient, http.MethodPost, "/api/update-operations/"+opID.String()+"/cancel", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member cancel operation = %d, want 403", resp.StatusCode)
	}
}

func TestOperationCancel_PendingSucceeds_RunningRejected(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	vm, planID := e.createDraftPlan(t, adminClient)

	pendingOp := e.createOperationFixture(t, vm, planID, "PENDING")
	resp, body := e.do(t, adminClient, http.MethodPost, "/api/update-operations/"+pendingOp.String()+"/cancel", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel pending operation = %d, want 200: %v", resp.StatusCode, body)
	}
	if body["status"] != "CANCELLED" {
		t.Errorf("status after cancel = %v, want CANCELLED", body["status"])
	}

	_, planID2 := e.createDraftPlan(t, adminClient)
	runningOp := e.createOperationFixture(t, vm, planID2, "PENDING")
	if _, err := e.store.UpdateOperationStatus(context.Background(), generated.UpdateOperationStatusParams{ID: runningOp, Status: "CONNECTING"}); err != nil {
		t.Fatalf("advance to connecting: %v", err)
	}
	if _, err := e.store.UpdateOperationStatus(context.Background(), generated.UpdateOperationStatusParams{ID: runningOp, Status: "RUNNING"}); err != nil {
		t.Fatalf("advance to running: %v", err)
	}

	resp2, body2 := e.do(t, adminClient, http.MethodPost, "/api/update-operations/"+runningOp.String()+"/cancel", nil)
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("cancel running operation = %d, want 409 (cancellation unavailable once package changes are in progress): %v", resp2.StatusCode, body2)
	}
}

// === Global/per-VM history listing ===

func TestOperationsList_MemberScoped_NoLeak(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	authorizedVM, planA := e.createDraftPlan(t, adminClient)
	unauthorizedVM, planB := e.createDraftPlan(t, adminClient)
	e.createOperationFixture(t, authorizedVM, planA, "SUCCESS")
	e.createOperationFixture(t, unauthorizedVM, planB, "SUCCESS")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedVM, services.PermVMView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, body := e.get(t, memberClient, "/api/update-operations")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list operations = %d, want 200: %v", resp.StatusCode, body)
	}
	ops, _ := body["operations"].([]any)
	for _, raw := range ops {
		op := raw.(map[string]any)
		if op["vm_id"] == unauthorizedVM.String() {
			t.Errorf("member's operation list leaked an operation for an unauthorized VM: %v", op)
		}
	}
}

func TestOperationsListForVM_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	vm, planID := e.createDraftPlan(t, adminClient)
	e.createOperationFixture(t, vm, planID, "SUCCESS")

	memberEmail, memberPassword, _ := e.createMember(t)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, _ := e.get(t, memberClient, "/api/vms/"+vm.String()+"/update-operations")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unauthorized member list-for-vm = %d, want 404", resp.StatusCode)
	}
}

// === Verify: admin-only, never mutates operations.status ===

func TestOperationVerify_MemberForbidden(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	vm, planID := e.createDraftPlan(t, adminClient)
	opID := e.createOperationFixture(t, vm, planID, "SUCCESS")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	resp, _ := e.do(t, memberClient, http.MethodPost, "/api/update-operations/"+opID.String()+"/verify", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member verify = %d, want 403", resp.StatusCode)
	}
}
