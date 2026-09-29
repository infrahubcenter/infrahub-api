// This file exercises the Step 9 Update Center HTTP surface: read-only
// OS/kernel/reboot/package-update views (member-scoped, never leaking a
// global count -- spec §46), admin-only update planning end to end
// (create/validate/approve/cancel), server-side target-version resolution
// (spec §25/§30 -- the client never controls what gets stored), the IDOR
// matrix (a package from a different VM must be rejected exactly like one
// that doesn't exist), stale-plan detection (spec §28), and audit
// logging. Like package_test.go/docker_test.go, connection-dependent
// prechecks (VM reachable) were also verified manually against a real
// SSH-reachable Ubuntu VM, documented in the Step 9 delivery summary --
// these tests write package/package_update fixture rows directly into
// the database rather than driving a real package scan.
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

// createPackageWithUpdateFixture inserts a package row plus an active
// package_updates row for it directly (bypassing SSH/discovery),
// returning the package's DB row ID -- ready to be selected into an
// update plan.
func (e *testEnv) createPackageWithUpdateFixture(t *testing.T, vmResourceID uuid.UUID, name, installedVersion, availableVersion string, isSecurity bool) uuid.UUID {
	t.Helper()
	vm, err := e.store.GetVMByResourceID(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("load vm for package fixture: %v", err)
	}
	pkg, err := e.store.UpsertPackage(context.Background(), generated.UpsertPackageParams{
		VmID: vm.ID, Name: name, InstalledVersion: installedVersion, PackageManager: "APT", Architecture: "amd64",
	})
	if err != nil {
		t.Fatalf("create package fixture: %v", err)
	}
	securityStatus := "NOT_SECURITY"
	if isSecurity {
		securityStatus = "CONFIRMED"
	}
	if _, err := e.store.UpsertPackageUpdate(context.Background(), generated.UpsertPackageUpdateParams{
		VmID: vm.ID, PackageID: pkg.ID, CurrentVersion: installedVersion, AvailableVersion: availableVersion,
		Severity: "HIGH", IsSecurityUpdate: isSecurity, SecurityStatus: securityStatus,
	}); err != nil {
		t.Fatalf("create package update fixture: %v", err)
	}
	return pkg.ID
}

func (e *testEnv) setPackageManager(t *testing.T, vmResourceID uuid.UUID, pmType string) {
	t.Helper()
	vm, err := e.store.GetVMByResourceID(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("load vm: %v", err)
	}
	if _, err := e.store.UpdateVMPackageManager(context.Background(), generated.UpdateVMPackageManagerParams{
		ID: vm.ID, PackageManager: pgutil.Text(pmType),
	}); err != nil {
		t.Fatalf("set package manager: %v", err)
	}
}

// === GET /api/updates ===

func TestUpdatesGlobal_MemberSeesOnlyAuthorizedVMs_NoGlobalLeak(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	authorizedVM := e.createVM(t, project)
	unauthorizedVM := e.createVM(t, project)
	e.createPackageWithUpdateFixture(t, authorizedVM, "nginx", "1.24", "1.26", false)
	e.createPackageWithUpdateFixture(t, unauthorizedVM, "openssl", "3.0.13", "3.0.14", true)

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedVM, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/updates")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member GET /api/updates = %d, want 200", resp.StatusCode)
	}
	vms, _ := body["vms"].([]any)
	if len(vms) != 1 {
		t.Fatalf("vms = %v, want exactly 1 (only the authorized VM)", vms)
	}
	first := vms[0].(map[string]any)
	if first["vm_id"] != authorizedVM.String() {
		t.Errorf("vm_id = %v, want %v", first["vm_id"], authorizedVM)
	}
	totals, _ := body["totals"].(map[string]any)
	if totals["package_updates"] != float64(1) {
		t.Errorf("totals.package_updates = %v, want 1 (must never include the unauthorized VM's update)", totals["package_updates"])
	}
	if totals["security_updates"] != float64(0) {
		t.Errorf("totals.security_updates = %v, want 0 (the security update belongs to the unauthorized VM)", totals["security_updates"])
	}
}

func TestUpdatesGlobal_AdminSeesAll(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createPackageWithUpdateFixture(t, vm, "curl", "8.5", "8.6", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/updates")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin GET /api/updates = %d, want 200", resp.StatusCode)
	}
	vms, _ := body["vms"].([]any)
	found := false
	for _, v := range vms {
		if v.(map[string]any)["vm_id"] == vm.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("admin's vms list did not include %v: %v", vm, vms)
	}
}

// === GET /api/vms/:id/updates* ===

func TestVMUpdates_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	for _, path := range []string{"/updates", "/updates/summary", "/updates/security", "/updates/kernel"} {
		resp, _ := e.get(t, client, "/api/vms/"+vm.String()+path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unauthorized member GET .../vms/:id%s = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestVMUpdates_UnknownInitially_NoFakeData(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/updates")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET .../updates = %d, want 200", resp.StatusCode)
	}
	os, _ := body["os"].(map[string]any)
	if os["status"] != "UNKNOWN" {
		t.Errorf("os.status = %v, want UNKNOWN (never scanned yet -- must never fabricate UP_TO_DATE)", os["status"])
	}
	kernel, _ := body["kernel"].(map[string]any)
	if kernel["reboot_required"] != false {
		t.Errorf("kernel.reboot_required = %v, want false when reboot state was never detected", kernel["reboot_required"])
	}
}

func TestVMUpdatesSecurity_SeverityBreakdown(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.createPackageWithUpdateFixture(t, vm, "openssl", "3.0.13", "3.0.14", true)
	e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/updates/security")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET .../updates/security = %d, want 200", resp.StatusCode)
	}
	updates, _ := body["updates"].([]any)
	if len(updates) != 1 {
		t.Fatalf("updates = %v, want exactly 1 (only the security update, not nginx)", updates)
	}
	severity, _ := body["severity"].(map[string]any)
	if severity["high"] != float64(1) {
		t.Errorf("severity.high = %v, want 1", severity["high"])
	}
}

// === POST /api/vms/:id/update-plans ===

func TestCreatePlan_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member create plan = %d, want 403", resp.StatusCode)
	}
}

func TestCreatePlan_Success_TargetVersionResolvedServerSide(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.setPackageManager(t, vm, "APT")
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// The client submits a deliberately wrong target_version -- the
	// backend must ignore it and resolve "1.26" from the database
	// (spec §25/§30: "Do not trust target version from frontend").
	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String(), "target_version": "99.99.99-attacker-supplied"}},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create plan = %d, want 201: %v", resp.StatusCode, body)
	}
	items, _ := body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %v, want 1", items)
	}
	first := items[0].(map[string]any)
	if first["target_version"] != "1.26" {
		t.Errorf("target_version = %v, want 1.26 (the database's own value, never the client-submitted one)", first["target_version"])
	}
	plan, _ := body["plan"].(map[string]any)
	if plan["status"] != "DRAFT" {
		t.Errorf("plan.status = %v, want DRAFT", plan["status"])
	}
}

func TestCreatePlan_PackageFromDifferentVM_Rejected(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmA := e.createVM(t, project)
	vmB := e.createVM(t, project)
	pkgOnB := e.createPackageWithUpdateFixture(t, vmB, "curl", "8.5", "8.6", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// IDOR: VM-A's plan-creation request references a package that
	// genuinely exists, but on VM-B -- must be rejected, not silently
	// accepted or leaking VM-B's package into VM-A's plan.
	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vmA.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgOnB.String()}},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create plan with cross-VM package = %d, want 400 (IDOR): %v", resp.StatusCode, body)
	}
}

func TestCreatePlan_DuplicateItem_Rejected(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}, {"package_id": pkgID.String()}},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create plan with duplicate item = %d, want 400", resp.StatusCode)
	}
}

func TestCreatePlan_UnknownPackage_Rejected(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": uuid.NewString()}},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create plan with unknown package = %d, want 400", resp.StatusCode)
	}
}

func TestCreatePlan_EmptyItems_Rejected(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{"items": []map[string]string{}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create plan with no items = %d, want 400", resp.StatusCode)
	}
}

// === GET /api/update-plans/:id ===

func TestGetPlan_IncludesCommandPreview_NeverExecuted(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	e.setPackageManager(t, vm, "APT")
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}},
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create plan = %d", createResp.StatusCode)
	}
	planID := createBody["plan"].(map[string]any)["id"].(string)

	resp, body := e.get(t, client, "/api/update-plans/"+planID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get plan = %d, want 200", resp.StatusCode)
	}
	cmd, _ := body["proposed_command"].(string)
	if cmd != "apt-get install --only-upgrade nginx" {
		t.Errorf("proposed_command = %q, want the exact preview string", cmd)
	}
	if body["executed"] != false {
		t.Errorf("executed = %v, want false -- this step must never execute anything", body["executed"])
	}
}

func TestGetPlan_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	createResp, createBody := e.do(t, adminClient, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}},
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create plan = %d", createResp.StatusCode)
	}
	planID := createBody["plan"].(map[string]any)["id"].(string)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	resp, _ := e.get(t, memberClient, "/api/update-plans/"+planID)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member get plan = %d, want 403 (update planning is admin-only end to end)", resp.StatusCode)
	}
}

// === POST /api/update-plans/:id/validate, /approve, /cancel ===

func TestValidatePlan_ReportsFailedChecks_NeverMutatesStatus(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project) // no SSH credential configured
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}},
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create plan = %d", createResp.StatusCode)
	}
	planID := createBody["plan"].(map[string]any)["id"].(string)

	resp, body := e.do(t, client, http.MethodPost, "/api/update-plans/"+planID+"/validate", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("validate plan = %d, want 200", resp.StatusCode)
	}
	if body["all_passed"] != false {
		t.Errorf("all_passed = %v, want false (no SSH credential configured)", body["all_passed"])
	}

	// Validate is a pure diagnostic -- the plan must still be DRAFT.
	planResp, planBody := e.get(t, client, "/api/update-plans/"+planID)
	if planResp.StatusCode != http.StatusOK {
		t.Fatalf("get plan = %d", planResp.StatusCode)
	}
	if planBody["plan"].(map[string]any)["status"] != "DRAFT" {
		t.Errorf("plan status after validate = %v, want DRAFT (validate must never mutate status)", planBody["plan"].(map[string]any)["status"])
	}
}

func TestApprovePlan_FailsChecks_StaysDraft(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project) // no SSH credential -> approval must fail
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}},
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create plan = %d", createResp.StatusCode)
	}
	planID := createBody["plan"].(map[string]any)["id"].(string)

	resp, _ := e.do(t, client, http.MethodPost, "/api/update-plans/"+planID+"/approve", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("approve plan with failing checks = %d, want 409", resp.StatusCode)
	}

	planResp, planBody := e.get(t, client, "/api/update-plans/"+planID)
	if planResp.StatusCode != http.StatusOK {
		t.Fatalf("get plan = %d", planResp.StatusCode)
	}
	if planBody["plan"].(map[string]any)["status"] != "DRAFT" {
		t.Errorf("plan status = %v, want DRAFT (a failed approval must never transition the plan)", planBody["plan"].(map[string]any)["status"])
	}
}

func TestApprovePlan_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	createResp, createBody := e.do(t, adminClient, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}},
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create plan = %d", createResp.StatusCode)
	}
	planID := createBody["plan"].(map[string]any)["id"].(string)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	resp, _ := e.do(t, memberClient, http.MethodPost, "/api/update-plans/"+planID+"/approve", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member approve plan = %d, want 403", resp.StatusCode)
	}
}

func TestCancelPlan_DraftToCancelled_ThenTerminalRejected(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}},
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create plan = %d", createResp.StatusCode)
	}
	planID := createBody["plan"].(map[string]any)["id"].(string)

	resp, body := e.do(t, client, http.MethodPost, "/api/update-plans/"+planID+"/cancel", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel plan = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "CANCELLED" {
		t.Errorf("status = %v, want CANCELLED", body["status"])
	}

	// #23: Step 9 never transitions a plan to EXECUTING/COMPLETED/FAILED --
	// cancelling an already-terminal plan must be rejected, not silently
	// re-accepted.
	secondResp, _ := e.do(t, client, http.MethodPost, "/api/update-plans/"+planID+"/cancel", nil)
	if secondResp.StatusCode != http.StatusConflict {
		t.Fatalf("cancel an already-cancelled plan = %d, want 409", secondResp.StatusCode)
	}
}

// === Stale plan detection (spec #28) ===

func TestValidatePlan_DetectsStaleWhenAvailableVersionChanges(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}},
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create plan = %d", createResp.StatusCode)
	}
	planID := createBody["plan"].(map[string]any)["id"].(string)

	// A later package scan discovers a newer version than what the plan
	// snapshotted (spec #28's exact example: nginx 1.26.2 while the plan
	// still says 1.26.1 -- here 1.27 vs the plan's 1.26).
	e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.27", false)

	resp, body := e.do(t, client, http.MethodPost, "/api/update-plans/"+planID+"/validate", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("validate plan = %d, want 200", resp.StatusCode)
	}
	if body["stale"] != true {
		t.Errorf("stale = %v, want true (the available version changed since plan creation)", body["stale"])
	}
}

// === POST /api/vms/:id/updates/refresh, /precheck ===

func TestRefreshUpdates_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/updates/refresh", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member refresh updates = %d, want 403", resp.StatusCode)
	}
}

func TestPrecheck_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/updates/precheck", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member precheck = %d, want 403", resp.StatusCode)
	}
}

// === Audit logging (spec #54/#55) ===

func TestUpdatePlan_AuditEventsRecorded_NoSecrets(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	pkgID := e.createPackageWithUpdateFixture(t, vm, "nginx", "1.24", "1.26", false)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/update-plans", map[string]any{
		"items": []map[string]string{{"package_id": pkgID.String()}},
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create plan = %d", createResp.StatusCode)
	}
	planID := createBody["plan"].(map[string]any)["id"].(string)

	cancelResp, _ := e.do(t, client, http.MethodPost, "/api/update-plans/"+planID+"/cancel", nil)
	if cancelResp.StatusCode != http.StatusOK {
		t.Fatalf("cancel plan = %d", cancelResp.StatusCode)
	}

	assertAuditEventExists(t, e, "VM", vm, services.AuditUpdatePlanCreated)
	assertAuditEventExists(t, e, "VM", vm, services.AuditUpdatePlanCancelled)

	logs, err := e.store.ListAuditLogsByResource(context.Background(), generated.ListAuditLogsByResourceParams{
		ResourceID: pgutil.NullUUID(&vm), Limit: 20,
	})
	if err != nil {
		t.Fatalf("query audit logs: %v", err)
	}
	for _, l := range logs {
		if l.Action != services.AuditUpdatePlanCreated && l.Action != services.AuditUpdatePlanCancelled {
			continue
		}
		metadata := string(l.Metadata)
		for _, secret := range []string{"BEGIN OPENSSH PRIVATE KEY", "password", "target_version"} {
			if contains(metadata, secret) {
				t.Errorf("audit metadata for %s contains %q, must never log secrets or raw client input: %s", l.Action, secret, metadata)
			}
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
