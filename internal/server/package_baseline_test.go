// This file covers the "packages installed since VM onboarding" feature
// (migration 053): the auto-stamp-once semantics of
// SetVMPackageBaselineIfUnset, the admin-only "Reset Baseline to Now"
// endpoint, and the ?new_since_baseline=true list filter. It deliberately
// does not exercise PackageService.Scan's real SSH success path (that
// would need a fake SSH server that speaks a realistic apt/dpkg protocol,
// which nothing in this codebase currently provides) -- instead it seeds
// packages directly via the store, exactly like TestDiscover_Connection-
// Failure_DoesNotErasePriorData seeds discovery data, and drives the
// baseline itself through the real store methods and HTTP endpoint.
package server_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/services"
)

func TestPackageBaseline_AutoStampIsIdempotent(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vm := e.createVM(t, workspace)
	ctx := context.Background()
	vmRow, err := e.store.GetVMByResourceID(ctx, vm)
	if err != nil {
		t.Fatalf("load vm: %v", err)
	}

	if vmRow.PackageBaselineAt.Valid {
		t.Fatal("a freshly created VM must start with no package baseline")
	}

	if err := e.store.SetVMPackageBaselineIfUnset(ctx, vmRow.ID); err != nil {
		t.Fatalf("SetVMPackageBaselineIfUnset (first call): %v", err)
	}
	afterFirst, err := e.store.GetVMByResourceID(ctx, vm)
	if err != nil {
		t.Fatalf("reload vm: %v", err)
	}
	if !afterFirst.PackageBaselineAt.Valid {
		t.Fatal("expected package_baseline_at to be set after the first SetVMPackageBaselineIfUnset call")
	}
	firstStamp := afterFirst.PackageBaselineAt.Time

	time.Sleep(10 * time.Millisecond)
	if err := e.store.SetVMPackageBaselineIfUnset(ctx, vmRow.ID); err != nil {
		t.Fatalf("SetVMPackageBaselineIfUnset (second call): %v", err)
	}
	afterSecond, err := e.store.GetVMByResourceID(ctx, vm)
	if err != nil {
		t.Fatalf("reload vm: %v", err)
	}
	if !afterSecond.PackageBaselineAt.Time.Equal(firstStamp) {
		t.Errorf("package_baseline_at changed on a second call (%v -> %v); the auto-stamp must only ever take effect once", firstStamp, afterSecond.PackageBaselineAt.Time)
	}
}

func TestPackageResetBaseline_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vm := e.createVM(t, workspace)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)
	adminEmail, adminPassword := e.createAdmin(t)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	memberResp, _ := e.do(t, memberClient, http.MethodPut, "/api/vms/"+vm.String()+"/packages/baseline", nil)
	if memberResp.StatusCode != http.StatusForbidden {
		t.Fatalf("member reset baseline = %d, want 403", memberResp.StatusCode)
	}

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	adminResp, adminBody := e.do(t, adminClient, http.MethodPut, "/api/vms/"+vm.String()+"/packages/baseline", nil)
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin reset baseline = %d, want 200", adminResp.StatusCode)
	}
	if adminBody["package_baseline_at"] == nil || adminBody["package_baseline_at"] == "" {
		t.Errorf("expected a non-empty package_baseline_at in the response, got %v", adminBody["package_baseline_at"])
	}
}

func TestPackageResetBaseline_ReflectedInSummaryAndAudited(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vm := e.createVM(t, workspace)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	beforeResp, beforeBody := e.get(t, client, "/api/vms/"+vm.String()+"/packages/summary")
	if beforeResp.StatusCode != http.StatusOK {
		t.Fatalf("summary before reset = %d, want 200", beforeResp.StatusCode)
	}
	if _, present := beforeBody["package_baseline_at"]; present {
		t.Errorf("expected no package_baseline_at before any scan or reset, got %v", beforeBody["package_baseline_at"])
	}

	resetResp, _ := e.do(t, client, http.MethodPut, "/api/vms/"+vm.String()+"/packages/baseline", nil)
	if resetResp.StatusCode != http.StatusOK {
		t.Fatalf("reset baseline = %d, want 200", resetResp.StatusCode)
	}

	afterResp, afterBody := e.get(t, client, "/api/vms/"+vm.String()+"/packages/summary")
	if afterResp.StatusCode != http.StatusOK {
		t.Fatalf("summary after reset = %d, want 200", afterResp.StatusCode)
	}
	if afterBody["package_baseline_at"] == nil || afterBody["package_baseline_at"] == "" {
		t.Error("expected a non-empty package_baseline_at in the summary after reset")
	}

	assertAuditEventExists(t, e, "VM", vm, services.AuditPackageBaselineReset)
}

func TestPackagesList_NewSinceBaselineFilter(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	vm := e.createVM(t, workspace)
	ctx := context.Background()
	vmRow, err := e.store.GetVMByResourceID(ctx, vm)
	if err != nil {
		t.Fatalf("load vm: %v", err)
	}

	// A package that existed before the baseline was set.
	if _, err := e.store.UpsertPackage(ctx, generated.UpsertPackageParams{
		VmID: vmRow.ID, Name: "pre-existing-pkg", InstalledVersion: "1.0", PackageManager: "APT", Architecture: "amd64",
	}); err != nil {
		t.Fatalf("seed pre-existing package: %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	if _, err := e.store.SetVMPackageBaselineNow(ctx, vmRow.ID); err != nil {
		t.Fatalf("set baseline: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	// A package installed after the baseline.
	if _, err := e.store.UpsertPackage(ctx, generated.UpsertPackageParams{
		VmID: vmRow.ID, Name: "new-since-baseline-pkg", InstalledVersion: "2.0", PackageManager: "APT", Architecture: "amd64",
	}); err != nil {
		t.Fatalf("seed new-since-baseline package: %v", err)
	}

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/packages?new_since_baseline=true")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list ?new_since_baseline=true = %d, want 200", resp.StatusCode)
	}
	packages, _ := body["packages"].([]any)
	if len(packages) != 1 {
		t.Fatalf("new_since_baseline packages = %d, want exactly 1", len(packages))
	}
	name, _ := packages[0].(map[string]any)["name"].(string)
	if name != "new-since-baseline-pkg" {
		t.Errorf("new_since_baseline package name = %q, want new-since-baseline-pkg", name)
	}

	allResp, allBody := e.get(t, client, "/api/vms/"+vm.String()+"/packages")
	if allResp.StatusCode != http.StatusOK {
		t.Fatalf("unfiltered list = %d, want 200", allResp.StatusCode)
	}
	allPackages, _ := allBody["packages"].([]any)
	if len(allPackages) != 2 {
		t.Fatalf("unfiltered packages = %d, want 2 (baseline filter must not affect the default list)", len(allPackages))
	}
}
