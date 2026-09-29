// This file exercises the Step 7 package inventory/update HTTP surface:
// IDOR protection on the member-readable GET endpoints, admin-only
// scan/refresh/acknowledge/dismiss, the manual-trigger rate limit, "no
// fake data" (an unscanned VM reports an empty/zero inventory, never
// fabricated packages), audit events, and the cross-VM recommendations
// dashboard's per-role scoping (spec §39). Like ssh_test.go/monitoring_test.go,
// connection-dependent cases point at a deterministically unreachable
// loopback port; the real end-to-end happy path (actual dpkg-query/rpm
// output, actual version comparison against a live APT VM) was verified
// manually, documented in the Step 7 delivery summary.
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

// === GET /packages ===

func TestPackages_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/packages")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member packages list = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

func TestPackages_AuthorizedMember_EmptyInitially(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/packages")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member packages list = %d, want 200", resp.StatusCode)
	}
	pkgs, _ := body["packages"].([]any)
	if len(pkgs) != 0 {
		t.Errorf("packages = %v, want empty (no scan has ever run -- must never fabricate data)", pkgs)
	}
	if body["total"] != float64(0) {
		t.Errorf("total = %v, want 0", body["total"])
	}
}

func TestPackagesSummary_EmptyInitially(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/packages/summary")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("packages summary = %d, want 200", resp.StatusCode)
	}
	for _, field := range []string{"total", "up_to_date", "updates_available", "security_updates"} {
		if body[field] != float64(0) {
			t.Errorf("%s = %v, want 0", field, body[field])
		}
	}
	if _, present := body["last_scan"]; present {
		t.Error("last_scan should be absent when no scan has ever run")
	}
}

func TestPackagesDiscoveryStatus_EmptyInitially(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/vms/"+vm.String()+"/packages/discovery-status")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery-status = %d, want 200", resp.StatusCode)
	}
	runs, _ := body["runs"].([]any)
	if len(runs) != 0 {
		t.Errorf("runs = %v, want empty", runs)
	}
}

func TestPackagesUpdates_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vm.String()+"/packages/updates")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member packages/updates = %d, want 404", resp.StatusCode)
	}
}

// === POST /packages/scan, /packages/refresh ===

func TestPackageScan_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/scan", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member scan = %d, want 403", resp.StatusCode)
	}
}

func TestPackageRefresh_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/refresh", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member refresh = %d, want 403", resp.StatusCode)
	}
}

func TestPackageScan_NotConfigured_ReturnsFailedNotError(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/scan", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scan with no credential = %d, want 200 (operation endpoint; failure conveyed in body)", resp.StatusCode)
	}
	if body["status"] != "FAILED" {
		t.Errorf("status = %v, want FAILED", body["status"])
	}
}

func TestPackageScan_ConnectionRefused_NoPackagesFabricated(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, key)

	resp, body := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/scan", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scan = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "FAILED" {
		t.Fatalf("status = %v, want FAILED", body["status"])
	}

	listResp, listBody := e.get(t, client, "/api/vms/"+vm.String()+"/packages")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("packages list after failed scan = %d, want 200", listResp.StatusCode)
	}
	pkgs, _ := listBody["packages"].([]any)
	if len(pkgs) != 0 {
		t.Errorf("packages = %v, want empty -- a failed scan must never fabricate inventory", pkgs)
	}
}

func TestPackageScan_RateLimited(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, key)

	first, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/scan", nil)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first scan = %d, want 200", first.StatusCode)
	}
	second, secondBody := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/scan", nil)
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("immediate second scan = %d, want 429 (spec §23: overlapping/rapid scans must be prevented)", second.StatusCode)
	}
	if secondBody["error"] == nil {
		t.Error("expected an error message on the rate-limited response")
	}
}

func TestPackageScan_NotFoundVM(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+uuid.NewString()+"/packages/scan", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("scan on a nonexistent VM = %d, want 404", resp.StatusCode)
	}
}

func TestAudit_PackageScanEventsRecorded(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, key)
	e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/scan", nil)

	assertAuditEventExists(t, e, "VM", vm, services.AuditPackageScanStarted)
	assertAuditEventExists(t, e, "VM", vm, services.AuditPackageScanFailed)
}

// === Acknowledge / Dismiss ===

func TestPackageAcknowledge_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vm, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/"+uuid.NewString()+"/acknowledge", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member acknowledge = %d, want 403", resp.StatusCode)
	}
}

func TestPackageDismiss_NoActiveUpdate_BadRequest(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVMWithAddress(t, project, "127.0.0.1", 1)
	adminEmail, adminPassword := e.createAdmin(t)
	key, _ := generateTestSSHKeyPEM(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)
	e.attachSSHKeyCredential(t, project, vm, key)
	// Seed a package with no active update directly (bypassing a real scan,
	// which would require a reachable VM).
	pkg := e.createPackageFixture(t, vm, "nginx", "1.24.0")

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/"+pkg.String()+"/dismiss", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("dismiss with no active update = %d, want 400", resp.StatusCode)
	}
}

// TestPackageAcknowledge_DoesNotResolveLinkedRecommendation is a
// regression test: acknowledging (or dismissing) a package update must
// set its linked recommendation to the SAME status (ACKNOWLEDGED), never
// silently flip it to RESOLVED -- RESOLVED is reserved for the automatic
// scan-sync path when the underlying update actually disappears.
func TestPackageAcknowledge_DoesNotResolveLinkedRecommendation(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	packageID := e.createPackageFixture(t, vm, "nginx", "1.24.0")
	updateID := e.createPackageUpdateFixture(t, vm, packageID, "1.24.0", "1.26.2")
	e.createRecommendationFixtureWithSource(t, vm, "nginx update available", updateID)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/"+packageID.String()+"/acknowledge", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acknowledge = %d, want 200", resp.StatusCode)
	}

	status := e.recommendationStatusBySource(t, updateID)
	if status != "ACKNOWLEDGED" {
		t.Errorf("linked recommendation status = %q, want ACKNOWLEDGED (must not be silently resolved)", status)
	}
}

func TestPackageDismiss_SetsLinkedRecommendationDismissed(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	packageID := e.createPackageFixture(t, vm, "openssl", "3.0.13")
	updateID := e.createPackageUpdateFixture(t, vm, packageID, "3.0.13", "3.0.14")
	e.createRecommendationFixtureWithSource(t, vm, "openssl update available", updateID)

	resp, _ := e.do(t, client, http.MethodPost, "/api/vms/"+vm.String()+"/packages/"+packageID.String()+"/dismiss", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dismiss = %d, want 200", resp.StatusCode)
	}

	status := e.recommendationStatusBySource(t, updateID)
	if status != "DISMISSED" {
		t.Errorf("linked recommendation status = %q, want DISMISSED", status)
	}
}

// === Cross-VM /recommendations dashboard (spec §38-39) ===

func TestRecommendations_MemberSeesOnlyAuthorizedVMs(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	authorizedVM := e.createVM(t, project)
	unauthorizedVM := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedVM, services.PermVMView)

	e.createRecommendationFixture(t, authorizedVM, "nginx update available")
	e.createRecommendationFixture(t, unauthorizedVM, "openssl update available")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/recommendations")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member recommendations = %d, want 200", resp.StatusCode)
	}
	items, _ := body["recommendations"].([]any)
	if len(items) != 1 {
		t.Fatalf("got %d recommendations, want 1 (only the authorized VM's)", len(items))
	}
	first := items[0].(map[string]any)
	if first["resource_id"] != authorizedVM.String() {
		t.Errorf("recommendation resource_id = %v, want %v", first["resource_id"], authorizedVM)
	}
	if body["total"] != float64(1) {
		t.Errorf("total = %v, want 1 (member must never see the global count -- spec §39)", body["total"])
	}
}

func TestRecommendations_AdminSeesAll(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmA := e.createVM(t, project)
	vmB := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	e.createRecommendationFixture(t, vmA, "nginx update available")
	e.createRecommendationFixture(t, vmB, "openssl update available")

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/recommendations")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin recommendations = %d, want 200", resp.StatusCode)
	}
	items, _ := body["recommendations"].([]any)
	if len(items) < 2 {
		t.Fatalf("got %d recommendations, want at least 2 (admin sees everything)", len(items))
	}
}

// TestRecommendations_MemberSeesAuthorizedObjectStorage is the direct
// regression test for the Object Storage authorization gap (Phase 0):
// RecommendationHandler.List's authorization merge only ever consulted
// VM and database access before this fix, so a Member with legitimate
// object_storage.view access on a resource could never see a
// recommendation pointed at it. Mirrors
// TestRecommendations_MemberSeesOnlyAuthorizedVMs's shape exactly, but
// for an OBJECT_STORAGE resource instead of a VM.
func TestRecommendations_MemberSeesAuthorizedObjectStorage(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, authorizedStorage := e.createObjectStorageFixture(t, project)
	_, unauthorizedStorage := e.createObjectStorageFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedStorage, services.PermObjectStorageView)

	e.createRecommendationFixture(t, authorizedStorage, "object storage growth high")
	e.createRecommendationFixture(t, unauthorizedStorage, "object storage growth high")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/recommendations")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member recommendations = %d, want 200", resp.StatusCode)
	}
	items, _ := body["recommendations"].([]any)
	if len(items) != 1 {
		t.Fatalf("got %d recommendations, want 1 (only the authorized object storage's -- this is the Object Storage authorization gap regression)", len(items))
	}
	first := items[0].(map[string]any)
	if first["resource_id"] != authorizedStorage.String() {
		t.Errorf("recommendation resource_id = %v, want %v", first["resource_id"], authorizedStorage)
	}
	if body["total"] != float64(1) {
		t.Errorf("total = %v, want 1 (member must never see the global count -- spec §39)", body["total"])
	}
}

func TestRecommendations_MemberNoAccess_Empty(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	e.createRecommendationFixture(t, vm, "nginx update available")

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/recommendations")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("recommendations = %d, want 200", resp.StatusCode)
	}
	items, _ := body["recommendations"].([]any)
	if len(items) != 0 {
		t.Errorf("got %d recommendations, want 0 (member has no VM access at all)", len(items))
	}
}

// TestRecommendations_SeverityFilter is Step 19 Phase 4's direct
// regression test: GET /api/recommendations?severity=HIGH must return only
// HIGH-severity recommendations, following the identical optional-narg
// pattern the existing type/status params already use.
func TestRecommendations_SeverityFilter(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	e.createRecommendationFixtureWithSeverity(t, vm, "nginx update available", "HIGH")
	e.createRecommendationFixtureWithSeverity(t, vm, "openssl update available", "LOW")

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// Scoped to this test's own VM via resource_id -- this suite runs
	// against a real, shared, cumulative Postgres database (see
	// monitoring_dashboard_test.go's own note on this), and other tests
	// create their own HIGH-severity recommendations on other VMs, so an
	// unscoped severity=HIGH query would non-deterministically count every
	// HIGH recommendation ever created in the whole database, not just this
	// test's two fixtures.
	resp, body := e.get(t, client, "/api/recommendations?severity=HIGH&resource_id="+vm.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("severity-filtered recommendations = %d, want 200", resp.StatusCode)
	}
	items, _ := body["recommendations"].([]any)
	if len(items) != 1 {
		t.Fatalf("got %d recommendations for severity=HIGH, want exactly 1", len(items))
	}
	first := items[0].(map[string]any)
	if first["severity"] != "HIGH" {
		t.Errorf("recommendation severity = %v, want HIGH", first["severity"])
	}
	if first["title"] != "nginx update available" {
		t.Errorf("recommendation title = %v, want the HIGH-severity fixture's title", first["title"])
	}
	if body["total"] != float64(1) {
		t.Errorf("total = %v, want 1", body["total"])
	}
}

// --- fixtures ---

func (e *testEnv) createPackageFixture(t *testing.T, vmResourceID uuid.UUID, name, version string) uuid.UUID {
	t.Helper()
	vm, err := e.store.GetVMByResourceID(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("load vm for package fixture: %v", err)
	}
	row, err := e.store.UpsertPackage(context.Background(), generated.UpsertPackageParams{
		VmID: vm.ID, Name: name, InstalledVersion: version, PackageManager: "APT", Architecture: "amd64",
	})
	if err != nil {
		t.Fatalf("create package fixture: %v", err)
	}
	return row.ID
}

func (e *testEnv) createRecommendationFixture(t *testing.T, vmResourceID uuid.UUID, title string) uuid.UUID {
	t.Helper()
	return e.createRecommendationFixtureWithSeverity(t, vmResourceID, title, "MEDIUM")
}

// createRecommendationFixtureWithSeverity is createRecommendationFixture
// with an explicit severity, for the Step 19 Phase 4 ?severity= filter
// test, which needs two recommendations at two different severities.
func (e *testEnv) createRecommendationFixtureWithSeverity(t *testing.T, vmResourceID uuid.UUID, title, severity string) uuid.UUID {
	t.Helper()
	row, err := e.store.CreateRecommendation(context.Background(), generated.CreateRecommendationParams{
		ResourceID: vmResourceID, Type: "PACKAGE_UPDATE", Severity: severity, Title: title, Metadata: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("create recommendation fixture: %v", err)
	}
	return row.ID
}

func (e *testEnv) createPackageUpdateFixture(t *testing.T, vmResourceID, packageID uuid.UUID, current, available string) uuid.UUID {
	t.Helper()
	vm, err := e.store.GetVMByResourceID(context.Background(), vmResourceID)
	if err != nil {
		t.Fatalf("load vm for package update fixture: %v", err)
	}
	row, err := e.store.UpsertPackageUpdate(context.Background(), generated.UpsertPackageUpdateParams{
		VmID: vm.ID, PackageID: packageID, CurrentVersion: current, AvailableVersion: available,
		Severity: "HIGH", IsSecurityUpdate: true, SecurityStatus: "CONFIRMED",
	})
	if err != nil {
		t.Fatalf("create package update fixture: %v", err)
	}
	return row.ID
}

func (e *testEnv) createRecommendationFixtureWithSource(t *testing.T, vmResourceID uuid.UUID, title string, sourceID uuid.UUID) uuid.UUID {
	t.Helper()
	row, err := e.store.UpsertRecommendationBySource(context.Background(), generated.UpsertRecommendationBySourceParams{
		ResourceID: vmResourceID, Type: "PACKAGE_UPDATE", Severity: "HIGH", Title: title, Metadata: []byte("{}"),
		SourceType: pgutil.Text("package_update"), SourceID: pgutil.NullUUID(&sourceID),
	})
	if err != nil {
		t.Fatalf("create recommendation-with-source fixture: %v", err)
	}
	return row.ID
}

func (e *testEnv) recommendationStatusBySource(t *testing.T, sourceID uuid.UUID) string {
	t.Helper()
	rows, err := e.store.ListRecommendationsFiltered(context.Background(), generated.ListRecommendationsFilteredParams{Limit: 200})
	if err != nil {
		t.Fatalf("list recommendations: %v", err)
	}
	for _, r := range rows {
		if r.SourceID.Valid && pgutil.UUID(r.SourceID) == sourceID {
			return r.Status
		}
	}
	t.Fatalf("no recommendation found for source id %s", sourceID)
	return ""
}
