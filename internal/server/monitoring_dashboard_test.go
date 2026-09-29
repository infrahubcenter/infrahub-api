// This file exercises Step 19 Phase 2's central monitoring dashboard:
// GET /api/monitoring/overview and GET /api/monitoring/resources. Both
// endpoints reuse the exact same authorization building blocks
// GET /api/my-access already uses (h.vms.List, scopedDatabaseAccess,
// scopedObjectStorageAccess), so the Member-vs-Admin scoping assertions
// here mirror my_access_extended_test.go's/object_storage_summary_test.go's
// own shape -- an unauthorized resource must never contribute to a count
// or appear in a list, and (since neither endpoint uses a status code to
// signal denial -- both are `authenticated`, any role) that absence must
// be asserted directly against the response body, not a status code.
//
// The dashboard's own /api/monitoring/overview?project_id= filter is used
// throughout to get exact (not just ">=") assertions on Admin's otherwise-
// global counts, since this suite runs against a real, shared, cumulative
// Postgres database (object_storage_summary_test.go's own tests document
// this same constraint and fall back to ">=" where no such per-project
// scoping is available -- here it is, so exact equality is used instead).
package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// installDockerFixture marks vmResourceID's VM as having Docker installed
// (mirrors how a real discovery scan would set docker_installed via
// UpdateVMDiscoveryResult) -- required for the docker bucket's "hosts"
// count, independent of whether the VM has any container fixture rows.
func (e *testEnv) installDockerFixture(t *testing.T, vmResourceID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	vm, err := e.store.GetVMByResourceID(ctx, vmResourceID)
	if err != nil {
		t.Fatalf("load vm for docker-install fixture: %v", err)
	}
	if _, err := e.store.UpdateVMDiscoveryResult(ctx, generated.UpdateVMDiscoveryResultParams{
		ID: vm.ID, DockerInstalled: pgutil.Bool(true),
	}); err != nil {
		t.Fatalf("install docker fixture: %v", err)
	}
}

// === GET /api/monitoring/overview ===

func TestMonitoringOverview_MemberScopedToAuthorizedResourcesOnly(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.createDatabaseFixture(t, project)
	e.createObjectStorageFixture(t, project)

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmResource, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/monitoring/overview?project_id="+project.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview status = %d, want 200", resp.StatusCode)
	}
	vms, _ := body["vms"].(map[string]any)
	if vms["total"].(float64) != 1 {
		t.Errorf("member vms.total = %v, want 1 (only the directly-granted VM)", vms["total"])
	}
	databases, _ := body["databases"].(map[string]any)
	if databases["total"].(float64) != 0 {
		t.Errorf("member databases.total = %v, want 0 (no database access granted)", databases["total"])
	}
	objectStorage, _ := body["object_storage"].(map[string]any)
	if objectStorage["total"].(float64) != 0 {
		t.Errorf("member object_storage.total = %v, want 0 (no object storage access granted)", objectStorage["total"])
	}

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	adminResp, adminBody := e.get(t, adminClient, "/api/monitoring/overview?project_id="+project.String())
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin overview status = %d, want 200", adminResp.StatusCode)
	}
	adminVMs, _ := adminBody["vms"].(map[string]any)
	if adminVMs["total"].(float64) != 1 {
		t.Errorf("admin vms.total = %v, want 1", adminVMs["total"])
	}
	adminDBs, _ := adminBody["databases"].(map[string]any)
	if adminDBs["total"].(float64) != 1 {
		t.Errorf("admin databases.total = %v, want 1 (Admin sees every resource, no grant needed)", adminDBs["total"])
	}
	adminOS, _ := adminBody["object_storage"].(map[string]any)
	if adminOS["total"].(float64) != 1 {
		t.Errorf("admin object_storage.total = %v, want 1 (Admin sees every resource, no grant needed)", adminOS["total"])
	}
}

// TestMonitoringOverview_ObjectStorageAlertsAndRecommendationsIncludedForAuthorizedMember
// is a direct regression test locking in Phase 0's Object Storage alerts/
// recommendations fix within this new endpoint specifically: a Member
// granted only Object Storage access must see that resource's alert and
// recommendation counted in Overview's Alerts/Recommendations buckets --
// before Phase 0's fix, GetUserAlertAccessResourceIDs never consulted
// Object Storage access at all, so both buckets would have silently read
// zero for this exact scenario.
func TestMonitoringOverview_ObjectStorageAlertsAndRecommendationsIncludedForAuthorizedMember(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, osResource := e.createObjectStorageFixture(t, project)

	ctx := context.Background()
	// Simulate a fast-cycle result classifying the bucket as unreachable --
	// mirrors TestAlertEngine_ObjectStorageUnavailable_TriggersImmediately's
	// own fixture shape exactly (object_storage_test.go).
	if _, err := e.store.UpdateObjectStorageConnectionStatus(ctx, generated.UpdateObjectStorageConnectionStatusParams{
		ID: osID, ConnectionStatus: "UNAVAILABLE", HealthStatus: "CRITICAL",
	}); err != nil {
		t.Fatalf("seed connection status: %v", err)
	}
	e.createAlertRuleFixture(t, osResource, services.AlertTypeObjectStorageUnavailable, 0, 0)
	e.alertEngine.EvaluateOnce(ctx)
	e.createRecommendationFixture(t, osResource, "Object storage needs attention")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, osResource, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/monitoring/overview?project_id="+project.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview status = %d, want 200", resp.StatusCode)
	}

	alerts, _ := body["alerts"].(map[string]any)
	if alerts["active"].(float64) != 1 {
		t.Fatalf("member alerts.active = %v, want 1 (Object Storage access must count its own alert, Phase 0 regression)", alerts["active"])
	}

	recommendations, _ := body["recommendations"].(map[string]any)
	if recommendations["total"].(float64) != 1 {
		t.Fatalf("member recommendations.total = %v, want 1 (Object Storage access must count its own recommendation, Phase 0 regression)", recommendations["total"])
	}
	if recommendations["new"].(float64) != 1 {
		t.Errorf("member recommendations.new = %v, want 1", recommendations["new"])
	}
}

func TestMonitoringOverview_AdminSeesGlobalUnrestrictedCounts(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	e.createVM(t, project)
	e.createDatabaseFixture(t, project)
	e.createObjectStorageFixture(t, project)

	// No grants at all -- Admin must still see every resource in this
	// project, the same "Admin bypasses explicit grants" behavior every
	// other authorization path in this project already has.
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/monitoring/overview?project_id="+project.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin overview status = %d, want 200", resp.StatusCode)
	}
	vms, _ := body["vms"].(map[string]any)
	if vms["total"].(float64) != 1 {
		t.Errorf("admin vms.total = %v, want 1", vms["total"])
	}
	databases, _ := body["databases"].(map[string]any)
	if databases["total"].(float64) != 1 {
		t.Errorf("admin databases.total = %v, want 1", databases["total"])
	}
	objectStorage, _ := body["object_storage"].(map[string]any)
	if objectStorage["total"].(float64) != 1 {
		t.Errorf("admin object_storage.total = %v, want 1", objectStorage["total"])
	}
	// Step 19 Phase 3: the docker bucket is now real (GetDockerSummaryAcrossVMs
	// wired into Overview), scoped by the same ?project_id= filter as every
	// other bucket above -- the project's one VM was created via createVM,
	// which never sets docker_installed, so every count here must be exactly
	// 0, never a fabricated non-zero placeholder.
	docker, ok := body["docker"].(map[string]any)
	if !ok {
		t.Fatalf("admin overview missing %q bucket, want it present now that Phase 3 is built: %v", "docker", body)
	}
	for _, field := range []string{"hosts", "containers_total", "containers_running", "containers_stopped", "containers_unhealthy", "images_total"} {
		if docker[field] != float64(0) {
			t.Errorf("admin docker.%s = %v, want 0 (project's one VM never had docker_installed set)", field, docker[field])
		}
	}
}

// TestMonitoringOverview_DockerBucketScopedToAuthorizedVMs is Step 19
// Phase 3's direct regression test: two VMs in the same project both have
// Docker installed and containers discovered, but the Member is only
// granted access to one of them. The docker bucket must reflect only the
// authorized VM's hosts/containers for the Member, and the full set for
// Admin -- exactly the same authorized-resource-ID scoping every other
// Overview bucket already gets, now extended to Docker.
func TestMonitoringOverview_DockerBucketScopedToAuthorizedVMs(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	authorizedVM := e.createVM(t, project)
	unauthorizedVM := e.createVM(t, project)

	e.installDockerFixture(t, authorizedVM)
	e.installDockerFixture(t, unauthorizedVM)
	e.createDockerContainerFixture(t, authorizedVM, "web-1", "authorized-container-1")
	e.createDockerContainerFixture(t, authorizedVM, "web-2", "authorized-container-2")
	e.createDockerContainerFixture(t, unauthorizedVM, "web-3", "unauthorized-container-1")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedVM, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/monitoring/overview?project_id="+project.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member overview status = %d, want 200", resp.StatusCode)
	}
	memberDocker, _ := body["docker"].(map[string]any)
	if memberDocker["hosts"].(float64) != 1 {
		t.Errorf("member docker.hosts = %v, want 1 (only the authorized VM)", memberDocker["hosts"])
	}
	if memberDocker["containers_total"].(float64) != 2 {
		t.Errorf("member docker.containers_total = %v, want 2 (only the authorized VM's containers)", memberDocker["containers_total"])
	}
	if memberDocker["containers_running"].(float64) != 2 {
		t.Errorf("member docker.containers_running = %v, want 2", memberDocker["containers_running"])
	}

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	adminResp, adminBody := e.get(t, adminClient, "/api/monitoring/overview?project_id="+project.String())
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin overview status = %d, want 200", adminResp.StatusCode)
	}
	adminDocker, _ := adminBody["docker"].(map[string]any)
	if adminDocker["hosts"].(float64) != 2 {
		t.Errorf("admin docker.hosts = %v, want 2 (both VMs, no grant needed)", adminDocker["hosts"])
	}
	if adminDocker["containers_total"].(float64) != 3 {
		t.Errorf("admin docker.containers_total = %v, want 3 (both VMs' containers)", adminDocker["containers_total"])
	}

	// List-shaped IDOR: the unauthorized VM's container name/id must never
	// appear anywhere in the Member's raw response body -- the docker
	// bucket is summary-only (counts, not a resource list), but confirm
	// this explicitly rather than assuming it from the shape alone.
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshal member response body: %v", err)
	}
	if strings.Contains(string(raw), "unauthorized-container-1") {
		t.Errorf("member response body leaked the unauthorized VM's container: %s", raw)
	}
}

// === GET /api/monitoring/resources ===

func TestMonitoringResources_FiltersAppliedServerSideNotClientSide(t *testing.T) {
	e := setup(t)
	projectA := e.createWorkspace(t)
	projectB := e.createWorkspace(t)
	vmA := e.createVM(t, projectA)
	vmB := e.createVM(t, projectB)

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmA, services.PermVMView)
	e.grantDirectVMAccess(t, memberID, vmB, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	// Unfiltered: both authorized VMs are visible.
	allResp, allBody := e.get(t, client, "/api/monitoring/resources")
	if allResp.StatusCode != http.StatusOK {
		t.Fatalf("resources status = %d, want 200", allResp.StatusCode)
	}
	allResources, _ := allBody["resources"].([]any)
	if len(allResources) != 2 {
		t.Fatalf("unfiltered resources = %d, want 2 (both authorized VMs)", len(allResources))
	}

	// project_id=projectA must narrow to exactly vmA -- never widen past
	// what the caller is authorized for, and never include vmB.
	filteredResp, filteredBody := e.get(t, client, "/api/monitoring/resources?project_id="+projectA.String())
	if filteredResp.StatusCode != http.StatusOK {
		t.Fatalf("filtered resources status = %d, want 200", filteredResp.StatusCode)
	}
	filtered, _ := filteredBody["resources"].([]any)
	if len(filtered) != 1 {
		t.Fatalf("project_id-filtered resources = %d, want exactly 1", len(filtered))
	}
	first := filtered[0].(map[string]any)
	if first["id"] != vmA.String() {
		t.Errorf("filtered resource id = %v, want %v", first["id"], vmA)
	}
	if filteredBody["total"].(float64) != 1 {
		t.Errorf("filtered total = %v, want 1", filteredBody["total"])
	}

	// A project the member has no authorized resource in at all must never
	// "fall back" to the unfiltered set -- it must narrow to nothing.
	otherProject := e.createWorkspace(t)
	emptyResp, emptyBody := e.get(t, client, "/api/monitoring/resources?project_id="+otherProject.String())
	if emptyResp.StatusCode != http.StatusOK {
		t.Fatalf("empty-project resources status = %d, want 200", emptyResp.StatusCode)
	}
	emptyResources, _ := emptyBody["resources"].([]any)
	if len(emptyResources) != 0 {
		t.Fatalf("resources filtered to an unrelated project = %d, want 0 (never widen)", len(emptyResources))
	}
}

func TestMonitoringResources_MemberNeverSeesUnauthorizedResource(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	authorizedVM := e.createVM(t, project)
	unauthorizedVM := e.createVM(t, project)

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedVM, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/monitoring/resources?project_id="+project.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resources status = %d, want 200", resp.StatusCode)
	}
	resources, _ := body["resources"].([]any)
	if len(resources) != 1 {
		t.Fatalf("member resources = %d, want exactly 1 (the authorized VM)", len(resources))
	}
	first := resources[0].(map[string]any)
	if first["id"] != authorizedVM.String() {
		t.Errorf("visible resource id = %v, want %v", first["id"], authorizedVM)
	}

	// List-shaped IDOR: assert the unauthorized VM's ID never appears
	// ANYWHERE in the raw response body (not merely absent from the top-
	// level list), regardless of status code -- this endpoint always
	// returns 200 for any authenticated caller, so a status code can never
	// be the signal here.
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshal response body: %v", err)
	}
	if strings.Contains(string(raw), unauthorizedVM.String()) {
		t.Errorf("response body leaked the unauthorized VM's id %q: %s", unauthorizedVM, raw)
	}
}

func TestMonitoringResources_AdminSeesGlobalUnrestrictedCounts(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vm := e.createVM(t, project)

	// No grants at all -- Admin must still see it.
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/monitoring/resources?project_id="+project.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin resources status = %d, want 200", resp.StatusCode)
	}
	resources, _ := body["resources"].([]any)
	if len(resources) != 1 {
		t.Fatalf("admin resources = %d, want exactly 1", len(resources))
	}
	if resources[0].(map[string]any)["id"] != vm.String() {
		t.Errorf("admin resource id = %v, want %v", resources[0].(map[string]any)["id"], vm)
	}
}

// === GET /api/monitoring/timeline ===

// createAlertFixture inserts one alert row directly (via a real alert
// rule fixture for the AlertRuleID foreign key, then store.CreateAlert
// itself) rather than driving the full AlertEngine.EvaluateOnce cycle --
// Timeline's own tests only need a real, resource-scoped alert row with
// controllable severity/title, not a faithful metric-breach simulation
// (that path is already covered by alerts_test.go). Returns the created
// alert's id.
func (e *testEnv) createAlertFixture(t *testing.T, workspaceID, resourceID uuid.UUID, alertType services.AlertType, severity, title string) uuid.UUID {
	t.Helper()
	ruleID := e.createAlertRuleFixture(t, resourceID, alertType, 0, 0)
	alert, err := e.store.CreateAlert(context.Background(), generated.CreateAlertParams{
		AlertRuleID: ruleID, ResourceID: resourceID, WorkspaceID: pgutil.NullUUID(&workspaceID),
		AlertType: string(alertType), Severity: severity, Metric: "test_metric",
		CurrentValue: pgutil.Float8(1), Threshold: 0, Title: title,
	})
	if err != nil {
		t.Fatalf("create alert fixture: %v", err)
	}
	return alert.ID
}

// TestMonitoringTimeline_ScopedToAuthorizedResources is Timeline's own
// IDOR regression test, mirroring Overview's/Resources'
// MemberScopedToAuthorizedResourcesOnly and MemberNeverSeesUnauthorizedResource
// above: a Member with access to one VM (which has its own alert) and no
// access to a Database (which has its own, separate alert) must see only
// the VM alert's synthetic events -- the Database alert's event, resource
// id, and title must never appear anywhere in the response body, exactly
// like Overview/Resources' own scoping.
func TestMonitoringTimeline_ScopedToAuthorizedResources(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	_, dbResource := e.createDatabaseFixture(t, project)

	e.createAlertFixture(t, project, vmResource, services.AlertTypeVMHighCPU, "WARNING", "VM CPU is high")
	e.createAlertFixture(t, project, dbResource, services.AlertTypeDatabaseUnavailable, "CRITICAL", "Database is unreachable")

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmResource, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/monitoring/timeline?project_id="+project.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member timeline status = %d, want 200", resp.StatusCode)
	}
	events, _ := body["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("member timeline events = %d, want exactly 1 (only the authorized VM's ALERT_TRIGGERED event): %v", len(events), events)
	}
	first := events[0].(map[string]any)
	if first["resource_id"] != vmResource.String() {
		t.Errorf("event resource_id = %v, want %v", first["resource_id"], vmResource)
	}
	if first["type"] != "ALERT_TRIGGERED" {
		t.Errorf("event type = %v, want ALERT_TRIGGERED", first["type"])
	}

	// List-shaped IDOR: the unauthorized database's resource id and alert
	// title must never appear anywhere in the raw response body, regardless
	// of the top-level events list already being correct.
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshal response body: %v", err)
	}
	if strings.Contains(string(raw), dbResource.String()) {
		t.Errorf("member timeline leaked the unauthorized database's resource id: %s", raw)
	}
	if strings.Contains(string(raw), "Database is unreachable") {
		t.Errorf("member timeline leaked the unauthorized database's alert title: %s", raw)
	}
}

// TestMonitoringTimeline_NeverFabricatesUnsetTimestamps is Timeline's
// core-constraint test: an alert that's active but never acknowledged or
// resolved must contribute exactly one event (ALERT_TRIGGERED), never a
// fake ALERT_ACKNOWLEDGED/ALERT_RESOLVED derived from a null
// acknowledged_at/resolved_at.
func TestMonitoringTimeline_NeverFabricatesUnsetTimestamps(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)
	e.createAlertFixture(t, project, vmResource, services.AlertTypeVMHighCPU, "WARNING", "VM CPU is high")

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/monitoring/timeline?project_id="+project.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin timeline status = %d, want 200", resp.StatusCode)
	}
	events, _ := body["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("timeline events for a never-acknowledged, never-resolved alert = %d, want exactly 1", len(events))
	}
	if events[0].(map[string]any)["type"] != "ALERT_TRIGGERED" {
		t.Errorf("event type = %v, want ALERT_TRIGGERED", events[0].(map[string]any)["type"])
	}
	for _, raw := range events {
		evt := raw.(map[string]any)
		if evt["type"] == "ALERT_ACKNOWLEDGED" || evt["type"] == "ALERT_RESOLVED" {
			t.Fatalf("timeline fabricated a %v event for an alert with no acknowledged_at/resolved_at set", evt["type"])
		}
	}
}

// TestMonitoringTimeline_SortedDescendingAndLimited seeds four events at
// four known, strictly increasing real timestamps (an alert's TRIGGERED ->
// ACKNOWLEDGED -> RESOLVED lifecycle, then a recommendation's DETECTED),
// then asserts the unfiltered response is sorted newest-first and that
// limit truncates to the newest N without disturbing that order.
func TestMonitoringTimeline_SortedDescendingAndLimited(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	project := e.createWorkspace(t)
	vmResource := e.createVM(t, project)

	alertID := e.createAlertFixture(t, project, vmResource, services.AlertTypeVMHighCPU, "WARNING", "VM CPU is high")

	adminEmail, adminPassword := e.createAdmin(t)
	admin, err := e.store.GetUserByEmail(ctx, adminEmail)
	if err != nil {
		t.Fatalf("load admin fixture: %v", err)
	}
	if _, err := e.store.AcknowledgeAlert(ctx, generated.AcknowledgeAlertParams{
		ID: alertID, AcknowledgedBy: pgutil.NullUUID(&admin.ID),
	}); err != nil {
		t.Fatalf("acknowledge alert fixture: %v", err)
	}
	if _, err := e.store.ResolveAlert(ctx, alertID); err != nil {
		t.Fatalf("resolve alert fixture: %v", err)
	}
	e.createRecommendationFixture(t, vmResource, "VM package needs an update")

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// Unfiltered (default limit): all 4 events, newest first.
	resp, body := e.get(t, client, "/api/monitoring/timeline?project_id="+project.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("timeline status = %d, want 200", resp.StatusCode)
	}
	events, _ := body["events"].([]any)
	if len(events) != 4 {
		t.Fatalf("timeline events = %d, want exactly 4: %v", len(events), events)
	}
	wantOrder := []string{"RECOMMENDATION_DETECTED", "ALERT_RESOLVED", "ALERT_ACKNOWLEDGED", "ALERT_TRIGGERED"}
	for i, wantType := range wantOrder {
		gotType := events[i].(map[string]any)["type"]
		if gotType != wantType {
			t.Errorf("event[%d].type = %v, want %v (want newest-first order %v)", i, gotType, wantType, wantOrder)
		}
	}
	if body["total"].(float64) != 4 {
		t.Errorf("total = %v, want 4", body["total"])
	}

	// limit=2 must truncate to the 2 newest events, in the same order,
	// while total still reports the pre-truncation count of 4.
	limitedResp, limitedBody := e.get(t, client, "/api/monitoring/timeline?project_id="+project.String()+"&limit=2")
	if limitedResp.StatusCode != http.StatusOK {
		t.Fatalf("limited timeline status = %d, want 200", limitedResp.StatusCode)
	}
	limitedEvents, _ := limitedBody["events"].([]any)
	if len(limitedEvents) != 2 {
		t.Fatalf("limit=2 timeline events = %d, want exactly 2", len(limitedEvents))
	}
	for i, wantType := range wantOrder[:2] {
		gotType := limitedEvents[i].(map[string]any)["type"]
		if gotType != wantType {
			t.Errorf("limited event[%d].type = %v, want %v", i, gotType, wantType)
		}
	}
	if limitedBody["total"].(float64) != 4 {
		t.Errorf("limit=2 total = %v, want 4 (pre-truncation count)", limitedBody["total"])
	}
}
