// Step 17 Phase 5: GET /api/object-storage/summary. Covers the routing-
// collision question (does registering a literal "summary" segment at the
// same path depth as the {id} wildcard actually work under Go 1.22+
// net/http.ServeMux?) and the Member-vs-Admin scoping every other
// cross-resource summary endpoint in this project (alerts, databases) also
// enforces: a Member's summary must reflect only their authorized object
// storages, never a global count.
package server_test

import (
	"context"
	"net/http"
	"testing"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/services"
)

// TestObjectStorageSummary_DoesNotCollideWithIDRoute is the explicit
// routing-collision test the plan calls for: GET /api/object-storage/summary
// and GET /api/object-storage/{a real UUID} must both resolve to their own
// handler, not have "summary" swallowed as an {id} path value (which would
// 404, since "summary" doesn't parse as a UUID) nor a real UUID's Get
// request somehow routed into Summary.
func TestObjectStorageSummary_DoesNotCollideWithIDRoute(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	osID, _ := e.createObjectStorageFixture(t, project)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	summaryResp, summaryBody := e.get(t, client, "/api/object-storage/summary")
	if summaryResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/object-storage/summary = %d, want 200 (summary must not be swallowed by the {id} route)", summaryResp.StatusCode)
	}
	for _, key := range []string{"total", "healthy", "warning", "critical", "unavailable"} {
		if _, ok := summaryBody[key]; !ok {
			t.Errorf("summary response missing %q key: %v", key, summaryBody)
		}
	}

	idResp, idBody := e.get(t, client, "/api/object-storage/"+osID.String())
	if idResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/object-storage/{id} = %d, want 200 (a real UUID must still route to Get, unaffected by the summary route)", idResp.StatusCode)
	}
	if idBody["id"] != osID.String() {
		t.Errorf("GET /api/object-storage/{id} id = %v, want %v", idBody["id"], osID)
	}
}

func TestObjectStorageSummary_MemberScopedToAuthorizedOnly(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	authorizedID, authorizedResourceID := e.createObjectStorageFixture(t, project)
	e.createObjectStorageFixture(t, project) // unauthorized, must not count

	if _, err := e.store.UpdateObjectStorageConnectionStatus(context.Background(), generated.UpdateObjectStorageConnectionStatusParams{
		ID: authorizedID, ConnectionStatus: "CONNECTED", HealthStatus: "HEALTHY",
	}); err != nil {
		t.Fatalf("seed connection status: %v", err)
	}

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, authorizedResourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/object-storage/summary")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member summary status = %d, want 200", resp.StatusCode)
	}
	total, _ := body["total"].(float64)
	if total != 1 {
		t.Fatalf("member summary total = %v, want 1 (scoped to the one authorized storage, not a global count)", body["total"])
	}
	healthy, _ := body["healthy"].(float64)
	if healthy != 1 {
		t.Errorf("member summary healthy = %v, want 1", body["healthy"])
	}
}

func TestObjectStorageSummary_UnavailableVsCritical_Partition(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	unavailableID, _ := e.createObjectStorageFixture(t, project)
	criticalID, _ := e.createObjectStorageFixture(t, project)
	healthyID, _ := e.createObjectStorageFixture(t, project)

	ctx := context.Background()
	// UNAVAILABLE connection_status: the bucket/endpoint could not be
	// reached at all -- must land in the "unavailable" bucket, not "critical".
	if _, err := e.store.UpdateObjectStorageConnectionStatus(ctx, generated.UpdateObjectStorageConnectionStatusParams{
		ID: unavailableID, ConnectionStatus: "UNAVAILABLE", HealthStatus: "CRITICAL",
	}); err != nil {
		t.Fatalf("seed unavailable status: %v", err)
	}
	// AUTH_FAILED: the endpoint responded (reachable) but rejected the
	// credential -- must land in "critical", not "unavailable".
	if _, err := e.store.UpdateObjectStorageConnectionStatus(ctx, generated.UpdateObjectStorageConnectionStatusParams{
		ID: criticalID, ConnectionStatus: "AUTH_FAILED", HealthStatus: "CRITICAL",
	}); err != nil {
		t.Fatalf("seed critical status: %v", err)
	}
	if _, err := e.store.UpdateObjectStorageConnectionStatus(ctx, generated.UpdateObjectStorageConnectionStatusParams{
		ID: healthyID, ConnectionStatus: "CONNECTED", HealthStatus: "HEALTHY",
	}); err != nil {
		t.Fatalf("seed healthy status: %v", err)
	}

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/object-storage/summary")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin summary status = %d, want 200", resp.StatusCode)
	}
	if got := body["unavailable"].(float64); got < 1 {
		t.Errorf("summary unavailable = %v, want >= 1 (UNAVAILABLE connection_status)", body["unavailable"])
	}
	if got := body["critical"].(float64); got < 1 {
		t.Errorf("summary critical = %v, want >= 1 (AUTH_FAILED connection_status)", body["critical"])
	}
	if got := body["healthy"].(float64); got < 1 {
		t.Errorf("summary healthy = %v, want >= 1", body["healthy"])
	}
}
