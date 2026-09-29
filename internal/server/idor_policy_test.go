// This file is Step 18's final polish-phase regression test proving the
// project's core disclosure policy (docs/authorization.md, "404-not-403:
// the disclosure policy", and Step 18 plan decision #2) holds exactly as
// designed across the endpoints this step added: resource-scoped endpoints
// (GET /api/databases/:id and friends) keep the existing 404-on-denial IDOR
// pattern; pure role-gated category endpoints (POST /api/users,
// GET /api/permissions, GET /api/users/:id) return 403 via RequireRole with
// no ID to hide.
//
// One layering nuance is easy to get backwards and is verified here
// directly against the real handler code rather than assumed: the three
// "Authorized Members" list endpoints
// (GET /api/{vms,databases,object-storage}/:id/access) are mounted behind
// requireAdmin at the router level (router.go), so a Member is rejected
// with 403 by RequireRole before the handler ever runs -- its internal
// authorizeDatabase/authorizeObjectStorage-style 404-on-denial helper is
// never reached for a non-admin caller at all (VMHandler.ListAccess/
// DatabaseHandler.ListAccess/ObjectStorageHandler.ListAccess call
// h.vms.ListAccess/h.databases.ListAccess/h.objectStorages.ListAccess
// directly with no authorizeX call in between). So even a Member holding a
// direct view grant on that exact resource gets 403, not 404 -- this is
// intentionally different from GET /api/databases/:id itself, which any
// authenticated role can reach and which does 404 on denial inside the
// handler. TestDatabaseListAccess_AdminOnly/TestObjectStorageListAccess_
// AdminOnly (database_test.go/object_storage_test.go) already establish
// this for Database/ObjectStorage; the VM case was the one genuine gap in
// that matrix, closed below.
package server_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/services"
)

// === (1) The explicit 404-vs-403 regression test ===

func TestIDORPolicy_ResourceScopedIs404_CategoryEndpointIs403(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, dbResourceID := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	// (a) Resource-scoped, zero grants: a database that genuinely exists
	// must 404 for this member, and that 404 body must be indistinguishable
	// from a request for a genuinely nonexistent database -- both go
	// through authorizeDatabase's single "database not found" message,
	// never leaking that the real ID exists.
	respExisting, bodyExisting := e.get(t, client, "/api/databases/"+dbID.String())
	if respExisting.StatusCode != http.StatusNotFound {
		t.Fatalf("member GET unauthorized-but-real database = %d, want 404", respExisting.StatusCode)
	}
	respNonexistent, bodyNonexistent := e.get(t, client, "/api/databases/"+uuid.NewString())
	if respNonexistent.StatusCode != http.StatusNotFound {
		t.Fatalf("member GET nonexistent database = %d, want 404", respNonexistent.StatusCode)
	}
	if len(bodyExisting) != len(bodyNonexistent) {
		t.Fatalf("404 bodies have different shape: real-but-unauthorized=%v nonexistent=%v (existence must not be disclosed)", bodyExisting, bodyNonexistent)
	}
	if bodyExisting["error"] != bodyNonexistent["error"] {
		t.Fatalf("404 bodies distinguishable by message: real-but-unauthorized=%v nonexistent=%v", bodyExisting["error"], bodyNonexistent["error"])
	}
	for _, leaky := range []string{"name", "host", "port", "type", "project_name", "resource_id"} {
		if _, present := bodyExisting[leaky]; present {
			t.Errorf("404 response leaked field %q: %v", leaky, bodyExisting)
		}
	}

	// (b) Pure role gate, nothing to hide: POST /api/users. Body content is
	// irrelevant -- RequireRole runs before the handler ever decodes it.
	respCreate, _ := e.do(t, client, http.MethodPost, "/api/users", map[string]string{"anything": "goes"})
	if respCreate.StatusCode != http.StatusForbidden {
		t.Fatalf("member POST /api/users = %d, want 403", respCreate.StatusCode)
	}

	// (c) Pure role gate: GET /api/permissions.
	respPerms, _ := e.get(t, client, "/api/permissions")
	if respPerms.StatusCode != http.StatusForbidden {
		t.Fatalf("member GET /api/permissions = %d, want 403", respPerms.StatusCode)
	}

	// (d) GET /api/databases/:id/access is admin-only AT THE ROUTE LEVEL
	// (requireAdmin in router.go) -- this is not a resource-scoped
	// existence question, it's an administrative action. Even granting this
	// exact member database.view on this exact database does not change the
	// outcome: RequireRole rejects with 403 before DatabaseHandler.ListAccess
	// (which never calls authorizeDatabase) ever runs.
	e.grantDirectVMAccess(t, memberID, dbResourceID, services.PermDatabaseView)
	respAccess, _ := e.get(t, client, "/api/databases/"+dbID.String()+"/access")
	if respAccess.StatusCode != http.StatusForbidden {
		t.Fatalf("member GET /api/databases/:id/access (own database.view grant) = %d, want 403 (admin-only route gate, not a 404 IDOR case)", respAccess.StatusCode)
	}
}

// === (2) Full IDOR matrix for the Phase 1-3 endpoints ===

// TestIDORPolicy_VMListAccess_MemberForbiddenEvenWithOwnGrant closes the one
// gap in this matrix: TestDatabaseListAccess_AdminOnly (database_test.go)
// and TestObjectStorageListAccess_AdminOnly (object_storage_test.go) already
// prove this for Database/ObjectStorage; VMHandler.ListAccess had no
// equivalent direct test even though it is wired identically
// (requireAdmin at the route level, no authorizeVM call inside the
// handler -- see vms.go's ListAccess).
func TestIDORPolicy_VMListAccess_MemberForbiddenEvenWithOwnGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmResourceID, services.PermVMView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/vms/"+vmResourceID.String()+"/access")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member GET /api/vms/:id/access (own vm.view grant) = %d, want 403 (admin-only route gate, not a 404 IDOR case)", resp.StatusCode)
	}
}

// TestIDORPolicy_PermissionsQueryParam_MemberForbiddenBeforeFilterEvaluated
// confirms the simpler truth about GET /api/permissions?user_id=...: since
// the route requires ADMIN at the middleware level (before
// PermissionsHandler.List ever parses a query param), a Member cannot reach
// the handler's user_id filter at all, regardless of whose ID it names --
// there is no per-param IDOR scenario to construct here, only the same
// route-level 403 TestPermissions_MemberForbidden already proves for the
// unfiltered request.
func TestIDORPolicy_PermissionsQueryParam_MemberForbiddenBeforeFilterEvaluated(t *testing.T) {
	e := setup(t)
	_, _, memberID := e.createMember(t)
	callerEmail, callerPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, callerEmail, callerPassword)

	resp, _ := e.get(t, client, "/api/permissions?user_id="+memberID.String())
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member GET /api/permissions?user_id=<someone-else> = %d, want 403", resp.StatusCode)
	}
}

// TestIDORPolicy_UserDetail_OtherUserID_MemberForbidden confirms
// GET /api/users/:id as a Member is a plain 403, not the 404 IDOR pattern:
// this is an admin-only category route (requireAdmin in router.go), and
// UserHandler.Get performs no per-caller resource-authorization check at
// all -- reading a real *other* user's ID changes nothing, unlike a
// resource-scoped endpoint where the existence of the target ID matters to
// the disclosure policy.
func TestIDORPolicy_UserDetail_OtherUserID_MemberForbidden(t *testing.T) {
	e := setup(t)
	_, _, targetID := e.createMember(t)
	callerEmail, callerPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, callerEmail, callerPassword)

	resp, _ := e.get(t, client, "/api/users/"+targetID.String())
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member GET /api/users/:id (other user's ID) = %d, want 403 (admin-only category route, not a 404 IDOR case)", resp.StatusCode)
	}
}
