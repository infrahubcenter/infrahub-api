// Tests for Step 18 Phase 3's extension of GET /api/users/:id: the new
// projects/database_access/object_storage_access/active_admin_count
// fields. Same conventions as router_test.go/users_role_test.go: real
// HTTP stack, real Postgres, skips (not fails) when DATABASE_URL is unset.
package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/services"
)

func TestUserGet_IncludesDatabaseAndObjectStorageAccess(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, dbResourceID := e.createDatabaseFixture(t, project)
	_, storageResourceID := e.createObjectStorageFixture(t, project)

	_, _, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, dbResourceID, services.PermDatabaseView, services.PermDatabaseBrowser)
	e.grantDirectVMAccess(t, memberID, storageResourceID, services.PermObjectStorageView)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/users/"+memberID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get user = %d, want 200", resp.StatusCode)
	}

	dbAccess, _ := body["database_access"].([]any)
	if len(dbAccess) != 1 {
		t.Fatalf("database_access = %v, want exactly 1 entry", dbAccess)
	}
	dbEntry := dbAccess[0].(map[string]any)
	if dbEntry["resource_id"] != dbResourceID.String() {
		t.Errorf("database_access resource_id = %v, want %v", dbEntry["resource_id"], dbResourceID)
	}
	dbPerms, _ := dbEntry["permissions"].([]any)
	if len(dbPerms) != 2 {
		t.Fatalf("database_access permissions = %v, want exactly 2 (view+browser, the real grant)", dbPerms)
	}
	foundView, foundBrowse := false, false
	for _, p := range dbPerms {
		if p == services.PermDatabaseView {
			foundView = true
		}
		if p == services.PermDatabaseBrowser {
			foundBrowse = true
		}
	}
	if !foundView || !foundBrowse {
		t.Errorf("database_access permissions = %v, want database.view + database.browser", dbPerms)
	}

	storageAccess, _ := body["object_storage_access"].([]any)
	if len(storageAccess) != 1 {
		t.Fatalf("object_storage_access = %v, want exactly 1 entry", storageAccess)
	}
	storageEntry := storageAccess[0].(map[string]any)
	if storageEntry["resource_id"] != storageResourceID.String() {
		t.Errorf("object_storage_access resource_id = %v, want %v", storageEntry["resource_id"], storageResourceID)
	}
	storagePerms, _ := storageEntry["permissions"].([]any)
	if len(storagePerms) != 1 || storagePerms[0] != services.PermObjectStorageView {
		t.Errorf("object_storage_access permissions = %v, want only object_storage.view (never object_storage.browser, not granted)", storagePerms)
	}
}

// TestUserGet_IncludesActiveAdminCount pins active_admin_count to a known
// value (via isolateSoleActiveAdmin, defined in users_role_test.go) and
// cross-checks it against CountActiveAdminUsers directly, for an arbitrary
// target user -- the field is a genuinely global count, not scoped to the
// target being viewed.
func TestUserGet_IncludesActiveAdminCount(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	_, loginBody := e.login(t, client, adminEmail, adminPassword)
	adminID, _ := uuid.Parse(loginBody["id"].(string))
	e.isolateSoleActiveAdmin(t, adminID)

	// Exactly one active admin now exists; add two more to reach a known
	// count of 3.
	e.createAdmin(t)
	e.createAdmin(t)

	_, _, memberID := e.createMember(t)

	resp, body := e.get(t, client, "/api/users/"+memberID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get user = %d, want 200", resp.StatusCode)
	}
	count, ok := body["active_admin_count"].(float64)
	if !ok {
		t.Fatalf("active_admin_count missing or wrong type: %v", body["active_admin_count"])
	}
	if int64(count) != 3 {
		t.Errorf("active_admin_count = %v, want 3", count)
	}

	real, err := e.store.CountActiveAdminUsers(context.Background())
	if err != nil {
		t.Fatalf("count active admins directly: %v", err)
	}
	if int64(count) != real {
		t.Errorf("active_admin_count = %v, want to match CountActiveAdminUsers = %v", count, real)
	}
}

// TestUserGet_WorkspacesDerivedFromDirectGrant proves the `workspaces`
// field is genuinely derived from real access (a direct VM grant, here),
// via workspacesForUser -- not from some separate, unpopulated membership
// table: a target user with only a direct VM grant in Workspace A shows
// Workspace A even though they were never added as a workspace member.
func TestUserGet_WorkspacesDerivedFromDirectGrant(t *testing.T) {
	e := setup(t)
	workspaceA := e.createWorkspace(t)
	vmResourceID := e.createVM(t, workspaceA)

	_, _, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmResourceID, services.PermVMView)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/users/"+memberID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get user = %d, want 200", resp.StatusCode)
	}
	workspaces, _ := body["workspaces"].([]any)
	found := false
	for _, w := range workspaces {
		if w.(map[string]any)["workspace_id"] == workspaceA.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("workspaces = %v, want to include %v (derived from the direct VM grant)", workspaces, workspaceA)
	}
}
