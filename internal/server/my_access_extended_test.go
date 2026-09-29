// Step 17 Phase 5: My Access is extended from VM-only to VMs + Databases +
// Object Storage (plan decision #8). These tests cover the two new
// sections' per-user permission scoping -- a Member's `databases`/
// `object_storage` entries must only include what they're actually
// authorized for, and each entry's `permissions` must reflect their real
// grant, never a hardcoded/admin-level value -- plus Admin's "see
// everything" behavior, which must match GetUserVMAccess's own existing
// Admin behavior rather than inventing new semantics for the two new keys.
package server_test

import (
	"net/http"
	"testing"

	"vmcontrolcenter/backend/internal/services"
)

func TestMyAccess_ReturnsAllThreeKeys_MemberScopedCorrectly(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)

	authorizedDB, dbResourceID := e.createDatabaseFixture(t, project)
	e.createDatabaseFixture(t, project) // unauthorized, must not appear

	authorizedStorage, storageResourceID := e.createObjectStorageFixture(t, project)
	e.createObjectStorageFixture(t, project) // unauthorized, must not appear

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, dbResourceID, services.PermDatabaseView, services.PermDatabaseBrowser)
	e.grantDirectVMAccess(t, memberID, storageResourceID, services.PermObjectStorageView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/my-access")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("my-access status = %d, want 200", resp.StatusCode)
	}

	if _, ok := body["vms"]; !ok {
		t.Errorf("my-access response missing 'vms' key")
	}

	databases, _ := body["databases"].([]any)
	if len(databases) != 1 {
		t.Fatalf("my-access returned %d databases, want exactly 1 (the authorized one)", len(databases))
	}
	dbEntry := databases[0].(map[string]any)
	if dbEntry["id"] != authorizedDB.String() {
		t.Errorf("my-access database id = %v, want %v", dbEntry["id"], authorizedDB)
	}
	dbPerms, _ := dbEntry["permissions"].([]any)
	if len(dbPerms) != 2 {
		t.Fatalf("my-access database permissions = %v, want exactly [database.browser, database.view] (the real grant)", dbPerms)
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
		t.Errorf("my-access database permissions = %v, want database.view + database.browser", dbPerms)
	}
	// Never a database.logs/query_details grant this member was never given.
	for _, p := range dbPerms {
		if p == services.PermDatabaseLogs || p == services.PermDatabaseQueryDetails {
			t.Errorf("my-access database permissions leaked ungranted permission %v", p)
		}
	}

	objectStorage, _ := body["object_storage"].([]any)
	if len(objectStorage) != 1 {
		t.Fatalf("my-access returned %d object storages, want exactly 1 (the authorized one)", len(objectStorage))
	}
	storageEntry := objectStorage[0].(map[string]any)
	if storageEntry["id"] != authorizedStorage.String() {
		t.Errorf("my-access object storage id = %v, want %v", storageEntry["id"], authorizedStorage)
	}
	storagePerms, _ := storageEntry["permissions"].([]any)
	if len(storagePerms) != 1 || storagePerms[0] != services.PermObjectStorageView {
		t.Errorf("my-access object storage permissions = %v, want only object_storage.view (never object_storage.browser, not granted)", storagePerms)
	}
}

func TestMyAccess_Admin_SeesAllDatabasesAndObjectStorage(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, _ := e.createDatabaseFixture(t, project)
	storageID, _ := e.createObjectStorageFixture(t, project)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/my-access")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("my-access status = %d, want 200", resp.StatusCode)
	}

	databases, _ := body["databases"].([]any)
	foundDB := false
	for _, d := range databases {
		entry := d.(map[string]any)
		if entry["id"] == dbID.String() {
			foundDB = true
			perms, _ := entry["permissions"].([]any)
			if len(perms) != 5 {
				t.Errorf("admin database permissions = %v, want all 5 grantable database permissions", perms)
			}
		}
	}
	if !foundDB {
		t.Errorf("admin my-access databases = %v, want to include %v (admins see every database, no explicit grant needed)", databases, dbID)
	}

	objectStorage, _ := body["object_storage"].([]any)
	foundStorage := false
	for _, s := range objectStorage {
		entry := s.(map[string]any)
		if entry["id"] == storageID.String() {
			foundStorage = true
			perms, _ := entry["permissions"].([]any)
			if len(perms) != 4 {
				t.Errorf("admin object storage permissions = %v, want all 4 grantable object storage permissions", perms)
			}
		}
	}
	if !foundStorage {
		t.Errorf("admin my-access object_storage = %v, want to include %v (admins see every object storage, no explicit grant needed)", objectStorage, storageID)
	}
}

func TestMyAccess_EmptyWhenNoGrants_AllThreeSectionsEmpty(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/my-access")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	databases, ok := body["databases"].([]any)
	if !ok || len(databases) != 0 {
		t.Fatalf("databases = %v, want empty array (present, never omitted)", body["databases"])
	}
	objectStorage, ok := body["object_storage"].([]any)
	if !ok || len(objectStorage) != 0 {
		t.Fatalf("object_storage = %v, want empty array (present, never omitted)", body["object_storage"])
	}
}

// === My Access gains `workspaces` (replaces the retired `groups`/
// `projects` sections now that Project+Group has been flattened into one
// Workspace tier) ===

// TestMyAccess_WorkspacesDerivedFromMembershipAndDirectAccess is the
// flat-tier equivalent of the old "projects derived from group-or-direct
// access" case: a direct grant in Workspace A plus membership in Workspace
// B must both surface, while Workspace C (neither) must not -- proving
// `workspaces` is genuinely derived from real access.
func TestMyAccess_WorkspacesDerivedFromMembershipAndDirectAccess(t *testing.T) {
	e := setup(t)
	workspaceA := e.createWorkspace(t)
	workspaceB := e.createWorkspace(t)
	workspaceC := e.createWorkspace(t)

	vmResourceID := e.createVM(t, workspaceA)

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmResourceID, services.PermVMView)
	e.addWorkspaceMember(t, workspaceB, memberID)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/my-access")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("my-access status = %d, want 200", resp.StatusCode)
	}
	workspaces, _ := body["workspaces"].([]any)
	seen := map[string]bool{}
	for _, w := range workspaces {
		seen[w.(map[string]any)["workspace_id"].(string)] = true
	}
	if !seen[workspaceA.String()] {
		t.Errorf("workspaces = %v, want to include workspace A (direct VM grant)", workspaces)
	}
	if !seen[workspaceB.String()] {
		t.Errorf("workspaces = %v, want to include workspace B (membership)", workspaces)
	}
	if seen[workspaceC.String()] {
		t.Errorf("workspaces = %v, want to NOT include workspace C (no access of any kind)", workspaces)
	}
}

// TestMyAccess_AdminSeesAllWorkspaces confirms an Admin's workspaces
// section is unconditional/global (mirrors GetUserVMAccess's own
// Admin-sees-everything behavior), not derived from the admin's own
// workspace_members/resource_permissions rows -- an Admin typically has
// neither.
func TestMyAccess_AdminSeesAllWorkspaces(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/my-access")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("my-access status = %d, want 200", resp.StatusCode)
	}

	workspaces, _ := body["workspaces"].([]any)
	found := false
	for _, w := range workspaces {
		if w.(map[string]any)["workspace_id"] == workspace.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("admin workspaces = %v, want to include %v (admin sees every workspace unconditionally)", workspaces, workspace)
	}
}

// TestMyAccess_WorkspacesMatchesUserDetailWorkspacesForSameUser is a drift
// guard: a Member's own GET /api/my-access workspaces list must match what
// an admin's GET /api/users/:id shows for that same user, since both are
// meant to call the exact same underlying computation (handlers.
// workspacesForUser) for a Member target rather than two implementations
// that could silently diverge.
func TestMyAccess_WorkspacesMatchesUserDetailWorkspacesForSameUser(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.addWorkspaceMember(t, workspace, memberID)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)
	myAccessResp, myAccessBody := e.get(t, memberClient, "/api/my-access")
	if myAccessResp.StatusCode != http.StatusOK {
		t.Fatalf("my-access status = %d, want 200", myAccessResp.StatusCode)
	}

	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	detailResp, detailBody := e.get(t, adminClient, "/api/users/"+memberID.String())
	if detailResp.StatusCode != http.StatusOK {
		t.Fatalf("get user = %d, want 200", detailResp.StatusCode)
	}

	myWorkspaces, _ := myAccessBody["workspaces"].([]any)
	detailWorkspaces, _ := detailBody["workspaces"].([]any)
	if len(myWorkspaces) != len(detailWorkspaces) {
		t.Fatalf("my-access workspaces (%d) and user-detail workspaces (%d) differ in count: %v vs %v", len(myWorkspaces), len(detailWorkspaces), myWorkspaces, detailWorkspaces)
	}
	myIDs := map[string]bool{}
	for _, w := range myWorkspaces {
		myIDs[w.(map[string]any)["workspace_id"].(string)] = true
	}
	for _, w := range detailWorkspaces {
		id := w.(map[string]any)["workspace_id"].(string)
		if !myIDs[id] {
			t.Errorf("user-detail workspace %s missing from my-access workspaces %v", id, myWorkspaces)
		}
	}
}
