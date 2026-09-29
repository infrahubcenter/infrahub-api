// This file exercises the standalone database HTTP surface: IDOR
// protection (404-not-403) on every database-scoped endpoint,
// Member-vs-Admin permission gating for the four never-default
// permissions (database.browser/logs/query_details plus the group-
// default database.view/database.performance), admin-only CRUD, and
// that Delete only soft-deletes the monitoring configuration -- never
// the underlying resource's history. Mirrors monitoring_test.go's shape
// exactly.
package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/services"
)

// createDatabaseFixture configures a standalone database directly
// through DatabaseService (bypassing HTTP), returning its ID and
// resource ID -- mirrors createVM's "insert the fixture directly, test
// the HTTP surface separately" shape.
func (e *testEnv) createDatabaseFixture(t *testing.T, workspaceID uuid.UUID) (databaseID, resourceID uuid.UUID) {
	t.Helper()
	db, err := e.databases.Configure(context.Background(), services.ConfigureInput{
		WorkspaceID: workspaceID, Name: "test-db-" + uuid.NewString(), Type: "POSTGRESQL",
		Host: "127.0.0.1", Port: 5432, DatabaseName: "appdb",
	})
	if err != nil {
		t.Fatalf("create database fixture: %v", err)
	}
	return db.ID, db.ResourceID
}

// === GET /api/databases/:id (IDOR) ===

func TestDatabaseGet_UnauthorizedMember_NotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, _ := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/databases/"+dbID.String())
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized member database get = %d, want 404 (existence must not be disclosed)", resp.StatusCode)
	}
}

func TestDatabaseGet_NonexistentID_NotFound(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/databases/"+uuid.NewString())
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("nonexistent database get = %d, want 404", resp.StatusCode)
	}
}

func TestDatabaseGet_AuthorizedMember_CanView(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/databases/"+dbID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized member database get = %d, want 200", resp.StatusCode)
	}
	if body["type"] != "POSTGRESQL" {
		t.Errorf("type = %v, want POSTGRESQL", body["type"])
	}
	if _, present := body["credential_username"]; present && body["credential_username"] != "" {
		t.Errorf("credential_username leaked in response: %v", body["credential_username"])
	}
}

func TestDatabaseGet_Admin_NeverNeedsExplicitGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, _ := e.createDatabaseFixture(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.get(t, client, "/api/databases/"+dbID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin database get = %d, want 200", resp.StatusCode)
	}
}

// === POST /api/databases (admin-only Configure) ===

func TestDatabaseConfigure_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/databases", map[string]any{
		"workspace_id": project.String(), "type": "POSTGRESQL", "host": "127.0.0.1", "port": 5432,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member configure database = %d, want 403", resp.StatusCode)
	}
}

func TestDatabaseConfigure_RejectsInvalidType(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/databases", map[string]any{
		"workspace_id": project.String(), "type": "ORACLE", "host": "127.0.0.1", "port": 5432,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("configure with invalid type = %d, want 400", resp.StatusCode)
	}
}

func TestDatabaseConfigure_NeverAcceptsAVMID(t *testing.T) {
	// Spec's central architectural requirement: a database is never a VM
	// child. POST /api/databases must succeed with only a project_id --
	// there is no vm_id field anywhere in the request shape.
	e := setup(t)
	project := e.createWorkspace(t)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/databases", map[string]any{
		"workspace_id": project.String(), "type": "REDIS", "host": "127.0.0.1", "port": 6379,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("configure standalone redis database = %d, want 201", resp.StatusCode)
	}
	if body["type"] != "REDIS" {
		t.Errorf("type = %v, want REDIS", body["type"])
	}
}

// === PATCH/DELETE /api/databases/:id (admin-only) ===

func TestDatabaseUpdate_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPatch, "/api/databases/"+dbID.String(), map[string]any{"host": "10.0.0.5"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member update database = %d, want 403", resp.StatusCode)
	}
}

func TestDatabaseUpdate_Admin_PartialUpdateOnlyChangesSuppliedFields(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, _ := e.createDatabaseFixture(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPatch, "/api/databases/"+dbID.String(), map[string]any{"host": "10.0.0.9"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin update database = %d, want 200", resp.StatusCode)
	}
	if body["host"] != "10.0.0.9" {
		t.Errorf("host = %v, want 10.0.0.9", body["host"])
	}
	if body["type"] != "POSTGRESQL" {
		t.Errorf("type = %v, want unchanged POSTGRESQL", body["type"])
	}
	if body["database_name"] != "appdb" {
		t.Errorf("database_name = %v, want unchanged appdb", body["database_name"])
	}
}

func TestDatabaseDelete_AdminOnly_MemberForbidden(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodDelete, "/api/databases/"+dbID.String(), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member delete database = %d, want 403", resp.StatusCode)
	}
}

func TestDatabaseDelete_Admin_SoftDeletesThenNotFound(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	adminEmail, adminPassword := e.createAdmin(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	delResp, _ := e.do(t, client, http.MethodDelete, "/api/databases/"+dbID.String(), map[string]string{"confirmation_name": e.resourceName(t, resourceID)})
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("admin delete database = %d, want 200", delResp.StatusCode)
	}

	getResp, _ := e.get(t, client, "/api/databases/"+dbID.String())
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404 (soft-deleted)", getResp.StatusCode)
	}
}

// === access grant/revoke (spec: Member permissions must be real) ===

func TestDatabaseAccess_GrantThenRevoke(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	adminEmail, adminPassword := e.createAdmin(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)
	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	// Before any grant, the member cannot see the database at all.
	preResp, _ := e.get(t, memberClient, "/api/databases/"+dbID.String())
	if preResp.StatusCode != http.StatusNotFound {
		t.Fatalf("pre-grant member get = %d, want 404", preResp.StatusCode)
	}

	grantResp, _ := e.do(t, adminClient, http.MethodPost, "/api/databases/"+dbID.String()+"/access", map[string]any{
		"user_id": memberID.String(), "permissions": []string{services.PermDatabaseView},
	})
	if grantResp.StatusCode != http.StatusOK {
		t.Fatalf("grant database access = %d, want 200", grantResp.StatusCode)
	}
	assertAuditEventExists(t, e, "DATABASE", resourceID, services.AuditDatabaseAccessGranted)

	postResp, _ := e.get(t, memberClient, "/api/databases/"+dbID.String())
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("post-grant member get = %d, want 200", postResp.StatusCode)
	}

	revokeResp, _ := e.do(t, adminClient, http.MethodDelete, "/api/databases/"+dbID.String()+"/access/"+memberID.String(), nil)
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke database access = %d, want 200", revokeResp.StatusCode)
	}
	assertAuditEventExists(t, e, "DATABASE", resourceID, services.AuditDatabaseAccessRevoked)

	afterRevokeResp, _ := e.get(t, memberClient, "/api/databases/"+dbID.String())
	if afterRevokeResp.StatusCode != http.StatusNotFound {
		t.Fatalf("post-revoke member get = %d, want 404", afterRevokeResp.StatusCode)
	}
}

func TestDatabaseAccess_GrantIsAdminOnly(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.do(t, client, http.MethodPost, "/api/databases/"+dbID.String()+"/access", map[string]any{
		"user_id": memberID.String(), "permissions": []string{services.PermDatabaseBrowser},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member grant access = %d, want 403", resp.StatusCode)
	}
}

// === group membership grants exactly view+performance, never browser/logs ===

func TestDatabaseAccess_GroupMembershipGrantsViewAndPerformanceOnly(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, workspace)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.addWorkspaceMember(t, workspace, memberID)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	viewResp, _ := e.get(t, client, "/api/databases/"+dbID.String())
	if viewResp.StatusCode != http.StatusOK {
		t.Fatalf("group member database.view (default) = %d, want 200", viewResp.StatusCode)
	}

	perfResp, _ := e.get(t, client, "/api/databases/"+dbID.String()+"/performance")
	if perfResp.StatusCode != http.StatusOK {
		t.Fatalf("group member database.performance (default) = %d, want 200", perfResp.StatusCode)
	}

	// database.browser is explicitly never a group-membership default
	// (spec: Member gets NO browser/logs/query_details access without an
	// explicit grant) -- the browser catalog endpoint must 404, not 200.
	_ = resourceID
	browserResp, _ := e.get(t, client, "/api/databases/"+dbID.String()+"/catalog")
	if browserResp.StatusCode != http.StatusNotFound {
		t.Fatalf("group member database.browser (never-default) = %d, want 404", browserResp.StatusCode)
	}
}

// === browser endpoint requires database.browser specifically, not just database.view ===

func TestDatabaseBrowser_RequiresBrowserPermission_ViewAloneInsufficient(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/databases/"+dbID.String()+"/catalog")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("database.view-only browser catalog = %d, want 404 (database.browser must be granted separately)", resp.StatusCode)
	}
}

func TestDatabaseLogs_RequiresLogsPermission_BrowserAloneInsufficient(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	// Real connection details against the local dev Postgres so the
	// catalog fetch below exercises the actual direct-connection browse
	// path, not just the permission gate.
	db, err := e.databases.Configure(context.Background(), services.ConfigureInput{
		WorkspaceID: project, Name: "test-browser-db-" + uuid.NewString(), Type: "POSTGRESQL",
		Host: "127.0.0.1", Port: 5432, DatabaseName: "vmcc", Username: "vmcc", Password: "vmcc_dev_password",
	})
	if err != nil {
		t.Fatalf("create browser database fixture: %v", err)
	}
	dbID, resourceID := db.ID, db.ResourceID
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView, services.PermDatabaseBrowser)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	catalogResp, _ := e.get(t, client, "/api/databases/"+dbID.String()+"/catalog")
	if catalogResp.StatusCode != http.StatusOK {
		t.Fatalf("database.browser-granted catalog = %d, want 200", catalogResp.StatusCode)
	}

	logsResp, _ := e.get(t, client, "/api/databases/"+dbID.String()+"/logs")
	if logsResp.StatusCode != http.StatusNotFound {
		t.Fatalf("database.browser-only logs = %d, want 404 (database.logs must be granted separately)", logsResp.StatusCode)
	}
}

// === query text gated to database.query_details, never leaked to performance-only viewers ===

func TestDatabaseQueries_TextHiddenWithoutQueryDetailsPermission(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView, services.PermDatabasePerformance)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, body := e.get(t, client, "/api/databases/"+dbID.String()+"/queries")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("database.performance queries list = %d, want 200", resp.StatusCode)
	}
	if body["queries"] == nil {
		t.Fatalf("expected a queries array in the response")
	}
}

// === cross-database IDOR: a permission on database A must never leak database B ===

// === GET /api/databases/:id/access (Step 18 Phase 2) ===

func TestDatabaseListAccess_AdminOnly(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceID, services.PermDatabaseView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/databases/"+dbID.String()+"/access")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member list database access = %d, want 403", resp.StatusCode)
	}
}

func TestDatabaseListAccess_MergesDirectAndGroup(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, workspace)

	directEmail, _, directID := e.createMember(t)
	e.grantDirectVMAccess(t, directID, resourceID, services.PermDatabaseBrowser)

	groupEmail, _, groupMemberID := e.createMember(t)
	e.addWorkspaceMember(t, workspace, groupMemberID)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/databases/"+dbID.String()+"/access")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin list database access = %d, want 200", resp.StatusCode)
	}
	members, _ := body["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("members = %v, want exactly 2 (direct member + group member)", members)
	}

	var directFound, groupFound bool
	for _, m := range members {
		row := m.(map[string]any)
		switch row["email"] {
		case directEmail:
			directFound = true
			if row["access_source"] != "DIRECT" {
				t.Errorf("direct member access_source = %v, want DIRECT", row["access_source"])
			}
			if row["browser"] != true {
				t.Errorf("direct member browser = %v, want true", row["browser"])
			}
			if row["view"] != false {
				t.Errorf("direct member view = %v, want false (only database.browser was granted)", row["view"])
			}
		case groupEmail:
			groupFound = true
			if row["access_source"] != "WORKSPACE" {
				t.Errorf("workspace member access_source = %v, want WORKSPACE", row["access_source"])
			}
			if row["view"] != true || row["performance"] != true {
				t.Errorf("group member view/performance = %v/%v, want true/true", row["view"], row["performance"])
			}
			if row["browser"] != false {
				t.Errorf("group member browser = %v, want false (never a group default)", row["browser"])
			}
		}
	}
	if !directFound || !groupFound {
		t.Fatalf("expected both direct (%s) and group (%s) members in %v", directEmail, groupEmail, members)
	}
}

func TestDatabaseGet_AccessToOneDatabaseDoesNotLeakAnother(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbA, resourceA := e.createDatabaseFixture(t, project)
	dbB, _ := e.createDatabaseFixture(t, project)
	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, resourceA, services.PermDatabaseView)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	aResp, _ := e.get(t, client, "/api/databases/"+dbA.String())
	if aResp.StatusCode != http.StatusOK {
		t.Fatalf("authorized database A get = %d, want 200", aResp.StatusCode)
	}
	bResp, _ := e.get(t, client, "/api/databases/"+dbB.String())
	if bResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorized database B get = %d, want 404 (access to A must not leak B)", bResp.StatusCode)
	}
}
