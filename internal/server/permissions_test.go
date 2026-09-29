// This file exercises GET /api/permissions: the unified, cross-resource-
// type direct-grants ledger backing the Permissions admin page. It is
// admin-only (a plain 403 for Members, not the 404-vs-403 IDOR pattern
// resource-scoped endpoints use, since this is a pure role-gated category
// endpoint), scoped to DIRECT grants only (workspace-derived access must
// never appear here), and returns one row per (resource, user, permission)
// rather than merging multiple permissions on the same grant into a
// permissions[] array.
//
// Every test below scopes its assertions through a query-param filter tied
// to a fixture ID freshly minted in that test (workspace_id/user_id are
// all fresh UUIDs) so results are deterministic even though this project's
// test database is never truncated between runs -- an unfiltered or
// loosely-filtered query could otherwise observe grants left behind by
// unrelated tests.
package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/services"
)

// createAdminWithID mirrors testEnv.createAdmin but also returns the new
// admin's user ID -- needed here (and not in router_test.go's shared
// createAdmin) because several tests below grant direct access straight to
// an ADMIN account, an unusual-but-valid combination used to make the
// role filter's exclusion behavior observable in both directions.
func (e *testEnv) createAdminWithID(t *testing.T) (email, password string, userID uuid.UUID) {
	t.Helper()
	email = uniqueEmail(t, "admin")
	password = "AdminPassw0rd!23"
	u, err := e.auth.CreateUserWithRole(context.Background(), email, "Test Admin", password, services.RoleAdmin)
	if err != nil {
		t.Fatalf("create admin fixture: %v", err)
	}
	return email, password, u.ID
}

// grantsContainEmail reports whether any row in a decoded /api/permissions
// "grants" array belongs to the given user_email.
func grantsContainEmail(grants []any, email string) bool {
	for _, g := range grants {
		row, ok := g.(map[string]any)
		if !ok {
			continue
		}
		if row["user_email"] == email {
			return true
		}
	}
	return false
}

// === GET /api/permissions is admin-only (plain 403, not 404-vs-403) ===

func TestPermissions_MemberForbidden(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)

	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/permissions")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member list permissions = %d, want 403", resp.StatusCode)
	}
}

// === filters ===

func TestPermissions_FiltersByResourceType(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	_, dbResourceID := e.createDatabaseFixture(t, project)

	vmEmail, _, vmUserID := e.createMember(t)
	e.grantDirectVMAccess(t, vmUserID, vmResourceID, services.PermVMView)

	dbEmail, _, dbUserID := e.createMember(t)
	e.grantDirectVMAccess(t, dbUserID, dbResourceID, services.PermDatabaseView)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	vmResp, vmBody := e.get(t, client, "/api/permissions?workspace_id="+project.String()+"&resource_type=VM")
	if vmResp.StatusCode != http.StatusOK {
		t.Fatalf("admin list VM permissions = %d, want 200", vmResp.StatusCode)
	}
	vmGrants, _ := vmBody["grants"].([]any)
	if len(vmGrants) != 1 {
		t.Fatalf("resource_type=VM grants = %v, want exactly 1", vmGrants)
	}
	if row := vmGrants[0].(map[string]any); row["resource_type"] != "VM" || row["user_email"] != vmEmail {
		t.Errorf("resource_type=VM row = %v, want resource_type VM / user_email %s", row, vmEmail)
	}

	dbResp, dbBody := e.get(t, client, "/api/permissions?workspace_id="+project.String()+"&resource_type=DATABASE")
	if dbResp.StatusCode != http.StatusOK {
		t.Fatalf("admin list DATABASE permissions = %d, want 200", dbResp.StatusCode)
	}
	dbGrants, _ := dbBody["grants"].([]any)
	if len(dbGrants) != 1 {
		t.Fatalf("resource_type=DATABASE grants = %v, want exactly 1", dbGrants)
	}
	if row := dbGrants[0].(map[string]any); row["resource_type"] != "DATABASE" || row["user_email"] != dbEmail {
		t.Errorf("resource_type=DATABASE row = %v, want resource_type DATABASE / user_email %s", row, dbEmail)
	}
}

func TestPermissions_FiltersByWorkspaceID(t *testing.T) {
	e := setup(t)
	workspaceA := e.createWorkspace(t)
	workspaceB := e.createWorkspace(t)
	_, resourceA := e.createDatabaseFixture(t, workspaceA)
	_, resourceB := e.createDatabaseFixture(t, workspaceB)

	emailA, _, userA := e.createMember(t)
	e.grantDirectVMAccess(t, userA, resourceA, services.PermDatabaseView)

	emailB, _, userB := e.createMember(t)
	e.grantDirectVMAccess(t, userB, resourceB, services.PermDatabaseView)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/permissions?workspace_id="+workspaceA.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin list permissions by workspace = %d, want 200", resp.StatusCode)
	}
	grants, _ := body["grants"].([]any)
	if len(grants) != 1 {
		t.Fatalf("workspace_id=A grants = %v, want exactly 1", grants)
	}
	row := grants[0].(map[string]any)
	if row["workspace_id"] != workspaceA.String() || row["user_email"] != emailA {
		t.Errorf("workspace_id=A row = %v, want workspace_id %s / user_email %s", row, workspaceA, emailA)
	}
	if grantsContainEmail(grants, emailB) {
		t.Fatalf("workspace_id filter leaked workspace B's grant for %s: %v", emailB, grants)
	}
}

func TestPermissions_FiltersByRole(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, memberResourceID := e.createDatabaseFixture(t, project)
	_, adminResourceID := e.createDatabaseFixture(t, project)

	memberEmail, _, memberUserID := e.createMember(t)
	e.grantDirectVMAccess(t, memberUserID, memberResourceID, services.PermDatabaseView)

	// Unusual but valid data: an ADMIN account also holding a direct
	// grant (ADMIN bypasses authorization entirely via IsAdmin() and
	// normally never needs one) -- constructed purely so ?role=ADMIN and
	// ?role=MEMBER's exclusion behavior is genuinely observable in both
	// directions, not just "a MEMBER row exists."
	adminTargetEmail, _, adminTargetID := e.createAdminWithID(t)
	e.grantDirectVMAccess(t, adminTargetID, adminResourceID, services.PermDatabaseView)

	actorEmail, actorPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, actorEmail, actorPassword)

	memberResp, memberBody := e.get(t, client, "/api/permissions?workspace_id="+project.String()+"&role=MEMBER")
	if memberResp.StatusCode != http.StatusOK {
		t.Fatalf("admin list permissions by role=MEMBER = %d, want 200", memberResp.StatusCode)
	}
	memberGrants, _ := memberBody["grants"].([]any)
	if len(memberGrants) != 1 {
		t.Fatalf("role=MEMBER grants = %v, want exactly 1", memberGrants)
	}
	if row := memberGrants[0].(map[string]any); row["user_email"] != memberEmail || row["user_role"] != "MEMBER" {
		t.Errorf("role=MEMBER row = %v, want user_email %s / user_role MEMBER", row, memberEmail)
	}

	adminResp, adminBody := e.get(t, client, "/api/permissions?workspace_id="+project.String()+"&role=ADMIN")
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("admin list permissions by role=ADMIN = %d, want 200", adminResp.StatusCode)
	}
	adminGrants, _ := adminBody["grants"].([]any)
	if len(adminGrants) != 1 {
		t.Fatalf("role=ADMIN grants = %v, want exactly 1", adminGrants)
	}
	if row := adminGrants[0].(map[string]any); row["user_email"] != adminTargetEmail || row["user_role"] != "ADMIN" {
		t.Errorf("role=ADMIN row = %v, want user_email %s / user_role ADMIN", row, adminTargetEmail)
	}
}

// === direct-grants-only: the single most important correctness property
// of this endpoint (plan decision #6) ===

func TestPermissions_NeverIncludesWorkspaceDerivedAccess(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	e.createDatabaseFixture(t, workspace)

	memberEmail, _, memberUserID := e.createMember(t)
	e.addWorkspaceMember(t, workspace, memberUserID)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/permissions?workspace_id="+workspace.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin list permissions = %d, want 200", resp.StatusCode)
	}
	grants, _ := body["grants"].([]any)
	if len(grants) != 0 {
		t.Fatalf("workspace-derived-only access leaked into /api/permissions: %v (want 0 rows -- %s has only workspace membership, no direct grant)", grants, memberEmail)
	}
}

// === soft-deleted resources must never leak a grant ===

func TestPermissions_NeverLeaksDeletedResource(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	dbID, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, _, memberUserID := e.createMember(t)
	e.grantDirectVMAccess(t, memberUserID, resourceID, services.PermDatabaseView)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	preResp, preBody := e.get(t, client, "/api/permissions?workspace_id="+project.String())
	if preResp.StatusCode != http.StatusOK {
		t.Fatalf("admin list permissions pre-delete = %d, want 200", preResp.StatusCode)
	}
	preGrants, _ := preBody["grants"].([]any)
	if !grantsContainEmail(preGrants, memberEmail) {
		t.Fatalf("expected pre-delete grant for %s in %v", memberEmail, preGrants)
	}

	delResp, _ := e.do(t, client, http.MethodDelete, "/api/databases/"+dbID.String(), map[string]string{"confirmation_name": e.resourceName(t, resourceID)})
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("admin delete database = %d, want 200", delResp.StatusCode)
	}

	postResp, postBody := e.get(t, client, "/api/permissions?workspace_id="+project.String())
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("admin list permissions post-delete = %d, want 200", postResp.StatusCode)
	}
	postGrants, _ := postBody["grants"].([]any)
	if grantsContainEmail(postGrants, memberEmail) {
		t.Fatalf("soft-deleted resource's grant for %s leaked into /api/permissions: %v", memberEmail, postGrants)
	}
}

// === response shape: one row per (resource, user, permission), never a
// merged permissions[] array (locks in the contract permissions.go's own
// comment documents, so a future refactor can't silently regress it) ===

func TestPermissions_ResponseShape_OneRowPerPermission(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, resourceID := e.createDatabaseFixture(t, project)
	memberEmail, _, memberUserID := e.createMember(t)
	e.grantDirectVMAccess(t, memberUserID, resourceID, services.PermDatabaseView, services.PermDatabaseBrowser)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/permissions?user_id="+memberUserID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin list permissions by user = %d, want 200", resp.StatusCode)
	}
	grants, _ := body["grants"].([]any)
	if len(grants) != 2 {
		t.Fatalf("grants for %s = %v, want exactly 2 rows (one per permission, not one merged row)", memberEmail, grants)
	}

	var viewRows, browserRows int
	for _, g := range grants {
		row := g.(map[string]any)
		if _, ok := row["permissions"]; ok {
			t.Fatalf("grant row carries a permissions[] array %v; expected one row per (resource,user,permission) with a single \"permission\" string field", row)
		}
		switch row["permission"] {
		case services.PermDatabaseView:
			viewRows++
		case services.PermDatabaseBrowser:
			browserRows++
		default:
			t.Errorf("unexpected permission in row %v", row)
		}
		if row["user_email"] != memberEmail {
			t.Errorf("row user_email = %v, want %s", row["user_email"], memberEmail)
		}
	}
	if viewRows != 1 {
		t.Errorf("database.view rows = %d, want exactly 1", viewRows)
	}
	if browserRows != 1 {
		t.Errorf("database.browser rows = %d, want exactly 1", browserRows)
	}
}
