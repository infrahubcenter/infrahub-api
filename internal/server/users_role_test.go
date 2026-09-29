// Tests for Step 18 Phase 1: the role-change API and the last-active-admin
// safety invariant it must never violate, plus the audit events and
// derived user-status field that ride along with it. Same conventions as
// router_test.go: real HTTP stack, real Postgres, skips (not fails) when
// DATABASE_URL is unset.
package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// isolateSoleActiveAdmin deactivates every other active admin-or-owner
// except keepAdminID for the duration of the calling test, restoring their
// previous is_active state via t.Cleanup. CountActiveAdminUsers (the query
// backing the last-active-admin-or-owner invariant) counts ADMIN and OWNER
// together (Owner is a strict superset of Admin) and is, by design, a
// genuinely global count -- it has no notion of "this test's fixtures",
// because the real invariant it protects ("never leave the whole system
// with zero privileged users") must hold system-wide, not per-test. That's
// correct for production, but it means deterministically testing "the sole
// active admin" against this dev Postgres instance -- shared and
// long-lived across many prior test runs, so it can carry other active
// admin/owner fixtures left over from unrelated runs (users_owner_test.go's
// fixtures included) -- requires temporarily neutralizing every other
// active admin-or-owner so this test's fixture is provably the only one,
// then putting back exactly what was there before.
func (e *testEnv) isolateSoleActiveAdmin(t *testing.T, keepAdminID uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	rows, err := e.store.ListUsersWithRole(ctx)
	if err != nil {
		t.Fatalf("list users to isolate sole admin: %v", err)
	}
	type idName struct {
		id   uuid.UUID
		name string
	}
	var others []idName
	for _, row := range rows {
		if (row.RoleName == services.RoleAdmin || row.RoleName == services.RoleOwner) && row.IsActive && row.ID != keepAdminID {
			others = append(others, idName{id: row.ID, name: row.Name})
		}
	}
	for _, o := range others {
		if _, err := e.store.UpdateUser(ctx, generated.UpdateUserParams{ID: o.id, Name: o.name, IsActive: false}); err != nil {
			t.Fatalf("deactivate other admin %s: %v", o.id, err)
		}
	}

	t.Cleanup(func() {
		restoreCtx := context.Background()
		for _, o := range others {
			if _, err := e.store.UpdateUser(restoreCtx, generated.UpdateUserParams{ID: o.id, Name: o.name, IsActive: true}); err != nil {
				t.Errorf("restore other admin %s active state: %v", o.id, err)
			}
		}
	})
}

func TestLastAdmin_CannotDisable(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	_, loginBody := e.login(t, client, adminEmail, adminPassword)
	adminID, _ := uuid.Parse(loginBody["id"].(string))
	e.isolateSoleActiveAdmin(t, adminID)

	resp, body := e.do(t, client, http.MethodPatch, "/api/users/"+adminID.String(), map[string]any{"is_active": false})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("disable sole admin = %d, want 409; body=%v", resp.StatusCode, body)
	}

	row, err := e.store.GetUserWithRoleByID(context.Background(), adminID)
	if err != nil {
		t.Fatalf("reload admin: %v", err)
	}
	if !row.IsActive {
		t.Errorf("admin is_active = false after a rejected disable, want still true")
	}
}

func TestLastAdmin_CannotDemote(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	_, loginBody := e.login(t, client, adminEmail, adminPassword)
	adminID, _ := uuid.Parse(loginBody["id"].(string))
	e.isolateSoleActiveAdmin(t, adminID)

	resp, body := e.do(t, client, http.MethodPatch, "/api/users/"+adminID.String(), map[string]any{"role": "MEMBER"})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("demote sole admin = %d, want 409; body=%v", resp.StatusCode, body)
	}

	row, err := e.store.GetUserWithRoleByID(context.Background(), adminID)
	if err != nil {
		t.Fatalf("reload admin: %v", err)
	}
	if row.RoleName != services.RoleAdmin {
		t.Errorf("admin role = %v after a rejected demotion, want still ADMIN", row.RoleName)
	}
}

func TestLastAdmin_CanDemoteWhenAnotherAdminExists(t *testing.T) {
	e := setup(t)
	actorEmail, actorPassword := e.createAdmin(t)
	targetEmail, targetPassword := e.createAdmin(t)

	actorClient := newClient()
	e.login(t, actorClient, actorEmail, actorPassword)

	// A separate client just to discover the target's ID via its own
	// login response -- the actual demotion below is performed by actorClient
	// (a different admin), never by the target logging in and doing it to
	// themselves, so this test stays isolated from the self-demotion rules.
	targetClient := newClient()
	_, targetLoginBody := e.login(t, targetClient, targetEmail, targetPassword)
	targetID, _ := uuid.Parse(targetLoginBody["id"].(string))

	resp, body := e.do(t, actorClient, http.MethodPatch, "/api/users/"+targetID.String(), map[string]any{"role": "MEMBER"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("demote one of two admins = %d, want 200; body=%v", resp.StatusCode, body)
	}
	if body["role"] != "MEMBER" {
		t.Errorf("role in response = %v, want MEMBER", body["role"])
	}

	row, err := e.store.GetUserWithRoleByID(context.Background(), targetID)
	if err != nil {
		t.Fatalf("reload demoted user: %v", err)
	}
	if row.RoleName != services.RoleMember {
		t.Errorf("stored role = %v, want MEMBER", row.RoleName)
	}

	// The other admin (actor) must be completely unaffected.
	actorRow, err := e.store.GetUserWithRoleByEmail(context.Background(), actorEmail)
	if err != nil {
		t.Fatalf("reload actor admin: %v", err)
	}
	if actorRow.RoleName != services.RoleAdmin || !actorRow.IsActive {
		t.Errorf("actor admin state changed unexpectedly: role=%v is_active=%v", actorRow.RoleName, actorRow.IsActive)
	}
}

func TestSelfDemotion_RequiresConfirmation(t *testing.T) {
	e := setup(t)
	// A second admin so the self-demoting user below is never the last one --
	// this test is purely about the confirmation gate, not the last-admin
	// check (that precedence is covered separately).
	e.createAdmin(t)
	selfEmail, selfPassword := e.createAdmin(t)

	client := newClient()
	_, loginBody := e.login(t, client, selfEmail, selfPassword)
	selfID, _ := uuid.Parse(loginBody["id"].(string))

	resp, body := e.do(t, client, http.MethodPatch, "/api/users/"+selfID.String(), map[string]any{"role": "MEMBER"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("self-demote without confirmation = %d, want 400; body=%v", resp.StatusCode, body)
	}

	resp2, body2 := e.do(t, client, http.MethodPatch, "/api/users/"+selfID.String(), map[string]any{
		"role": "MEMBER", "confirmation": true,
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("self-demote with confirmation = %d, want 200; body=%v", resp2.StatusCode, body2)
	}
	if body2["role"] != "MEMBER" {
		t.Errorf("role in response = %v, want MEMBER", body2["role"])
	}
}

func TestSelfDemotion_LastAdminRejectedEvenWithConfirmation(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	_, loginBody := e.login(t, client, adminEmail, adminPassword)
	adminID, _ := uuid.Parse(loginBody["id"].(string))
	e.isolateSoleActiveAdmin(t, adminID)

	resp, body := e.do(t, client, http.MethodPatch, "/api/users/"+adminID.String(), map[string]any{
		"role": "MEMBER", "confirmation": true,
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("sole admin self-demote even with confirmation = %d, want 409 (last-admin check must win); body=%v", resp.StatusCode, body)
	}

	row, err := e.store.GetUserWithRoleByID(context.Background(), adminID)
	if err != nil {
		t.Fatalf("reload admin: %v", err)
	}
	if row.RoleName != services.RoleAdmin || !row.IsActive {
		t.Errorf("sole admin state changed despite rejection: role=%v is_active=%v", row.RoleName, row.IsActive)
	}
}

func TestAudit_RoleChangedRecorded(t *testing.T) {
	e := setup(t)
	actorEmail, actorPassword := e.createAdmin(t)
	_, _, targetID := e.createMember(t)

	client := newClient()
	e.login(t, client, actorEmail, actorPassword)

	resp, body := e.do(t, client, http.MethodPatch, "/api/users/"+targetID.String(), map[string]any{"role": "ADMIN"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("promote member to admin = %d, want 200; body=%v", resp.StatusCode, body)
	}

	assertAuditEventExists(t, e, "USER", targetID, services.AuditUserRoleChanged)

	logs, err := e.store.ListAuditLogsByResource(context.Background(), generated.ListAuditLogsByResourceParams{
		ResourceID: pgutil.NullUUID(&targetID), Limit: 500,
	})
	if err != nil {
		t.Fatalf("query audit logs: %v", err)
	}
	found := false
	for _, l := range logs {
		if l.Action != services.AuditUserRoleChanged {
			continue
		}
		found = true
		var metadata map[string]any
		if err := json.Unmarshal(l.Metadata, &metadata); err != nil {
			t.Fatalf("unmarshal audit metadata: %v", err)
		}
		if metadata["from"] != "MEMBER" || metadata["to"] != "ADMIN" {
			t.Errorf("role-change metadata = %v, want from=MEMBER to=ADMIN", metadata)
		}
	}
	if !found {
		t.Fatalf("no %s audit log found for user %s", services.AuditUserRoleChanged, targetID)
	}
}

func TestAudit_UserEnabledRecorded(t *testing.T) {
	e := setup(t)
	actorEmail, actorPassword := e.createAdmin(t)
	_, _, targetID := e.createMember(t)

	client := newClient()
	e.login(t, client, actorEmail, actorPassword)

	disableResp, _ := e.do(t, client, http.MethodPatch, "/api/users/"+targetID.String(), map[string]any{"is_active": false})
	if disableResp.StatusCode != http.StatusOK {
		t.Fatalf("disable member = %d, want 200", disableResp.StatusCode)
	}
	enableResp, _ := e.do(t, client, http.MethodPatch, "/api/users/"+targetID.String(), map[string]any{"is_active": true})
	if enableResp.StatusCode != http.StatusOK {
		t.Fatalf("re-enable member = %d, want 200", enableResp.StatusCode)
	}

	assertAuditEventExists(t, e, "USER", targetID, services.AuditUserDisabled)
	assertAuditEventExists(t, e, "USER", targetID, services.AuditUserEnabled)
}

func TestUserStatus_DerivedCorrectly(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	memberEmail, memberPassword, memberID := e.createMember(t)

	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	resp, body := e.get(t, adminClient, "/api/users/"+memberID.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get user = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "INVITED" {
		t.Errorf("status before first login = %v, want INVITED", body["status"])
	}

	memberClient := newClient()
	loginResp, _ := e.login(t, memberClient, memberEmail, memberPassword)
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("member login = %d, want 200", loginResp.StatusCode)
	}

	resp2, body2 := e.get(t, adminClient, "/api/users/"+memberID.String())
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("get user after login = %d, want 200", resp2.StatusCode)
	}
	if body2["status"] != "ACTIVE" {
		t.Errorf("status after a real login = %v, want ACTIVE", body2["status"])
	}
	if body2["last_login_at"] == nil {
		t.Errorf("last_login_at = nil after a real login, want a timestamp")
	}

	disableResp, _ := e.do(t, adminClient, http.MethodPatch, "/api/users/"+memberID.String(), map[string]any{"is_active": false})
	if disableResp.StatusCode != http.StatusOK {
		t.Fatalf("disable member = %d, want 200", disableResp.StatusCode)
	}

	resp3, body3 := e.get(t, adminClient, "/api/users/"+memberID.String())
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("get user after disable = %d, want 200", resp3.StatusCode)
	}
	if body3["status"] != "DISABLED" {
		t.Errorf("status after disable = %v, want DISABLED regardless of login history", body3["status"])
	}
}
