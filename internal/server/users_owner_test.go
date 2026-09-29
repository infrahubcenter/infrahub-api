// Tests for the OWNER role tier: RequireAnyRole admits Owner to every
// existing Admin-gated route, only an Owner may create/promote another
// Owner (Admin keeps its existing Admin/Member-only invite capability),
// and the last-active-owner safety invariant. Same conventions as
// router_test.go/users_role_test.go: real HTTP stack, real Postgres,
// skips (not fails) when DATABASE_URL is unset.
package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/services"
)

func (e *testEnv) createOwner(t *testing.T) (email, password string) {
	t.Helper()
	email = uniqueEmail(t, "owner")
	password = "OwnerPassw0rd!23"
	if _, err := e.auth.CreateUserWithRole(context.Background(), email, "Test Owner", password, services.RoleOwner); err != nil {
		t.Fatalf("create owner fixture: %v", err)
	}
	return email, password
}

// isolateSoleActiveOwner mirrors isolateSoleActiveAdmin (router_test.go)
// exactly, but for OWNER: deactivates every other active Owner for the
// duration of the calling test, restoring their previous is_active state
// via t.Cleanup, so keepOwnerID is provably the only active Owner in the
// system -- required to deterministically exercise the last-active-owner
// invariant against this shared, long-lived dev Postgres instance.
func (e *testEnv) isolateSoleActiveOwner(t *testing.T, keepOwnerID uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	rows, err := e.store.ListUsersWithRole(ctx)
	if err != nil {
		t.Fatalf("list users to isolate sole owner: %v", err)
	}
	type idName struct {
		id   uuid.UUID
		name string
	}
	var others []idName
	for _, row := range rows {
		if row.RoleName == services.RoleOwner && row.IsActive && row.ID != keepOwnerID {
			others = append(others, idName{id: row.ID, name: row.Name})
		}
	}
	for _, o := range others {
		if _, err := e.store.UpdateUser(ctx, generated.UpdateUserParams{ID: o.id, Name: o.name, IsActive: false}); err != nil {
			t.Fatalf("deactivate other owner %s: %v", o.id, err)
		}
	}

	t.Cleanup(func() {
		restoreCtx := context.Background()
		for _, o := range others {
			if _, err := e.store.UpdateUser(restoreCtx, generated.UpdateUserParams{ID: o.id, Name: o.name, IsActive: true}); err != nil {
				t.Errorf("restore other owner %s active state: %v", o.id, err)
			}
		}
	})
}

// TestOwnerSatisfiesAdminGate proves RequireAnyRole(Admin, Owner) -- the
// router.go change backing "Owner has every Admin capability" -- actually
// admits an Owner into a route gated requireAdmin(...), using the plain
// admin list endpoint as a representative example.
func TestOwnerSatisfiesAdminGate(t *testing.T) {
	e := setup(t)
	ownerEmail, ownerPassword := e.createOwner(t)
	client := newClient()
	e.login(t, client, ownerEmail, ownerPassword)

	resp, body := e.get(t, client, "/api/users")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner GET /api/users = %d, want 200; body=%v", resp.StatusCode, body)
	}
}

func TestCreateUser_AdminCannotCreateOwner(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/users", map[string]any{
		"name": "Attempted Owner", "email": uniqueEmail(t, "attempted-owner"), "role": "OWNER",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin create OWNER = %d, want 403; body=%v", resp.StatusCode, body)
	}
}

func TestCreateUser_OwnerCanCreateOwner(t *testing.T) {
	e := setup(t)
	ownerEmail, ownerPassword := e.createOwner(t)
	client := newClient()
	e.login(t, client, ownerEmail, ownerPassword)

	newOwnerEmail := uniqueEmail(t, "new-owner")
	resp, body := e.do(t, client, http.MethodPost, "/api/users", map[string]any{
		"name": "New Owner", "email": newOwnerEmail, "role": "OWNER",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("owner create OWNER = %d, want 201; body=%v", resp.StatusCode, body)
	}
	if body["role"] != "OWNER" {
		t.Errorf("role in response = %v, want OWNER", body["role"])
	}

	row, err := e.store.GetUserWithRoleByEmail(context.Background(), newOwnerEmail)
	if err != nil {
		t.Fatalf("reload new owner: %v", err)
	}
	if row.RoleName != services.RoleOwner {
		t.Errorf("stored role = %v, want OWNER", row.RoleName)
	}
}

func TestUpdateUser_AdminCannotPromoteToOwner(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	_, _, targetID := e.createMember(t)

	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPatch, "/api/users/"+targetID.String(), map[string]any{"role": "OWNER"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin promote member to OWNER = %d, want 403; body=%v", resp.StatusCode, body)
	}

	row, err := e.store.GetUserWithRoleByID(context.Background(), targetID)
	if err != nil {
		t.Fatalf("reload target: %v", err)
	}
	if row.RoleName != services.RoleMember {
		t.Errorf("target role = %v after a rejected promotion, want still MEMBER", row.RoleName)
	}
}

func TestUpdateUser_OwnerCanPromoteToOwner(t *testing.T) {
	e := setup(t)
	ownerEmail, ownerPassword := e.createOwner(t)
	_, _, targetID := e.createMember(t)

	client := newClient()
	e.login(t, client, ownerEmail, ownerPassword)

	resp, body := e.do(t, client, http.MethodPatch, "/api/users/"+targetID.String(), map[string]any{"role": "OWNER"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner promote member to OWNER = %d, want 200; body=%v", resp.StatusCode, body)
	}
	if body["role"] != "OWNER" {
		t.Errorf("role in response = %v, want OWNER", body["role"])
	}
}

// TestLastOwner_CannotDemote proves the last-active-owner invariant is
// enforced even when other Admins remain (so the broader last-active-
// admin-or-owner check alone wouldn't catch this) -- distinct behavior
// from TestLastAdmin_CannotDemote (users_role_test.go), which is why this
// gets its own error message assertion. Acts via a separate Admin actor
// (not the owner acting on themselves): self-action would first hit the
// self-demotion-confirmation gate inside the broader admin-or-owner check
// above it (that check's own count stays > 1 here, by design, so it never
// blocks on its own), which would mask the owner-specific check this test
// exists to exercise.
func TestLastOwner_CannotDemote(t *testing.T) {
	e := setup(t)
	// A separate Admin so the broader admin-or-owner count stays above 1
	// even after the sole Owner below is removed from it -- isolates this
	// test to the Owner-specific invariant.
	actorEmail, actorPassword := e.createAdmin(t)

	ownerEmail, ownerPassword := e.createOwner(t)
	ownerClient := newClient()
	_, loginBody := e.login(t, ownerClient, ownerEmail, ownerPassword)
	ownerID, _ := uuid.Parse(loginBody["id"].(string))
	e.isolateSoleActiveOwner(t, ownerID)

	actorClient := newClient()
	e.login(t, actorClient, actorEmail, actorPassword)

	resp, body := e.do(t, actorClient, http.MethodPatch, "/api/users/"+ownerID.String(), map[string]any{"role": "ADMIN"})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("demote sole owner = %d, want 409; body=%v", resp.StatusCode, body)
	}
	if body["error"] != "cannot remove the last active owner" {
		t.Errorf("error message = %v, want %q", body["error"], "cannot remove the last active owner")
	}

	row, err := e.store.GetUserWithRoleByID(context.Background(), ownerID)
	if err != nil {
		t.Fatalf("reload owner: %v", err)
	}
	if row.RoleName != services.RoleOwner {
		t.Errorf("owner role = %v after a rejected demotion, want still OWNER", row.RoleName)
	}
}

// TestLastOwner_CannotDisable mirrors TestLastOwner_CannotDemote's actor
// setup for the same reason -- see its doc comment.
func TestLastOwner_CannotDisable(t *testing.T) {
	e := setup(t)
	actorEmail, actorPassword := e.createAdmin(t)

	ownerEmail, ownerPassword := e.createOwner(t)
	ownerClient := newClient()
	_, loginBody := e.login(t, ownerClient, ownerEmail, ownerPassword)
	ownerID, _ := uuid.Parse(loginBody["id"].(string))
	e.isolateSoleActiveOwner(t, ownerID)

	actorClient := newClient()
	e.login(t, actorClient, actorEmail, actorPassword)

	resp, body := e.do(t, actorClient, http.MethodPatch, "/api/users/"+ownerID.String(), map[string]any{"is_active": false})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("disable sole owner = %d, want 409; body=%v", resp.StatusCode, body)
	}

	row, err := e.store.GetUserWithRoleByID(context.Background(), ownerID)
	if err != nil {
		t.Fatalf("reload owner: %v", err)
	}
	if !row.IsActive {
		t.Errorf("owner is_active = false after a rejected disable, want still true")
	}
}

// TestLastOwner_CanDemoteWhenAnotherOwnerExists proves the invariant is
// specific to the *count* of active owners, not a blanket "an Owner can
// never be demoted" rule.
func TestLastOwner_CanDemoteWhenAnotherOwnerExists(t *testing.T) {
	e := setup(t)
	actorEmail, actorPassword := e.createOwner(t)
	targetEmail, targetPassword := e.createOwner(t)

	actorClient := newClient()
	e.login(t, actorClient, actorEmail, actorPassword)

	targetClient := newClient()
	_, targetLoginBody := e.login(t, targetClient, targetEmail, targetPassword)
	targetID, _ := uuid.Parse(targetLoginBody["id"].(string))

	resp, body := e.do(t, actorClient, http.MethodPatch, "/api/users/"+targetID.String(), map[string]any{"role": "ADMIN"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("demote one of two owners = %d, want 200; body=%v", resp.StatusCode, body)
	}

	row, err := e.store.GetUserWithRoleByID(context.Background(), targetID)
	if err != nil {
		t.Fatalf("reload demoted owner: %v", err)
	}
	if row.RoleName != services.RoleAdmin {
		t.Errorf("stored role = %v, want ADMIN", row.RoleName)
	}
}
