// Tests for Step 18 Phase 4: GET /api/users' search/role/status filters,
// sort, pagination, and per-user resource counts. Same conventions as
// router_test.go/users_role_test.go: real HTTP stack, real Postgres, skips
// (not fails) when DATABASE_URL is unset.
//
// This dev Postgres instance is shared and long-lived across many prior
// test runs (see users_role_test.go's isolateSoleActiveAdmin comment), so
// assertions here avoid depending on the *total* number of users in the
// system -- tests either scope themselves with a random unique tag baked
// into fixture names/emails and filter on it via ?search=, or assert
// presence/absence of specific known IDs rather than exact list lengths.
package server_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/services"
)

// createMemberNamed is like createMember but with a caller-chosen name
// (createMember always uses the fixed name "Test Member"), so search-by-name
// tests can seed fixtures that are distinguishable from one another.
func (e *testEnv) createMemberNamed(t *testing.T, name string) (email, password string, userID uuid.UUID) {
	t.Helper()
	email = uniqueEmail(t, strings.ToLower(strings.ReplaceAll(name, " ", "-")))
	password = "MemberPassw0rd!23"
	u, err := e.auth.CreateUserWithRole(context.Background(), email, name, password, services.RoleMember)
	if err != nil {
		t.Fatalf("create named member fixture: %v", err)
	}
	return email, password, u.ID
}

func usersFromBody(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	raw, _ := body["users"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("users[] entry is not an object: %v", r)
		}
		out = append(out, m)
	}
	return out
}

func findUserByID(t *testing.T, body map[string]any, id string) map[string]any {
	t.Helper()
	for _, u := range usersFromBody(t, body) {
		if u["id"] == id {
			return u
		}
	}
	t.Fatalf("user %s not found in response users[]: %v", id, body["users"])
	return nil
}

func containsUserID(users []map[string]any, id string) bool {
	for _, u := range users {
		if u["id"] == id {
			return true
		}
	}
	return false
}

func TestUsersList_SearchFiltersByNameOrEmail(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	tag := "search" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	_, _, matchID := e.createMemberNamed(t, tag+"-match")
	_, _, otherID := e.createMemberNamed(t, "unrelated-"+strings.ReplaceAll(uuid.NewString(), "-", "")[:10])

	resp, body := e.get(t, client, "/api/users?search="+tag)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search users = %d, want 200; body=%v", resp.StatusCode, body)
	}
	users := usersFromBody(t, body)
	if len(users) != 1 {
		t.Fatalf("search=%s returned %d users, want exactly 1: %v", tag, len(users), users)
	}
	if users[0]["id"] != matchID.String() {
		t.Errorf("search result id = %v, want %v", users[0]["id"], matchID)
	}
	if containsUserID(users, otherID.String()) {
		t.Errorf("search result unexpectedly includes unrelated user %v", otherID)
	}
}

func TestUsersList_FilterByRole(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	_, _, memberID := e.createMember(t)

	client := newClient()
	_, loginBody := e.login(t, client, adminEmail, adminPassword)
	adminID, _ := uuid.Parse(loginBody["id"].(string))

	respAdmins, bodyAdmins := e.get(t, client, "/api/users?role=ADMIN")
	if respAdmins.StatusCode != http.StatusOK {
		t.Fatalf("list role=ADMIN = %d, want 200", respAdmins.StatusCode)
	}
	adminUsers := usersFromBody(t, bodyAdmins)
	if !containsUserID(adminUsers, adminID.String()) {
		t.Errorf("role=ADMIN missing the fixture admin %v", adminID)
	}
	if containsUserID(adminUsers, memberID.String()) {
		t.Errorf("role=ADMIN unexpectedly includes the fixture member %v", memberID)
	}
	for _, u := range adminUsers {
		if u["role"] != "ADMIN" {
			t.Errorf("role=ADMIN result contains non-admin entry: %v", u)
		}
	}

	respMembers, bodyMembers := e.get(t, client, "/api/users?role=MEMBER")
	if respMembers.StatusCode != http.StatusOK {
		t.Fatalf("list role=MEMBER = %d, want 200", respMembers.StatusCode)
	}
	memberUsers := usersFromBody(t, bodyMembers)
	if !containsUserID(memberUsers, memberID.String()) {
		t.Errorf("role=MEMBER missing the fixture member %v", memberID)
	}
	if containsUserID(memberUsers, adminID.String()) {
		t.Errorf("role=MEMBER unexpectedly includes the fixture admin %v", adminID)
	}
	for _, u := range memberUsers {
		if u["role"] != "MEMBER" {
			t.Errorf("role=MEMBER result contains non-member entry: %v", u)
		}
	}
}

func TestUsersList_FilterByStatus(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// INVITED: never logged in.
	_, _, invitedID := e.createMember(t)

	// ACTIVE: a real login via the login endpoint sets last_login_at.
	activeEmail, activePassword, activeID := e.createMember(t)
	activeClient := newClient()
	loginResp, _ := e.login(t, activeClient, activeEmail, activePassword)
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("active fixture login = %d, want 200", loginResp.StatusCode)
	}

	// DISABLED: disabled via the real PATCH endpoint, regardless of login history.
	_, _, disabledID := e.createMember(t)
	disableResp, _ := e.do(t, client, http.MethodPatch, "/api/users/"+disabledID.String(), map[string]any{"is_active": false})
	if disableResp.StatusCode != http.StatusOK {
		t.Fatalf("disable fixture = %d, want 200", disableResp.StatusCode)
	}

	cases := []struct {
		status  string
		want    uuid.UUID
		exclude []uuid.UUID
	}{
		{"INVITED", invitedID, []uuid.UUID{activeID, disabledID}},
		{"ACTIVE", activeID, []uuid.UUID{invitedID, disabledID}},
		{"DISABLED", disabledID, []uuid.UUID{invitedID, activeID}},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			resp, body := e.get(t, client, "/api/users?status="+tc.status)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%s = %d, want 200", tc.status, resp.StatusCode)
			}
			users := usersFromBody(t, body)
			if !containsUserID(users, tc.want.String()) {
				t.Errorf("status=%s missing expected user %v", tc.status, tc.want)
			}
			for _, ex := range tc.exclude {
				if containsUserID(users, ex.String()) {
					t.Errorf("status=%s unexpectedly includes user %v", tc.status, ex)
				}
			}
			for _, u := range users {
				if u["status"] != tc.status {
					t.Errorf("status=%s result contains entry with status %v: %v", tc.status, u["status"], u)
				}
			}
		})
	}
}

func TestUsersList_Pagination(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	tag := "paginate" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	const fixtureCount = 5
	ids := make(map[string]bool, fixtureCount)
	for i := 0; i < fixtureCount; i++ {
		_, _, id := e.createMemberNamed(t, tag+"-user")
		ids[id.String()] = true
	}

	seen := make(map[string]bool, fixtureCount)
	pageSizes := []int{2, 2, 1}
	offset := 0
	for _, size := range pageSizes {
		resp, body := e.get(t, client, "/api/users?search="+tag+"&limit=2&offset="+strconv.Itoa(offset))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("paginated list offset=%d = %d, want 200; body=%v", offset, resp.StatusCode, body)
		}
		total, ok := body["total"].(float64)
		if !ok || int(total) != fixtureCount {
			t.Fatalf("total = %v, want %d", body["total"], fixtureCount)
		}
		users := usersFromBody(t, body)
		if len(users) != size {
			t.Fatalf("offset=%d returned %d users, want %d", offset, len(users), size)
		}
		for _, u := range users {
			id := u["id"].(string)
			if !ids[id] {
				t.Errorf("offset=%d returned unexpected user %v", offset, id)
			}
			if seen[id] {
				t.Errorf("offset=%d re-returned user %v already seen on an earlier page", offset, id)
			}
			seen[id] = true
		}
		offset += 2
	}

	if len(seen) != fixtureCount {
		t.Errorf("pages covered %d distinct users, want all %d", len(seen), fixtureCount)
	}
}

func TestUsersList_SortByLastLogin(t *testing.T) {
	e := setup(t)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	tag := "sortlogin" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	earlyEmail, earlyPassword, earlyID := e.createMemberNamed(t, tag+"-early")
	lateEmail, latePassword, lateID := e.createMemberNamed(t, tag+"-late")

	earlyClient := newClient()
	loginResp1, _ := e.login(t, earlyClient, earlyEmail, earlyPassword)
	if loginResp1.StatusCode != http.StatusOK {
		t.Fatalf("early fixture login = %d, want 200", loginResp1.StatusCode)
	}
	// A small gap so the two last_login_at values are unambiguously ordered.
	time.Sleep(50 * time.Millisecond)
	lateClient := newClient()
	loginResp2, _ := e.login(t, lateClient, lateEmail, latePassword)
	if loginResp2.StatusCode != http.StatusOK {
		t.Fatalf("late fixture login = %d, want 200", loginResp2.StatusCode)
	}

	ascResp, ascBody := e.get(t, adminClient, "/api/users?search="+tag+"&sort=last_login_at&order=asc")
	if ascResp.StatusCode != http.StatusOK {
		t.Fatalf("sort asc = %d, want 200", ascResp.StatusCode)
	}
	ascUsers := usersFromBody(t, ascBody)
	if len(ascUsers) != 2 {
		t.Fatalf("sort asc returned %d users, want 2: %v", len(ascUsers), ascUsers)
	}
	if ascUsers[0]["id"] != earlyID.String() || ascUsers[1]["id"] != lateID.String() {
		t.Errorf("sort=last_login_at&order=asc = [%v, %v], want [%v, %v]", ascUsers[0]["id"], ascUsers[1]["id"], earlyID, lateID)
	}

	descResp, descBody := e.get(t, adminClient, "/api/users?search="+tag+"&sort=last_login_at&order=desc")
	if descResp.StatusCode != http.StatusOK {
		t.Fatalf("sort desc = %d, want 200", descResp.StatusCode)
	}
	descUsers := usersFromBody(t, descBody)
	if len(descUsers) != 2 {
		t.Fatalf("sort desc returned %d users, want 2: %v", len(descUsers), descUsers)
	}
	if descUsers[0]["id"] != lateID.String() || descUsers[1]["id"] != earlyID.String() {
		t.Errorf("sort=last_login_at&order=desc = [%v, %v], want [%v, %v]", descUsers[0]["id"], descUsers[1]["id"], lateID, earlyID)
	}
}

// TestUsersList_CountsExcludeSoftDeletedResources directly tests the
// deleted_at caveat flagged in the Step 18 Phase 4 plan: resources.deleted_at
// alone is never set by the Database/ObjectStorage soft-delete path (only
// the type-specific databases.deleted_at/object_storages.deleted_at columns
// are), so CountEffectiveDatabaseAccessPerUser must join to databases and
// check its own deleted_at, not just resources.deleted_at -- otherwise a
// soft-deleted database's grant would silently keep counting forever.
func TestUsersList_CountsExcludeSoftDeletedResources(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	dbID, dbResourceID := e.createDatabaseFixture(t, project)

	_, _, memberID := e.createMember(t)
	e.grantDirectVMAccess(t, memberID, vmResourceID, services.PermVMView)
	e.grantDirectVMAccess(t, memberID, dbResourceID, services.PermDatabaseView)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/users")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list users = %d, want 200", resp.StatusCode)
	}
	before := findUserByID(t, body, memberID.String())
	if v, _ := before["vm_count"].(float64); int64(v) != 1 {
		t.Fatalf("vm_count before delete = %v, want 1", before["vm_count"])
	}
	if v, _ := before["database_count"].(float64); int64(v) != 1 {
		t.Fatalf("database_count before delete = %v, want 1", before["database_count"])
	}

	delResp, _ := e.do(t, client, http.MethodDelete, "/api/databases/"+dbID.String(), map[string]string{"confirmation_name": e.resourceName(t, dbResourceID)})
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete database = %d, want 200", delResp.StatusCode)
	}

	resp2, body2 := e.get(t, client, "/api/users")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("list users after delete = %d, want 200", resp2.StatusCode)
	}
	after := findUserByID(t, body2, memberID.String())
	if v, _ := after["vm_count"].(float64); int64(v) != 1 {
		t.Errorf("vm_count after unrelated database delete = %v, want still 1", after["vm_count"])
	}
	if v, _ := after["database_count"].(float64); int64(v) != 0 {
		t.Errorf("database_count after soft-deleting the database = %v, want 0 (must not keep counting a soft-deleted database's grant)", after["database_count"])
	}
}

func TestUsersList_AdminOnly(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/users?search=x&limit=5&sort=email")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member list users (with query params) = %d, want 403", resp.StatusCode)
	}
}
