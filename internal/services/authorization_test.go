package services_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database"
	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

func setupAuthz(t *testing.T) (*services.AuthorizationService, *repository.Store) {
	t.Helper()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL not set; skipping authorization service test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, databaseURL, database.PoolConfig{
		MaxConns: 5, MinConns: 1, ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("connect to database: %v", err)
	}
	t.Cleanup(pool.Close)

	store := repository.New(pool)
	return services.NewAuthorizationService(store.Queries), store
}

// mustCreateVMResource creates a fresh workspace and a VM in it (ungrouped,
// same shape used everywhere else in this project -- Workspace is a flat
// tier, so there is no separate "grouped" case to construct).
func mustCreateVMResource(t *testing.T, store *repository.Store) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	workspace, err := store.CreateWorkspace(ctx, generated.CreateWorkspaceParams{Name: "authz-test-workspace-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	return mustCreateVMResourceIn(t, store, workspace.ID)
}

func mustCreateVMResourceIn(t *testing.T, store *repository.Store, workspaceID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	resource, err := store.CreateResource(ctx, generated.CreateResourceParams{
		WorkspaceID:  workspaceID,
		Name:         "authz-test-vm-" + uuid.NewString(),
		ResourceType: "VM",
	})
	if err != nil {
		t.Fatalf("create resource: %v", err)
	}
	if _, err := store.CreateVM(ctx, generated.CreateVMParams{
		ResourceID: resource.ID, Hostname: resource.Name, Address: "10.0.0.1", SshPort: 22,
	}); err != nil {
		t.Fatalf("create vm: %v", err)
	}
	return resource.ID
}

// mustCreateUser creates a real users row (a random UUID alone won't
// satisfy resource_permissions.user_id's foreign key).
func mustCreateUser(t *testing.T, store *repository.Store) uuid.UUID {
	t.Helper()
	u, err := store.CreateUser(context.Background(), generated.CreateUserParams{
		Email:        "authz-test-" + uuid.NewString() + "@security-test.local",
		Name:         "Authz Test User",
		PasswordHash: "unused-in-this-test",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u.ID
}

// Console (vm.connect) authorization is the primitive a future SSH console
// endpoint will call. It must default to deny -- no grant, no permission --
// exactly like every other permission check (Step 3 §48: "Never assume VM
// visible = console access").
func TestCanAccessVM_ConsoleDeniedByDefault(t *testing.T) {
	authz, store := setupAuthz(t)
	vmID := mustCreateVMResource(t, store)
	userID := mustCreateUser(t, store)

	user := services.AuthenticatedUser{ID: userID, Role: services.RoleMember}

	allowed, err := authz.CanAccessVM(context.Background(), user, vmID, services.PermVMConnect)
	if err != nil {
		t.Fatalf("CanAccessVM: %v", err)
	}
	if allowed {
		t.Fatal("expected console access to be denied with no grant at all")
	}
}

// A view-only grant must not imply console access -- vm.view and
// vm.connect are independent permissions (Step 3 §47).
func TestCanAccessVM_ViewGrantDoesNotImplyConnect(t *testing.T) {
	authz, store := setupAuthz(t)
	vmID := mustCreateVMResource(t, store)
	userID := mustCreateUser(t, store)
	user := services.AuthenticatedUser{ID: userID, Role: services.RoleMember}

	viewPerm, err := store.GetPermissionByName(context.Background(), services.PermVMView)
	if err != nil {
		t.Fatalf("load vm.view permission: %v", err)
	}
	if err := store.GrantResourcePermission(context.Background(), generated.GrantResourcePermissionParams{
		ResourceID: vmID, UserID: userID, PermissionID: viewPerm.ID,
	}); err != nil {
		t.Fatalf("grant vm.view: %v", err)
	}

	canView, err := authz.CanAccessVM(context.Background(), user, vmID, services.PermVMView)
	if err != nil || !canView {
		t.Fatalf("CanAccessVM(vm.view) = %v, %v; want true, nil", canView, err)
	}

	canConnect, err := authz.CanAccessVM(context.Background(), user, vmID, services.PermVMConnect)
	if err != nil {
		t.Fatalf("CanAccessVM(vm.connect): %v", err)
	}
	if canConnect {
		t.Fatal("vm.view grant must not imply vm.connect")
	}
}

// A nonexistent VM ID must deny, not error -- this is what makes the
// 404-not-403 policy possible: the handler doesn't need to distinguish
// "no such VM" from "not authorized".
func TestCanAccessVM_NonexistentVM_DeniesWithoutError(t *testing.T) {
	authz, _ := setupAuthz(t)
	user := services.AuthenticatedUser{ID: uuid.New(), Role: services.RoleMember}

	allowed, err := authz.CanAccessVM(context.Background(), user, uuid.New(), services.PermVMView)
	if err != nil {
		t.Fatalf("CanAccessVM on nonexistent VM returned an error: %v", err)
	}
	if allowed {
		t.Fatal("nonexistent VM must never be reported as accessible")
	}
}

// Direct and workspace grants for the same VM must merge into one entry
// with the union of permissions, not appear twice (Step 3 §19).
func TestGetUserVMAccess_MergesDirectAndGroupGrants(t *testing.T) {
	authz, store := setupAuthz(t)
	ctx := context.Background()

	workspace, err := store.CreateWorkspace(ctx, generated.CreateWorkspaceParams{Name: "authz-merge-workspace-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	vmID := mustCreateVMResourceIn(t, store, workspace.ID)

	userID := mustCreateUser(t, store)
	if err := store.AddWorkspaceMember(ctx, generated.AddWorkspaceMemberParams{WorkspaceID: workspace.ID, UserID: userID}); err != nil {
		t.Fatalf("add workspace member: %v", err)
	}
	viewPerm, err := store.GetPermissionByName(ctx, services.PermVMView)
	if err != nil {
		t.Fatalf("load permission: %v", err)
	}
	if err := store.GrantResourcePermission(ctx, generated.GrantResourcePermissionParams{
		ResourceID: vmID, UserID: userID, PermissionID: viewPerm.ID,
	}); err != nil {
		t.Fatalf("grant direct vm.view: %v", err)
	}

	access, err := authz.GetUserVMAccess(ctx, services.AuthenticatedUser{ID: userID, Role: services.RoleMember})
	if err != nil {
		t.Fatalf("GetUserVMAccess: %v", err)
	}

	matches := 0
	for _, a := range access {
		if a.ResourceID != vmID {
			continue
		}
		matches++
		hasView, hasConnect := false, false
		for _, p := range a.Permissions {
			if p == services.PermVMView {
				hasView = true
			}
			if p == services.PermVMConnect {
				hasConnect = true
			}
		}
		if !hasView || !hasConnect {
			t.Errorf("merged permissions = %v, want both vm.view and vm.connect", a.Permissions)
		}
	}
	if matches != 1 {
		t.Fatalf("VM appeared %d times in GetUserVMAccess, want exactly 1 (merged, not duplicated)", matches)
	}
}
