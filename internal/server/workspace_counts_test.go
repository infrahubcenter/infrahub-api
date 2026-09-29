// Workspace detail/list responses carry database_count/object_storage_count
// alongside vm_count/member_count (spec §68-69's "VMs / Databases / Object
// Storage side by side"). These tests cover both the happy-path count and
// the correctness requirement the count queries' own SQL comments document:
// a soft-deleted standalone database/object storage (which only ever sets
// deleted_at on the databases/object_storages child row, never on the
// owning resources row -- unlike a VM) must NOT still be counted.
package server_test

import (
	"context"
	"net/http"
	"testing"
)

func TestWorkspaceGet_IncludesDatabaseAndObjectStorageCounts(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	e.createDatabaseFixture(t, workspace)
	e.createDatabaseFixture(t, workspace)
	e.createObjectStorageFixture(t, workspace)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/workspaces/"+workspace.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get workspace status = %d, want 200", resp.StatusCode)
	}
	if got := body["database_count"].(float64); got != 2 {
		t.Errorf("workspace database_count = %v, want 2", body["database_count"])
	}
	if got := body["object_storage_count"].(float64); got != 1 {
		t.Errorf("workspace object_storage_count = %v, want 1", body["object_storage_count"])
	}
}

func TestWorkspaceList_IncludesDatabaseAndObjectStorageCounts(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	e.createDatabaseFixture(t, workspace)
	e.createObjectStorageFixture(t, workspace)
	e.createObjectStorageFixture(t, workspace)

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodGet, "/api/workspaces", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list workspaces status = %d, want 200", resp.StatusCode)
	}
	workspaces, _ := body["workspaces"].([]any)
	found := false
	for _, w := range workspaces {
		row := w.(map[string]any)
		if row["id"] != workspace.String() {
			continue
		}
		found = true
		if got := row["database_count"].(float64); got != 1 {
			t.Errorf("workspace list database_count = %v, want 1", row["database_count"])
		}
		if got := row["object_storage_count"].(float64); got != 2 {
			t.Errorf("workspace list object_storage_count = %v, want 2", row["object_storage_count"])
		}
	}
	if !found {
		t.Fatalf("workspace %v not found in workspace list", workspace)
	}
}

// TestWorkspaceCounts_ExcludeSoftDeletedDatabaseAndObjectStorage guards the
// deviation these count queries make from a literal vm_count mirror:
// vm_count's WHERE r.deleted_at IS NULL alone is NOT sufficient for
// database_count/object_storage_count, because SoftDeleteDatabaseResource/
// SoftDeleteObjectStorageResource only ever set deleted_at on the
// databases/object_storages child row, never on the owning resources row.
func TestWorkspaceCounts_ExcludeSoftDeletedDatabaseAndObjectStorage(t *testing.T) {
	e := setup(t)
	workspace := e.createWorkspace(t)
	dbID, _ := e.createDatabaseFixture(t, workspace)
	storageID, _ := e.createObjectStorageFixture(t, workspace)

	if err := e.databases.Delete(context.Background(), dbID); err != nil {
		t.Fatalf("soft-delete database fixture: %v", err)
	}
	if err := e.objectStorages.Delete(context.Background(), storageID); err != nil {
		t.Fatalf("soft-delete object storage fixture: %v", err)
	}

	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/workspaces/"+workspace.String())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get workspace status = %d, want 200", resp.StatusCode)
	}
	if got := body["database_count"].(float64); got != 0 {
		t.Errorf("workspace database_count after soft-delete = %v, want 0 (a deleted database must not still be counted)", body["database_count"])
	}
	if got := body["object_storage_count"].(float64); got != 0 {
		t.Errorf("workspace object_storage_count after soft-delete = %v, want 0 (a deleted object storage must not still be counted)", body["object_storage_count"])
	}
}
