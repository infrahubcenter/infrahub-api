// This file exercises the per-user saved dashboard views feature ("save
// in dashboard name inside monitoring and logs I can able to create") --
// private per-user, scoped by feature, and re-saving under an existing
// name replaces it.
package server_test

import (
	"net/http"
	"testing"
)

func TestSavedViews_CreateListLoad(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/saved-views", map[string]any{
		"feature": "docker_monitor", "name": "My Apps", "filters": map[string]any{"search": "checkout"},
	})
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("create saved view = %d, want 200: %v", createResp.StatusCode, createBody)
	}
	if createBody["name"] != "My Apps" {
		t.Errorf("expected name 'My Apps', got %v", createBody["name"])
	}

	listResp, listBody := e.get(t, client, "/api/saved-views?feature=docker_monitor")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list saved views = %d, want 200", listResp.StatusCode)
	}
	views, _ := listBody["views"].([]any)
	if len(views) != 1 {
		t.Fatalf("expected exactly 1 saved view, got %d", len(views))
	}
	view := views[0].(map[string]any)
	filters, _ := view["filters"].(map[string]any)
	if filters["search"] != "checkout" {
		t.Errorf("expected saved filters to round-trip, got %v", view["filters"])
	}

	// A different feature must never see this one.
	otherResp, otherBody := e.get(t, client, "/api/saved-views?feature=k8s_monitor")
	if otherResp.StatusCode != http.StatusOK {
		t.Fatalf("list saved views (other feature) = %d, want 200", otherResp.StatusCode)
	}
	if otherViews, _ := otherBody["views"].([]any); len(otherViews) != 0 {
		t.Errorf("expected 0 saved views for a different feature, got %d", len(otherViews))
	}
}

func TestSavedViews_SavingSameNameReplaces(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	e.do(t, client, http.MethodPost, "/api/saved-views", map[string]any{
		"feature": "docker_logs", "name": "View", "filters": map[string]any{"q": "error"},
	})
	e.do(t, client, http.MethodPost, "/api/saved-views", map[string]any{
		"feature": "docker_logs", "name": "View", "filters": map[string]any{"q": "panic"},
	})

	listResp, listBody := e.get(t, client, "/api/saved-views?feature=docker_logs")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list saved views = %d, want 200", listResp.StatusCode)
	}
	views, _ := listBody["views"].([]any)
	if len(views) != 1 {
		t.Fatalf("expected re-saving under the same name to replace, not duplicate -- got %d views", len(views))
	}
	filters, _ := views[0].(map[string]any)["filters"].(map[string]any)
	if filters["q"] != "panic" {
		t.Errorf("expected the replaced filters, got %v", filters)
	}
}

func TestSavedViews_PrivatePerUser(t *testing.T) {
	e := setup(t)
	member1Email, member1Password, _ := e.createMember(t)
	member2Email, member2Password, _ := e.createMember(t)

	client1 := newClient()
	e.login(t, client1, member1Email, member1Password)
	createResp, createBody := e.do(t, client1, http.MethodPost, "/api/saved-views", map[string]any{
		"feature": "k8s_logs", "name": "Only Mine", "filters": map[string]any{},
	})
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("create saved view = %d, want 200", createResp.StatusCode)
	}
	viewID, _ := createBody["id"].(string)

	client2 := newClient()
	e.login(t, client2, member2Email, member2Password)
	listResp, listBody := e.get(t, client2, "/api/saved-views?feature=k8s_logs")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list saved views = %d, want 200", listResp.StatusCode)
	}
	if views, _ := listBody["views"].([]any); len(views) != 0 {
		t.Fatalf("expected user 2 to see 0 of user 1's saved views, got %d", len(views))
	}

	// User 2 cannot delete user 1's view either, even by guessing its ID.
	deleteResp, _ := e.do(t, client2, http.MethodDelete, "/api/saved-views/"+viewID, nil)
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("delete (as a different user) = %d, want 200 (a silent no-op, per DELETE's idempotent convention)", deleteResp.StatusCode)
	}
	stillThereResp, stillThereBody := e.get(t, client1, "/api/saved-views?feature=k8s_logs")
	if stillThereResp.StatusCode != http.StatusOK {
		t.Fatalf("list saved views = %d, want 200", stillThereResp.StatusCode)
	}
	if views, _ := stillThereBody["views"].([]any); len(views) != 1 {
		t.Errorf("expected user 1's view to survive user 2's delete attempt, got %d views", len(views))
	}
}

// Folder > Dashboard: a dashboard can be saved inside a folder, or
// standalone (no folder_id) when created straight from the top level.
func TestSavedViewFolders_CreateAndSaveDashboardInside(t *testing.T) {
	e := setup(t)
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	folderResp, folderBody := e.do(t, client, http.MethodPost, "/api/saved-view-folders", map[string]any{
		"feature": "docker_monitor", "name": "Production",
	})
	if folderResp.StatusCode != http.StatusOK {
		t.Fatalf("create folder = %d, want 200: %v", folderResp.StatusCode, folderBody)
	}
	folderID, _ := folderBody["id"].(string)
	if folderID == "" {
		t.Fatal("expected a non-empty folder id")
	}

	listFoldersResp, listFoldersBody := e.get(t, client, "/api/saved-view-folders?feature=docker_monitor")
	if listFoldersResp.StatusCode != http.StatusOK {
		t.Fatalf("list folders = %d, want 200", listFoldersResp.StatusCode)
	}
	if folders, _ := listFoldersBody["folders"].([]any); len(folders) != 1 {
		t.Fatalf("expected exactly 1 folder, got %d", len(folders))
	}

	// A dashboard saved with folder_id lands inside the folder.
	insideResp, insideBody := e.do(t, client, http.MethodPost, "/api/saved-views", map[string]any{
		"feature": "docker_monitor", "name": "Checkout Service", "filters": map[string]any{}, "folder_id": folderID,
	})
	if insideResp.StatusCode != http.StatusOK {
		t.Fatalf("create dashboard inside folder = %d, want 200: %v", insideResp.StatusCode, insideBody)
	}
	if insideBody["folder_id"] != folderID {
		t.Errorf("expected folder_id to round-trip, got %v", insideBody["folder_id"])
	}

	// A dashboard saved with no folder_id stands alone.
	standaloneResp, standaloneBody := e.do(t, client, http.MethodPost, "/api/saved-views", map[string]any{
		"feature": "docker_monitor", "name": "Standalone Dashboard", "filters": map[string]any{},
	})
	if standaloneResp.StatusCode != http.StatusOK {
		t.Fatalf("create standalone dashboard = %d, want 200: %v", standaloneResp.StatusCode, standaloneBody)
	}
	if _, present := standaloneBody["folder_id"]; present {
		t.Errorf("expected no folder_id on a standalone dashboard, got %v", standaloneBody["folder_id"])
	}

	// Deleting the folder cascades to the dashboard saved inside it, but
	// leaves the standalone dashboard untouched.
	deleteFolderResp, _ := e.do(t, client, http.MethodDelete, "/api/saved-view-folders/"+folderID, nil)
	if deleteFolderResp.StatusCode != http.StatusOK {
		t.Fatalf("delete folder = %d, want 200", deleteFolderResp.StatusCode)
	}
	finalListResp, finalListBody := e.get(t, client, "/api/saved-views?feature=docker_monitor")
	if finalListResp.StatusCode != http.StatusOK {
		t.Fatalf("list saved views = %d, want 200", finalListResp.StatusCode)
	}
	views, _ := finalListBody["views"].([]any)
	if len(views) != 1 {
		t.Fatalf("expected only the standalone dashboard to survive folder deletion, got %d", len(views))
	}
	if views[0].(map[string]any)["name"] != "Standalone Dashboard" {
		t.Errorf("expected the surviving dashboard to be the standalone one, got %v", views[0])
	}
}

// A caller can't save a dashboard into another user's folder, even by
// guessing its ID -- ownership is checked, not just existence.
func TestSavedViewFolders_CannotSaveIntoAnotherUsersFolder(t *testing.T) {
	e := setup(t)
	member1Email, member1Password, _ := e.createMember(t)
	member2Email, member2Password, _ := e.createMember(t)

	client1 := newClient()
	e.login(t, client1, member1Email, member1Password)
	folderResp, folderBody := e.do(t, client1, http.MethodPost, "/api/saved-view-folders", map[string]any{
		"feature": "k8s_logs", "name": "User 1 Folder",
	})
	if folderResp.StatusCode != http.StatusOK {
		t.Fatalf("create folder = %d, want 200", folderResp.StatusCode)
	}
	folderID, _ := folderBody["id"].(string)

	client2 := newClient()
	e.login(t, client2, member2Email, member2Password)
	resp, body := e.do(t, client2, http.MethodPost, "/api/saved-views", map[string]any{
		"feature": "k8s_logs", "name": "Sneaky", "filters": map[string]any{}, "folder_id": folderID,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("save into another user's folder = %d, want 400: %v", resp.StatusCode, body)
	}
}
