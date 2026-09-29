package handlers

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// MyAccessHandler implements the member-facing "My Access" endpoints:
// VMs (the original Step 3 shape, exposed via VMService.List exactly as
// before), plus, per Step 17 Phase 5 / plan decision #8, Databases and
// Object Storage sections computed the same "list scoped to this caller's
// authorized resources" way GET /api/databases and GET /api/object-storage
// themselves already compute their own responses. Reuses
// DatabaseHandler.permissionsForDatabase / ObjectStorageHandler.
// permissionsForObjectStorage directly (same package, unexported methods)
// rather than reimplementing permission resolution a third time.
type MyAccessHandler struct {
	vms           *services.VMService
	store         *repository.Store
	authz         *services.AuthorizationService
	databases     *DatabaseHandler
	objectStorage *ObjectStorageHandler
}

// NewMyAccessHandler creates a MyAccessHandler.
func NewMyAccessHandler(
	vms *services.VMService, store *repository.Store, authz *services.AuthorizationService,
	databases *DatabaseHandler, objectStorage *ObjectStorageHandler,
) *MyAccessHandler {
	return &MyAccessHandler{vms: vms, store: store, authz: authz, databases: databases, objectStorage: objectStorage}
}

func (h *MyAccessHandler) authorizedVMs(r *http.Request) ([]vmSummary, error) {
	user, _ := services.UserFromContext(r.Context())

	items, err := h.vms.List(r.Context(), user)
	if err != nil {
		return nil, err
	}
	summaries := make([]vmSummary, 0, len(items))
	for _, item := range items {
		summaries = append(summaries, toVMSummary(item.Detail, item.Permissions, item.Source))
	}
	return summaries, nil
}

// authorizedDatabases mirrors DatabaseHandler.List's own scoping exactly
// (nil resource_ids for an Admin -- ListStandaloneDatabasesForDashboard's
// own "NULL = unrestricted" contract -- the caller's
// GetUserDatabaseAccess resource IDs otherwise) and the identical field
// set List's response items carry, so each entry matches the frontend's
// DatabaseListItem contract field-for-field. The one addition on top of
// List's own shape is `permissions`, computed per-row via
// permissionsForDatabase -- the frontend's my-access page true-hides the
// Browse action based on this, so it must reflect the caller's REAL grant,
// never a hardcoded value. Delegates to scopedDatabaseAccess (a package-
// level function, not a method) so UserHandler.Get can compute the exact
// same thing for an admin-specified target user instead of "self".
func (h *MyAccessHandler) authorizedDatabases(r *http.Request) ([]map[string]any, error) {
	user, _ := services.UserFromContext(r.Context())
	return scopedDatabaseAccess(r, h.store, h.authz, h.databases, user)
}

// authorizedObjectStorage mirrors ObjectStorageHandler.List exactly --
// same scoping, same field set, same per-row permissionsForObjectStorage
// call List itself already makes (reused here directly rather than
// reimplemented) -- so every field matches the frontend's
// ObjectStorageListItem contract, `permissions` included. Delegates to
// scopedObjectStorageAccess for the same reason authorizedDatabases
// delegates to scopedDatabaseAccess above.
func (h *MyAccessHandler) authorizedObjectStorage(r *http.Request) ([]map[string]any, error) {
	user, _ := services.UserFromContext(r.Context())
	return scopedObjectStorageAccess(r, h.store, h.authz, h.objectStorage, user)
}

// scopedDatabaseAccess computes the "list scoped to target's authorized
// databases" shape shared by My Access (target = caller) and
// GET /api/users/:id (target = an admin-specified user) -- a package-level
// function rather than a method so both handlers can call it against
// whichever user they need without one depending on the other.
func scopedDatabaseAccess(r *http.Request, store *repository.Store, authz *services.AuthorizationService, databases *DatabaseHandler, user services.AuthenticatedUser) ([]map[string]any, error) {
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		access, err := authz.GetUserDatabaseAccess(r.Context(), user)
		if err != nil {
			return nil, err
		}
		resourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			resourceIDs = append(resourceIDs, a.ResourceID)
		}
	}
	rows, err := store.ListStandaloneDatabasesForDashboard(r.Context(), resourceIDs)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		items = append(items, map[string]any{
			"id": row.ID.String(), "resource_id": row.ResourceID.String(), "name": pgutil.TextOrEmpty(row.ResourceName),
			"workspace_id": pgutil.UUIDPtr(row.WorkspaceID), "workspace_name": pgutil.TextOrEmpty(row.WorkspaceName),
			"type": row.Type, "provider": pgutil.TextOrEmpty(row.Provider),
			"host": row.Host, "port": row.Port, "database_name": pgutil.TextOrEmpty(row.DatabaseName),
			"monitoring_enabled": row.MonitoringEnabled, "connection_status": row.ConnectionStatus,
			"health": row.LatestHealth, "last_metric_at": formatTimestamptz(row.LatestMetricAt),
			"permissions": databases.permissionsForDatabase(r, user, row.ResourceID),
		})
	}
	return items, nil
}

// scopedObjectStorageAccess mirrors scopedDatabaseAccess exactly, for
// object storage -- see that function's comment.
func scopedObjectStorageAccess(r *http.Request, store *repository.Store, authz *services.AuthorizationService, objectStorage *ObjectStorageHandler, user services.AuthenticatedUser) ([]map[string]any, error) {
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		access, err := authz.GetUserObjectStorageAccess(r.Context(), user)
		if err != nil {
			return nil, err
		}
		resourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			resourceIDs = append(resourceIDs, a.ResourceID)
		}
	}
	rows, err := store.ListObjectStoragesForDashboard(r.Context(), resourceIDs)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		item := map[string]any{
			"id": row.ID.String(), "resource_id": row.ResourceID.String(), "name": pgutil.TextOrEmpty(row.ResourceName),
			"workspace_id": pgutil.UUIDPtr(row.WorkspaceID), "workspace_name": pgutil.TextOrEmpty(row.WorkspaceName),
			"provider": row.Provider, "endpoint": pgutil.TextOrEmpty(row.Endpoint),
			"region": pgutil.TextOrEmpty(row.Region), "bucket": row.Bucket, "base_path": pgutil.TextOrEmpty(row.BasePath),
			"monitoring_enabled": row.MonitoringEnabled, "connection_status": row.ConnectionStatus, "health_status": row.HealthStatus,
			"permissions": objectStorage.permissionsForObjectStorage(r, user, row.ResourceID),
		}
		objectCount, totalSizeBytes, lastCheckedAt := objectStorage.latestMetricSummary(r, row.ID)
		if objectCount != nil {
			item["object_count"] = *objectCount
		}
		if totalSizeBytes != nil {
			item["total_size_bytes"] = *totalSizeBytes
		}
		if lastCheckedAt != nil {
			item["last_checked_at"] = *lastCheckedAt
		}
		items = append(items, item)
	}
	return items, nil
}

// workspacesForUser returns user's Workspaces section: every workspace in
// the system for an Admin (access is unconditional/global, mirroring
// GetUserVMAccess's own Admin behavior -- an Admin need not personally
// belong to any workspace) or user's real workspace memberships plus every
// workspace containing a resource they hold a direct grant on otherwise
// (via ListWorkspacesForUserAccess -- mirrors the member-union logic that
// used to be split across groupsForUser/projectsForUser before Workspace
// replaced Project+Group). Shared by My Access (target = caller) and
// GET /api/users/:id (target = an admin-specified user).
func workspacesForUser(ctx context.Context, store *repository.Store, user services.AuthenticatedUser) ([]workspaceMembership, error) {
	if user.IsAdmin() {
		rows, err := store.ListAllWorkspaces(ctx)
		if err != nil {
			return nil, err
		}
		workspaces := make([]workspaceMembership, 0, len(rows))
		for _, w := range rows {
			workspaces = append(workspaces, workspaceMembership{WorkspaceID: w.WorkspaceID.String(), WorkspaceName: w.WorkspaceName})
		}
		return workspaces, nil
	}
	rows, err := store.ListWorkspacesForUserAccess(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	workspaces := make([]workspaceMembership, 0, len(rows))
	for _, w := range rows {
		workspaces = append(workspaces, workspaceMembership{WorkspaceID: w.ID.String(), WorkspaceName: w.Name})
	}
	return workspaces, nil
}

// Get handles GET /api/my-access: {"vms": [...], "databases": [...],
// "object_storage": [...]}, extended per Step 17 Phase 5 / plan decision #8
// from the original Step 3 VM-only shape (spec §40 explicitly asks for
// "Authorized Databases"/"Authorized Object Storage" too). Empty and error
// responses never distinguish "no access" from "some access you can't
// see" -- an empty section is always exactly `[]`, never omitted. It
// automatically reflects any group/direct assignment change the moment
// it's made (Step 4 §21) since every section is computed live from
// resource_permissions/group_members on every call, never cached. An Admin
// caller sees every VM/database/object storage in the system (mirrors
// GetUserVMAccess's own Admin behavior -- Admins bypass explicit grants
// the same way everywhere else in this codebase, so the two new keys
// behave identically rather than inventing separate semantics).
//
// Also adds `workspaces`: the flat "Your Workspaces" list, via
// workspacesForUser -- shares the exact Admin-sees-everything/Member-sees-
// derived split the vms/databases/object_storage sections above already
// use.
func (h *MyAccessHandler) Get(w http.ResponseWriter, r *http.Request) {
	user, _ := services.UserFromContext(r.Context())

	vms, err := h.authorizedVMs(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load access")
		return
	}
	databases, err := h.authorizedDatabases(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load access")
		return
	}
	objectStorage, err := h.authorizedObjectStorage(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load access")
		return
	}
	workspaces, err := workspacesForUser(r.Context(), h.store, user)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load access")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"vms": vms, "databases": databases, "object_storage": objectStorage,
		"workspaces": workspaces,
	})
}

// ListVMs handles GET /api/my-access/vms: the bare VM array, for a client
// that only wants to refresh the VM list without the rest of the My Access
// payload.
func (h *MyAccessHandler) ListVMs(w http.ResponseWriter, r *http.Request) {
	vms, err := h.authorizedVMs(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load access")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, vms)
}
