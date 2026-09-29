package handlers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// PermissionsHandler implements the unified, cross-resource-type direct-
// grants listing (spec §23's "Permissions" page): every direct
// VM/Database/ObjectStorage resource_permissions row in the system, in one
// place, filterable by resource type/workspace/user/grantee-role.
// Scoped to DIRECT grants only -- workspace-derived access stays visible
// per-resource via each type's own ListAccess endpoint instead, since a
// workspace-derived row here wouldn't be individually revocable the way
// this page's revoke action implies. Admin-only.
type PermissionsHandler struct {
	store *repository.Store
}

// NewPermissionsHandler creates a PermissionsHandler.
func NewPermissionsHandler(store *repository.Store) *PermissionsHandler {
	return &PermissionsHandler{store: store}
}

// permissionGrantResponse is one row per (resource, user, permission) --
// deliberately NOT merged into one row per (resource, user) with a
// permissions[] array. The spec's own §23 table format (Permission,
// Description, Resource, Scope, Role, Status) is a one-row-per-permission
// shape: each permission carries its own description, and a merged row
// would either drop the description (multiple permissions per row can each
// have a different description) or need its own array-of-descriptions
// alongside the permissions array, which is more complex than the
// underlying data actually requires. Returning the joined rows nearly
// as-is is simpler and strictly more correct against the spec's literal
// table shape; a frontend that wants a denser "one row per grant" view can
// still group these client-side by (resource_id, user_id).
type permissionGrantResponse struct {
	ResourceID    string  `json:"resource_id"`
	ResourceType  string  `json:"resource_type"`
	ResourceName  string  `json:"resource_name"`
	WorkspaceID   string  `json:"workspace_id"`
	WorkspaceName string  `json:"workspace_name"`
	UserID        string  `json:"user_id"`
	UserName      string  `json:"user_name"`
	UserEmail     string  `json:"user_email"`
	UserRole      string  `json:"user_role"`
	Permission    string  `json:"permission"`
	Description   string  `json:"description,omitempty"`
	GrantedAt     *string `json:"granted_at,omitempty"`
}

func toPermissionGrantResponse(row generated.ListAllDirectResourceGrantsRow) permissionGrantResponse {
	return permissionGrantResponse{
		ResourceID:    row.ResourceID.String(),
		ResourceType:  row.ResourceType,
		ResourceName:  row.ResourceName,
		WorkspaceID:   row.WorkspaceID.String(),
		WorkspaceName: row.WorkspaceName,
		UserID:        row.UserID.String(),
		UserName:      row.UserName,
		UserEmail:     row.UserEmail,
		UserRole:      row.UserRole,
		Permission:    row.PermissionName,
		Description:   pgutil.TextOrEmpty(row.PermissionDescription),
		GrantedAt:     formatTimestamptz(row.GrantedAt),
	}
}

// nullableUUIDParam parses an optional UUID query param into the
// pgtype.UUID shape ListAllDirectResourceGrantsParams expects (a NULL
// value means "no filter on this field"), or false if the value is
// present but not a valid UUID.
func nullableUUIDParam(raw string) (pgtype.UUID, bool) {
	if raw == "" {
		return pgtype.UUID{}, true
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return pgtype.UUID{}, false
	}
	return pgutil.NullUUID(&id), true
}

func nullableTextParam(raw string) pgtype.Text {
	if raw == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: raw, Valid: true}
}

// List handles GET /api/permissions (admin-only): the direct-grant ledger
// backing the unified Permissions page, optionally filtered by
// resource_type/workspace_id/user_id/role query params.
func (h *PermissionsHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	workspaceID, ok := nullableUUIDParam(q.Get("workspace_id"))
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}
	userID, ok := nullableUUIDParam(q.Get("user_id"))
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	rows, err := h.store.ListAllDirectResourceGrants(r.Context(), generated.ListAllDirectResourceGrantsParams{
		ResourceType: nullableTextParam(q.Get("resource_type")),
		WorkspaceID:  workspaceID,
		UserID:       userID,
		Role:         nullableTextParam(q.Get("role")),
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load permissions")
		return
	}

	grants := make([]permissionGrantResponse, 0, len(rows))
	for _, row := range rows {
		grants = append(grants, toPermissionGrantResponse(row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"grants": grants})
}
