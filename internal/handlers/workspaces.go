package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// WorkspaceHandler implements admin workspace management and workspace
// membership. Every route here is mounted behind RequireRole(ADMIN) except
// List (any authenticated role may see the workspace picker).
type WorkspaceHandler struct {
	workspaces *services.WorkspaceService
	audit      *services.AuditService
}

// NewWorkspaceHandler creates a WorkspaceHandler.
func NewWorkspaceHandler(workspaces *services.WorkspaceService, audit *services.AuditService) *WorkspaceHandler {
	return &WorkspaceHandler{workspaces: workspaces, audit: audit}
}

type workspaceResponse struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description,omitempty"`
	IsActive           bool   `json:"is_active"`
	VMCount            int64  `json:"vm_count"`
	DatabaseCount      int64  `json:"database_count"`
	ObjectStorageCount int64  `json:"object_storage_count"`
	DockerHostCount    int64  `json:"docker_host_count"`
	K8sClusterCount    int64  `json:"k8s_cluster_count"`
	MemberCount        int64  `json:"member_count"`
}

func toWorkspaceResponse(w generated.Workspace) workspaceResponse {
	return workspaceResponse{
		ID:          w.ID.String(),
		Name:        w.Name,
		Description: pgutil.TextOrEmpty(w.Description),
		IsActive:    w.IsActive,
	}
}

type createWorkspaceRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Create handles POST /api/workspaces.
func (h *WorkspaceHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	workspace, err := h.workspaces.Create(r.Context(), req.Name, req.Description)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditWorkspaceCreated,
		ResourceType: "WORKSPACE", ResourceID: &workspace.ID,
		Metadata: map[string]any{"name": workspace.Name},
	})

	httpx.WriteJSON(w, http.StatusCreated, toWorkspaceResponse(workspace))
}

// List handles GET /api/workspaces -- every workspace with its counts, the
// picker source for every VM/Database/Object Storage/Docker/Kubernetes
// create flow as well as the admin Manage Workspaces page.
func (h *WorkspaceHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.workspaces.List(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}

	workspaces := make([]workspaceResponse, 0, len(rows))
	for _, row := range rows {
		workspaces = append(workspaces, workspaceResponse{
			ID:                 row.ID.String(),
			Name:               row.Name,
			Description:        pgutil.TextOrEmpty(row.Description),
			IsActive:           row.IsActive,
			VMCount:            row.VmCount,
			DatabaseCount:      row.DatabaseCount,
			ObjectStorageCount: row.ObjectStorageCount,
			DockerHostCount:    row.DockerHostCount,
			K8sClusterCount:    row.K8sClusterCount,
			MemberCount:        row.MemberCount,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"workspaces": workspaces})
}

// Get handles GET /api/workspaces/:id.
func (h *WorkspaceHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}

	row, err := h.workspaces.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, workspaceResponse{
		ID:                 row.ID.String(),
		Name:               row.Name,
		Description:        pgutil.TextOrEmpty(row.Description),
		IsActive:           row.IsActive,
		VMCount:            row.VmCount,
		DatabaseCount:      row.DatabaseCount,
		ObjectStorageCount: row.ObjectStorageCount,
		DockerHostCount:    row.DockerHostCount,
		K8sClusterCount:    row.K8sClusterCount,
		MemberCount:        row.MemberCount,
	})
}

type updateWorkspaceRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

// Update handles PATCH /api/workspaces/:id.
func (h *WorkspaceHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}

	var req updateWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existing, err := h.workspaces.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	name := existing.Name
	if req.Name != nil {
		name = *req.Name
	}
	description := pgutil.TextOrEmpty(existing.Description)
	if req.Description != nil {
		description = *req.Description
	}
	isActive := existing.IsActive
	wasActive := existing.IsActive
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	updated, err := h.workspaces.Update(r.Context(), id, name, description, isActive)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	action := services.AuditWorkspaceUpdated
	if wasActive && !isActive {
		action = services.AuditWorkspaceDeactivated
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: action,
		ResourceType: "WORKSPACE", ResourceID: &updated.ID,
	})

	httpx.WriteJSON(w, http.StatusOK, toWorkspaceResponse(updated))
}

// Delete handles DELETE /api/workspaces/:id. Permanent and irreversible --
// distinct from Update's is_active deactivation. Requires the workspace's
// exact current name as confirmation_name, and is blocked while the
// workspace still has any VM/database/object storage (WorkspaceService.
// Delete enforces this).
func (h *WorkspaceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	var req deleteConfirmationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existing, err := h.workspaces.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if err := h.workspaces.Delete(r.Context(), id, req.ConfirmationName); err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditWorkspaceDeleted,
		ResourceType: "WORKSPACE", ResourceID: &id,
		Metadata: map[string]any{"name": existing.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

type workspaceMemberResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	IsActive     bool   `json:"is_active"`
	AccessSource string `json:"access_source"`
}

// ListMembers handles GET /api/workspaces/:workspaceId/members.
func (h *WorkspaceHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	workspaceID, err := uuid.Parse(r.PathValue("workspaceId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}

	users, err := h.workspaces.ListMembers(r.Context(), workspaceID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	members := make([]workspaceMemberResponse, 0, len(users))
	for _, u := range users {
		members = append(members, workspaceMemberResponse{
			ID: u.ID.String(), Name: u.Name, Email: u.Email, IsActive: u.IsActive,
			AccessSource: string(services.SourceWorkspace),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"members": members})
}

type addWorkspaceMemberRequest struct {
	UserID string `json:"user_id"`
}

// AddMember handles POST /api/workspaces/:workspaceId/members.
func (h *WorkspaceHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	workspaceID, err := uuid.Parse(r.PathValue("workspaceId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}

	var req addWorkspaceMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	if err := h.workspaces.AddMember(r.Context(), workspaceID, userID); err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditWorkspaceMemberAdded,
		ResourceType: "WORKSPACE", ResourceID: &workspaceID,
		Metadata: map[string]any{"target_user_id": userID.String()},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// RemoveMember handles DELETE /api/workspaces/:workspaceId/members/:userId.
// This only removes workspace-derived access; any direct VM/database/
// object storage grants the user has remain in effect.
func (h *WorkspaceHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	workspaceID, err := uuid.Parse(r.PathValue("workspaceId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	userID, err := uuid.Parse(r.PathValue("userId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}

	if err := h.workspaces.RemoveMember(r.Context(), workspaceID, userID); err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditWorkspaceMemberRemoved,
		ResourceType: "WORKSPACE", ResourceID: &workspaceID,
		Metadata: map[string]any{"target_user_id": userID.String()},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
