// Package handlers: docker_access.go implements the Docker Access admin
// page -- CRUD over docker_access_grants (Workspace-scoped, view-only
// docker.monitor/docker.logs/k8s.monitor/k8s.logs grants), plus a
// member-facing "what do I have access to" read. Every mutating route is
// mounted behind requireAdmin in router.go; MyAccess is authenticated-any-
// role.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// accessGrantedAction/accessRevokedAction pick the audit action matching
// which feature area a docker_access_grants permission belongs to (the
// table also carries k8s.monitor/k8s.logs -- see
// services.validDockerPermissions), so the audit trail still distinguishes
// Docker grants from K8s grants despite the shared table/service/handler.
func accessGrantedAction(permission string) string {
	if strings.HasPrefix(permission, "k8s.") {
		return services.AuditK8sAccessGranted
	}
	return services.AuditDockerAccessGranted
}

func accessRevokedAction(permission string) string {
	if strings.HasPrefix(permission, "k8s.") {
		return services.AuditK8sAccessRevoked
	}
	return services.AuditDockerAccessRevoked
}

type DockerAccessHandler struct {
	store  *repository.Store
	access *services.DockerAccessService
	audit  *services.AuditService
}

func NewDockerAccessHandler(store *repository.Store, access *services.DockerAccessService, audit *services.AuditService) *DockerAccessHandler {
	return &DockerAccessHandler{store: store, access: access, audit: audit}
}

type dockerAccessGrantRequest struct {
	UserID      string `json:"user_id"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	ResourceID  string `json:"resource_id,omitempty"`
	FolderID    string `json:"folder_id,omitempty"`
	DashboardID string `json:"dashboard_id,omitempty"`
	Permission  string `json:"permission"`
}

// Grant handles POST /api/docker/access-grants. Exactly one of
// dashboard_id, folder_id, resource_id, workspace_id must be set; if
// somehow more than one is present, the most specific scope wins in that
// order (dashboard > folder > resource > workspace).
func (h *DockerAccessHandler) Grant(w http.ResponseWriter, r *http.Request) {
	var req dockerAccessGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	in := services.GrantInput{Permission: req.Permission}
	switch {
	case req.DashboardID != "":
		id, err := uuid.Parse(req.DashboardID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid dashboard_id")
			return
		}
		in.MonitoringDashboardID = &id
	case req.FolderID != "":
		id, err := uuid.Parse(req.FolderID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid folder_id")
			return
		}
		in.MonitoringFolderID = &id
	case req.ResourceID != "":
		id, err := uuid.Parse(req.ResourceID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid resource_id")
			return
		}
		in.ResourceID = &id
	default:
		id, err := uuid.Parse(req.WorkspaceID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
			return
		}
		in.WorkspaceID = &id
	}

	actor, _ := services.UserFromContext(r.Context())
	in.UserID, in.GrantedBy = userID, actor.ID
	scopeName, err := h.access.Grant(r.Context(), in)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	metadata := map[string]any{"permission": req.Permission, "scope_name": scopeName}
	switch {
	case in.MonitoringDashboardID != nil:
		metadata["dashboard_id"] = in.MonitoringDashboardID.String()
	case in.MonitoringFolderID != nil:
		metadata["folder_id"] = in.MonitoringFolderID.String()
	case in.ResourceID != nil:
		metadata["resource_id"] = in.ResourceID.String()
	default:
		metadata["workspace_id"] = in.WorkspaceID.String()
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: accessGrantedAction(req.Permission), ResourceType: "USER", ResourceID: &userID,
		Metadata: metadata,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Revoke handles DELETE /api/docker/access-grants/:id.
func (h *DockerAccessHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	grantID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "grant not found")
		return
	}
	grant, err := h.access.Revoke(r.Context(), grantID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	metadata := map[string]any{"permission": grant.Permission, "grant_id": grantID.String(), "scope_type": grant.ScopeType}
	if id := pgutil.UUIDPtr(grant.WorkspaceID); id != nil {
		metadata["workspace_id"] = *id
	}
	if id := pgutil.UUIDPtr(grant.ResourceID); id != nil {
		metadata["resource_id"] = *id
	}
	if id := pgutil.UUIDPtr(grant.MonitoringFolderID); id != nil {
		metadata["folder_id"] = *id
	}
	if id := pgutil.UUIDPtr(grant.MonitoringDashboardID); id != nil {
		metadata["dashboard_id"] = *id
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: accessRevokedAction(grant.Permission), ResourceType: "USER", ResourceID: &grant.UserID,
		Metadata: metadata,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type dockerAccessGrantDTO struct {
	ID            string  `json:"id"`
	UserID        string  `json:"user_id,omitempty"`
	UserName      string  `json:"user_name,omitempty"`
	UserEmail     string  `json:"user_email,omitempty"`
	ScopeType     string  `json:"scope_type"`
	WorkspaceID   *string `json:"workspace_id,omitempty"`
	WorkspaceName *string `json:"workspace_name,omitempty"`
	ResourceID    *string `json:"resource_id,omitempty"`
	ResourceName  *string `json:"resource_name,omitempty"`
	FolderID      *string `json:"folder_id,omitempty"`
	FolderName    *string `json:"folder_name,omitempty"`
	DashboardID   *string `json:"dashboard_id,omitempty"`
	DashboardName *string `json:"dashboard_name,omitempty"`
	Permission    string  `json:"permission"`
	CreatedAt     string  `json:"created_at"`
}

// ListAll handles GET /api/docker/access-grants (admin management view).
func (h *DockerAccessHandler) ListAll(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.ListAllDockerAccessGrants(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load access grants")
		return
	}
	items := make([]dockerAccessGrantDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, dockerAccessGrantDTO{
			ID: row.ID.String(), UserID: row.UserID.String(), UserName: row.UserName, UserEmail: row.UserEmail,
			ScopeType: row.ScopeType, WorkspaceID: pgutil.UUIDPtr(row.WorkspaceID), WorkspaceName: pgutil.StringPtr(row.WorkspaceName),
			ResourceID: pgutil.UUIDPtr(row.ResourceID), ResourceName: pgutil.StringPtr(row.ResourceName),
			FolderID: pgutil.UUIDPtr(row.MonitoringFolderID), FolderName: pgutil.StringPtr(row.FolderName),
			DashboardID: pgutil.UUIDPtr(row.MonitoringDashboardID), DashboardName: pgutil.StringPtr(row.DashboardName),
			Permission: row.Permission, CreatedAt: row.CreatedAt.Time.Format(time.RFC3339),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"grants": items})
}

// MyAccess handles GET /api/docker/my-access: what the calling user
// currently has, and via which Workspace/resource grant -- authenticated-
// any-role, since this only ever reflects the caller's own grants.
func (h *DockerAccessHandler) MyAccess(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	rows, err := h.store.ListDockerAccessGrantsForUser(r.Context(), user.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load access grants")
		return
	}
	items := make([]dockerAccessGrantDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, dockerAccessGrantDTO{
			ID: row.ID.String(), ScopeType: row.ScopeType,
			WorkspaceID: pgutil.UUIDPtr(row.WorkspaceID), WorkspaceName: pgutil.StringPtr(row.WorkspaceName),
			ResourceID: pgutil.UUIDPtr(row.ResourceID), ResourceName: pgutil.StringPtr(row.ResourceName),
			FolderID: pgutil.UUIDPtr(row.MonitoringFolderID), FolderName: pgutil.StringPtr(row.FolderName),
			DashboardID: pgutil.UUIDPtr(row.MonitoringDashboardID), DashboardName: pgutil.StringPtr(row.DashboardName),
			Permission: row.Permission, CreatedAt: row.CreatedAt.Time.Format(time.RFC3339),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"is_admin": user.IsAdmin(),
		"grants":   items,
	})
}
