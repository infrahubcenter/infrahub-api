// Package handlers: monitoring_dashboards.go implements the new Folder >
// Dashboard model backing four independent trees -- Monitoring>Docker,
// Monitoring>Kubernetes, Logs>Docker, Logs>Kubernetes -- discriminated
// by `feature`. Replaces the retired handlers/dashboards.go. Folder CRUD
// is Admin-only; Dashboard create/rename/move/resource-selection/
// widgets/delete is Admin-only, but List/Get are any authenticated role,
// scoped by MonitoringDashboardService (Admin sees everything, a Member
// sees only Dashboards whose bound VM/cluster they hold the matching
// docker.monitor/docker.logs/k8s.monitor/k8s.logs grant on). See
// services/monitoring_dashboards.go and
// migrations/042_monitoring_dashboards.sql.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type MonitoringDashboardsHandler struct {
	store      *repository.Store
	folders    *services.MonitoringFolderService
	dashboards *services.MonitoringDashboardService
	audit      *services.AuditService
}

func NewMonitoringDashboardsHandler(
	store *repository.Store, folders *services.MonitoringFolderService, dashboards *services.MonitoringDashboardService, audit *services.AuditService,
) *MonitoringDashboardsHandler {
	return &MonitoringDashboardsHandler{store: store, folders: folders, dashboards: dashboards, audit: audit}
}

type monitoringFolderDTO struct {
	ID          string `json:"id"`
	Feature     string `json:"feature"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	CreatedAt   string `json:"created_at"`
}

func monitoringFolderDTOFrom(f generated.MonitoringFolder) monitoringFolderDTO {
	return monitoringFolderDTO{
		ID: f.ID.String(), Feature: f.Feature, WorkspaceID: f.WorkspaceID.String(),
		Name: f.Name, CreatedAt: formatTimestamptzOrEmpty(f.CreatedAt),
	}
}

type monitoringDashboardFilterDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type monitoringDashboardWidgetDTO struct {
	Type     string `json:"type"`
	Position int    `json:"position"`
}

type monitoringDashboardDTO struct {
	ID                     string                         `json:"id"`
	MonitoringFolderID     *string                        `json:"monitoring_folder_id,omitempty"`
	Feature                string                         `json:"feature"`
	WorkspaceID            string                         `json:"workspace_id"`
	Name                   string                         `json:"name"`
	Description            string                         `json:"description,omitempty"`
	VMResourceID           *string                        `json:"vm_resource_id,omitempty"`
	K8sClusterResourceID   *string                        `json:"k8s_cluster_resource_id,omitempty"`
	RefreshIntervalSeconds int32                          `json:"refresh_interval_seconds"`
	BoundResourceName      string                         `json:"bound_resource_name"`
	BoundResourceType      string                         `json:"bound_resource_type"`
	BoundResourceStatus    string                         `json:"bound_resource_status"`
	WorkspaceName          string                         `json:"workspace_name"`
	FolderName             *string                        `json:"folder_name,omitempty"`
	ResourceSelection      []monitoringDashboardFilterDTO `json:"resource_selection"`
	Widgets                []monitoringDashboardWidgetDTO `json:"widgets"`
	CreatedAt              string                         `json:"created_at"`
}

// toDashboardDTO fetches d's resource-selection and widgets inline --
// two small extra queries, acceptable since callers list at most a
// handful of Dashboards per folder/tree (never a paginated global list).
func (h *MonitoringDashboardsHandler) toDashboardDTO(r *http.Request, d services.MonitoringDashboardWithBinding) monitoringDashboardDTO {
	dto := monitoringDashboardDTO{
		ID: d.ID.String(), MonitoringFolderID: pgutil.UUIDPtr(d.MonitoringFolderID), Feature: d.Feature, WorkspaceID: d.WorkspaceID.String(),
		Name: d.Name, Description: pgutil.TextOrEmpty(d.Description),
		VMResourceID: pgutil.UUIDPtr(d.VmResourceID), K8sClusterResourceID: pgutil.UUIDPtr(d.K8sClusterResourceID),
		RefreshIntervalSeconds: d.RefreshIntervalSeconds,
		BoundResourceName:      d.BoundResourceName, BoundResourceType: d.BoundResourceType, BoundResourceStatus: d.BoundResourceStatus,
		WorkspaceName: d.WorkspaceName, FolderName: pgutil.StringPtr(d.FolderName),
		ResourceSelection: []monitoringDashboardFilterDTO{}, Widgets: []monitoringDashboardWidgetDTO{},
		CreatedAt: formatTimestamptzOrEmpty(d.CreatedAt),
	}
	if filters, err := h.dashboards.ListResourceSelection(r.Context(), d.ID); err == nil {
		for _, f := range filters {
			dto.ResourceSelection = append(dto.ResourceSelection, monitoringDashboardFilterDTO{Type: f.FilterType, Value: f.Value})
		}
	}
	if widgets, err := h.dashboards.ListWidgets(r.Context(), d.ID); err == nil {
		for _, w := range widgets {
			dto.Widgets = append(dto.Widgets, monitoringDashboardWidgetDTO{Type: w.WidgetType, Position: int(w.Position)})
		}
	}
	return dto
}

// ---- Folders ----

type createMonitoringFolderRequest struct {
	Feature     string `json:"feature"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
}

// CreateFolder handles POST /api/monitoring-folders (admin-only).
func (h *MonitoringDashboardsHandler) CreateFolder(w http.ResponseWriter, r *http.Request) {
	var req createMonitoringFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	folder, err := h.folders.Create(r.Context(), req.Feature, workspaceID, req.Name, actor.ID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditMonitoringFolderCreated, ResourceType: "MONITORING_FOLDER", ResourceID: &folder.ID,
		Metadata: map[string]any{"name": folder.Name, "feature": folder.Feature},
	})
	httpx.WriteJSON(w, http.StatusCreated, monitoringFolderDTOFrom(folder))
}

// ListFolders handles GET /api/monitoring-folders?feature=&workspace_id=
// (admin-only).
func (h *MonitoringDashboardsHandler) ListFolders(w http.ResponseWriter, r *http.Request) {
	feature := r.URL.Query().Get("feature")
	if feature == "" {
		httpx.WriteError(w, http.StatusBadRequest, "feature is required")
		return
	}
	workspaceID, err := uuid.Parse(r.URL.Query().Get("workspace_id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "workspace_id is required")
		return
	}
	rows, err := h.folders.ListForWorkspace(r.Context(), feature, workspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load folders")
		return
	}
	items := make([]monitoringFolderDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, monitoringFolderDTOFrom(row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"folders": items})
}

// GetFolder handles GET /api/monitoring-folders/:id -- any authenticated
// role, unlike ListFolders/CreateFolder/RenameFolder/DeleteFolder (Admin-
// only). A folder's name/feature/placement is low-sensitivity
// organizational metadata (not the dashboards inside it, which stay
// fully RBAC'd via MonitoringDashboardService.ListAccessibleForUser) --
// this exists purely so a Member landing on a folder's page can render
// its name/breadcrumb without needing the Admin-only list endpoint.
func (h *MonitoringDashboardsHandler) GetFolder(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "folder not found")
		return
	}
	folder, err := h.folders.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, monitoringFolderDTOFrom(folder))
}

type renameMonitoringFolderRequest struct {
	Name string `json:"name"`
}

// RenameFolder handles PATCH /api/monitoring-folders/:id (admin-only).
func (h *MonitoringDashboardsHandler) RenameFolder(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "folder not found")
		return
	}
	var req renameMonitoringFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	folder, err := h.folders.Rename(r.Context(), id, req.Name)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditMonitoringFolderRenamed, ResourceType: "MONITORING_FOLDER", ResourceID: &id,
		Metadata: map[string]any{"name": folder.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, monitoringFolderDTOFrom(folder))
}

// DeleteFolder handles DELETE /api/monitoring-folders/:id (admin-only) --
// cascades to every Dashboard filed inside it. The frontend confirms this
// with the admin first when the folder isn't empty.
func (h *MonitoringDashboardsHandler) DeleteFolder(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "folder not found")
		return
	}
	folder, err := h.folders.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if err := h.folders.Delete(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete folder")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditMonitoringFolderDeleted, ResourceType: "MONITORING_FOLDER", ResourceID: &id,
		Metadata: map[string]any{"name": folder.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- Dashboards ----

type createMonitoringDashboardRequest struct {
	Feature                string  `json:"feature"`
	Name                   string  `json:"name"`
	Description            string  `json:"description,omitempty"`
	MonitoringFolderID     *string `json:"monitoring_folder_id,omitempty"`
	VMResourceID           *string `json:"vm_resource_id,omitempty"`
	K8sClusterResourceID   *string `json:"k8s_cluster_resource_id,omitempty"`
	RefreshIntervalSeconds int32   `json:"refresh_interval_seconds,omitempty"`
}

// Create handles POST /api/monitoring-dashboards (admin-only).
func (h *MonitoringDashboardsHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createMonitoringDashboardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	folderID, err := parseOptionalUUID(req.MonitoringFolderID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid monitoring_folder_id")
		return
	}
	vmResourceID, err := parseOptionalUUID(req.VMResourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid vm_resource_id")
		return
	}
	clusterResourceID, err := parseOptionalUUID(req.K8sClusterResourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid k8s_cluster_resource_id")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	d, err := h.dashboards.Create(r.Context(), services.CreateMonitoringDashboardInput{
		Feature: req.Feature, Name: req.Name, Description: req.Description, MonitoringFolderID: folderID,
		VMResourceID: vmResourceID, ClusterResourceID: clusterResourceID, RefreshIntervalSeconds: req.RefreshIntervalSeconds,
	}, actor.ID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	full, err := h.dashboards.Get(r.Context(), d.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load created dashboard")
		return
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditMonitoringDashboardCreated, ResourceType: "MONITORING_DASHBOARD", ResourceID: &d.ID,
		Metadata: map[string]any{"name": d.Name, "feature": d.Feature, "bound_resource": full.BoundResourceName},
	})
	httpx.WriteJSON(w, http.StatusCreated, h.toDashboardDTO(r, full))
}

// List handles GET /api/monitoring-dashboards?feature=&workspace_id=&monitoring_folder_id=
// (any authenticated role, scoped by MonitoringDashboardService.ListAccessibleForUser).
func (h *MonitoringDashboardsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	feature := r.URL.Query().Get("feature")
	if feature == "" {
		httpx.WriteError(w, http.StatusBadRequest, "feature is required")
		return
	}
	workspaceID, err := parseOptionalUUID(optionalQueryParam(r, "workspace_id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}
	folderID, err := parseOptionalUUID(optionalQueryParam(r, "monitoring_folder_id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid monitoring_folder_id")
		return
	}
	rows, err := h.dashboards.ListAccessibleForUser(r.Context(), user, feature, workspaceID, folderID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	items := make([]monitoringDashboardDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, h.toDashboardDTO(r, row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"dashboards": items})
}

// Get handles GET /api/monitoring-dashboards/:id -- any authenticated
// role, but denied for a caller CanView doesn't clear; returns 404
// rather than 403 (matches this codebase's established convention).
func (h *MonitoringDashboardsHandler) Get(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "dashboard not found")
		return
	}
	d, err := h.dashboards.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	canView, err := h.dashboards.CanView(r.Context(), user, d.MonitoringDashboard)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to check access")
		return
	}
	if !canView {
		httpx.WriteError(w, http.StatusNotFound, "dashboard not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.toDashboardDTO(r, d))
}

type updateMonitoringDashboardRequest struct {
	Name                   *string `json:"name,omitempty"`
	Description            *string `json:"description,omitempty"`
	MonitoringFolderID     *string `json:"monitoring_folder_id"`
	MoveFolder             bool    `json:"move_folder,omitempty"`
	RefreshIntervalSeconds *int32  `json:"refresh_interval_seconds,omitempty"`
}

// Update handles PATCH /api/monitoring-dashboards/:id (admin-only) --
// renames, moves between Folders, and/or updates the refresh interval.
// The bound VM/cluster and feature are immutable (rebinding is
// delete+recreate).
func (h *MonitoringDashboardsHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "dashboard not found")
		return
	}
	var req updateMonitoringDashboardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	if req.Name != nil {
		description := ""
		if req.Description != nil {
			description = *req.Description
		} else if existing, err := h.dashboards.Get(r.Context(), id); err == nil {
			description = pgutil.TextOrEmpty(existing.Description)
		}
		if _, err := h.dashboards.Rename(r.Context(), id, *req.Name, description); err != nil {
			writeServiceError(w, err)
			return
		}
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &actor.ID, Action: services.AuditMonitoringDashboardRenamed, ResourceType: "MONITORING_DASHBOARD", ResourceID: &id,
			Metadata: map[string]any{"name": *req.Name},
		})
	}
	if req.MoveFolder {
		folderID, err := parseOptionalUUID(req.MonitoringFolderID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid monitoring_folder_id")
			return
		}
		if _, err := h.dashboards.Move(r.Context(), id, folderID); err != nil {
			writeServiceError(w, err)
			return
		}
		_ = h.audit.LogFrom(r, services.AuditEvent{
			UserID: &actor.ID, Action: services.AuditMonitoringDashboardMoved, ResourceType: "MONITORING_DASHBOARD", ResourceID: &id,
		})
	}
	if req.RefreshIntervalSeconds != nil {
		if _, err := h.dashboards.SetRefreshInterval(r.Context(), id, *req.RefreshIntervalSeconds); err != nil {
			writeServiceError(w, err)
			return
		}
	}
	full, err := h.dashboards.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.toDashboardDTO(r, full))
}

type setResourceSelectionRequest struct {
	Filters []monitoringDashboardFilterDTO `json:"filters"`
}

// SetResourceSelection handles PUT /api/monitoring-dashboards/:id/resource-selection
// (admin-only) -- persists the wizard's "Resources" step picks.
func (h *MonitoringDashboardsHandler) SetResourceSelection(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "dashboard not found")
		return
	}
	var req setResourceSelectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	filters := make([]services.FilterInput, 0, len(req.Filters))
	for _, f := range req.Filters {
		filters = append(filters, services.FilterInput{Type: f.Type, Value: f.Value})
	}
	if _, err := h.dashboards.SetResourceSelection(r.Context(), id, filters); err != nil {
		writeServiceError(w, err)
		return
	}
	full, err := h.dashboards.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditMonitoringDashboardResourceSelectionUpdated, ResourceType: "MONITORING_DASHBOARD", ResourceID: &id,
	})
	httpx.WriteJSON(w, http.StatusOK, h.toDashboardDTO(r, full))
}

type setWidgetsRequest struct {
	Widgets []string `json:"widgets"`
}

// SetWidgets handles PUT /api/monitoring-dashboards/:id/widgets
// (admin-only) -- persists the wizard's "Metrics" step picks, in order.
func (h *MonitoringDashboardsHandler) SetWidgets(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "dashboard not found")
		return
	}
	var req setWidgetsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if _, err := h.dashboards.SetWidgets(r.Context(), id, req.Widgets); err != nil {
		writeServiceError(w, err)
		return
	}
	full, err := h.dashboards.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditMonitoringDashboardWidgetsUpdated, ResourceType: "MONITORING_DASHBOARD", ResourceID: &id,
	})
	httpx.WriteJSON(w, http.StatusOK, h.toDashboardDTO(r, full))
}

// Delete handles DELETE /api/monitoring-dashboards/:id (admin-only). The
// bound VM/cluster and its containers/pods/logs are never touched --
// only the Dashboard organizational entity is removed.
func (h *MonitoringDashboardsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "dashboard not found")
		return
	}
	d, err := h.dashboards.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if err := h.dashboards.Delete(r.Context(), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete dashboard")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditMonitoringDashboardDeleted, ResourceType: "MONITORING_DASHBOARD", ResourceID: &id,
		Metadata: map[string]any{"name": d.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func optionalQueryParam(r *http.Request, key string) *string {
	v := r.URL.Query().Get(key)
	if v == "" {
		return nil
	}
	return &v
}
