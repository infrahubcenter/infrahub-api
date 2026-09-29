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

// ResourceHandler implements the generic, resource-type-agnostic endpoints.
// It is ADMIN-only end to end: unlike VMs, DATABASE/OBJECT_STORAGE
// resources have no MEMBER-facing access model yet (Step 4 §11).
type ResourceHandler struct {
	resources *services.ResourceService
}

// NewResourceHandler creates a ResourceHandler.
func NewResourceHandler(resources *services.ResourceService) *ResourceHandler {
	return &ResourceHandler{resources: resources}
}

type resourceResponse struct {
	ID           string `json:"id"`
	WorkspaceID  string `json:"workspace_id"`
	Name         string `json:"name"`
	ResourceType string `json:"resource_type"`
	Status       string `json:"status"`
	Description  string `json:"description,omitempty"`
}

func toResourceResponse(r generated.Resource) resourceResponse {
	return resourceResponse{
		ID: r.ID.String(), WorkspaceID: r.WorkspaceID.String(),
		Name: r.Name, ResourceType: r.ResourceType, Status: r.Status,
		Description: pgutil.TextOrEmpty(r.Description),
	}
}

// List handles GET /api/resources?workspace_id=&resource_type=&status=.
func (h *ResourceHandler) List(w http.ResponseWriter, r *http.Request) {
	filter := services.ResourceFilter{}
	q := r.URL.Query()

	if v := q.Get("workspace_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
			return
		}
		filter.WorkspaceID = &id
	}
	if v := q.Get("resource_type"); v != "" {
		if !services.ValidResourceTypes[v] {
			httpx.WriteError(w, http.StatusBadRequest, "invalid resource_type")
			return
		}
		filter.ResourceType = &v
	}
	if v := q.Get("status"); v != "" {
		if !services.ValidResourceStatuses[v] {
			httpx.WriteError(w, http.StatusBadRequest, "invalid status")
			return
		}
		filter.Status = &v
	}

	rows, err := h.resources.List(r.Context(), filter)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	resources := make([]resourceResponse, 0, len(rows))
	for _, row := range rows {
		resources = append(resources, toResourceResponse(row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"resources": resources})
}

// Get handles GET /api/resources/:id.
func (h *ResourceHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	resource, err := h.resources.Get(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toResourceResponse(resource))
}

type createResourceRequest struct {
	WorkspaceID  string `json:"workspace_id"`
	Name         string `json:"name"`
	ResourceType string `json:"resource_type"`
	Description  string `json:"description"`
}

// Create handles POST /api/resources. Only DATABASE and OBJECT_STORAGE
// placeholders can be created here -- VM creation requires the paired vms
// row, so it goes through POST /api/vms instead (ResourceService.CreatePlaceholder
// rejects VM with a clear error).
func (h *ResourceHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}

	resource, err := h.resources.CreatePlaceholder(r.Context(), workspaceID, req.Name, req.ResourceType, req.Description)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, toResourceResponse(resource))
}

type updateResourceRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	WorkspaceID *string `json:"workspace_id,omitempty"`
	Status      *string `json:"status,omitempty"`
}

// Update handles PATCH /api/resources/:id.
func (h *ResourceHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}

	var req updateResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	in := services.UpdateResourceInput{Name: req.Name, Description: req.Description, Status: req.Status}
	if req.WorkspaceID != nil {
		parsedID, err := uuid.Parse(*req.WorkspaceID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
			return
		}
		in.WorkspaceID = &parsedID
	}

	resource, err := h.resources.Update(r.Context(), id, in)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toResourceResponse(resource))
}

func parseOptionalUUID(s *string) (*uuid.UUID, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return nil, err
	}
	return &id, nil
}
