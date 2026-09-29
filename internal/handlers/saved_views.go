// Package handlers: saved_views.go implements per-user saved filters for
// the Docker/Kubernetes Monitoring and Logs dashboards -- a named,
// reloadable snapshot of whatever filter state the page that owns
// "feature" defines, optionally grouped into a "Folder" (Grafana-style
// Folder > Dashboard hierarchy -- a dashboard can also stand alone with no
// folder). Private per-user (never shared, never visible to other users,
// including other Admins) -- the simplest, safest semantics for a personal
// convenience feature, matching how user_preferences works elsewhere in
// this app. No service layer of its own (mirrors PermissionsHandler's
// precedent): validation here is a feature-name check plus a folder-
// ownership check, and the rest is ownership enforcement via WHERE
// clauses, not real business logic.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type SavedViewsHandler struct {
	store *repository.Store
}

func NewSavedViewsHandler(store *repository.Store) *SavedViewsHandler {
	return &SavedViewsHandler{store: store}
}

var validSavedViewFeatures = map[string]bool{
	"docker_monitor": true, "docker_logs": true, "k8s_monitor": true, "k8s_logs": true,
}

type savedDashboardViewDTO struct {
	ID        string          `json:"id"`
	Feature   string          `json:"feature"`
	Name      string          `json:"name"`
	Filters   json.RawMessage `json:"filters"`
	FolderID  *string         `json:"folder_id,omitempty"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

func toSavedViewDTO(v generated.SavedDashboardView) savedDashboardViewDTO {
	filters := v.Filters
	if len(filters) == 0 {
		filters = []byte("{}")
	}
	return savedDashboardViewDTO{
		ID: v.ID.String(), Feature: v.Feature, Name: v.Name, Filters: json.RawMessage(filters),
		FolderID:  pgutil.UUIDPtr(v.FolderID),
		CreatedAt: formatTimestamptzOrEmpty(v.CreatedAt), UpdatedAt: formatTimestamptzOrEmpty(v.UpdatedAt),
	}
}

type savedViewFolderDTO struct {
	ID        string `json:"id"`
	Feature   string `json:"feature"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

func toSavedViewFolderDTO(f generated.SavedViewFolder) savedViewFolderDTO {
	return savedViewFolderDTO{ID: f.ID.String(), Feature: f.Feature, Name: f.Name, CreatedAt: formatTimestamptzOrEmpty(f.CreatedAt)}
}

// List handles GET /api/saved-views?feature=docker_monitor -- every saved
// view the caller has created for that one dashboard, across every folder
// (and standalone). The page groups them client-side by folder_id.
func (h *SavedViewsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	feature := r.URL.Query().Get("feature")
	if !validSavedViewFeatures[feature] {
		httpx.WriteError(w, http.StatusBadRequest, "unknown feature")
		return
	}
	rows, err := h.store.ListSavedDashboardViewsForUser(r.Context(), generated.ListSavedDashboardViewsForUserParams{
		UserID: user.ID, Feature: feature,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load saved views")
		return
	}
	items := make([]savedDashboardViewDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toSavedViewDTO(row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"views": items})
}

type saveDashboardViewRequest struct {
	Feature  string          `json:"feature"`
	Name     string          `json:"name"`
	Filters  json.RawMessage `json:"filters"`
	FolderID *string         `json:"folder_id"`
}

// Create handles POST /api/saved-views. Saving under a name that already
// exists for this user+feature replaces it -- re-saving a view is the
// expected way to update it, not an error. FolderID is optional: omitted
// or null saves the dashboard standalone (no folder).
func (h *SavedViewsHandler) Create(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req saveDashboardViewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validSavedViewFeatures[req.Feature] {
		httpx.WriteError(w, http.StatusBadRequest, "unknown feature")
		return
	}
	if req.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	filters := req.Filters
	if len(filters) == 0 {
		filters = []byte("{}")
	}
	if !json.Valid(filters) {
		httpx.WriteError(w, http.StatusBadRequest, "filters must be valid JSON")
		return
	}

	var folderID pgtype.UUID
	if req.FolderID != nil && *req.FolderID != "" {
		parsed, err := uuid.Parse(*req.FolderID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid folder_id")
			return
		}
		if _, err := h.store.GetSavedViewFolderByID(r.Context(), generated.GetSavedViewFolderByIDParams{ID: parsed, UserID: user.ID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				httpx.WriteError(w, http.StatusBadRequest, "folder not found")
				return
			}
			httpx.WriteError(w, http.StatusInternalServerError, "failed to verify folder")
			return
		}
		folderID = pgutil.NullUUID(&parsed)
	}

	saved, err := h.store.UpsertSavedDashboardView(r.Context(), generated.UpsertSavedDashboardViewParams{
		UserID: user.ID, Feature: req.Feature, Name: req.Name, Filters: filters, FolderID: folderID,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save view")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toSavedViewDTO(saved))
}

// Delete handles DELETE /api/saved-views/:id -- scoped to the caller's own
// views by construction (the query's WHERE clause includes user_id), so a
// user can never delete someone else's saved view even by guessing an ID.
func (h *SavedViewsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "saved view not found")
		return
	}
	if err := h.store.DeleteSavedDashboardView(r.Context(), generated.DeleteSavedDashboardViewParams{ID: id, UserID: user.ID}); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete saved view")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// FolderList handles GET /api/saved-view-folders?feature=docker_monitor.
func (h *SavedViewsHandler) FolderList(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	feature := r.URL.Query().Get("feature")
	if !validSavedViewFeatures[feature] {
		httpx.WriteError(w, http.StatusBadRequest, "unknown feature")
		return
	}
	rows, err := h.store.ListSavedViewFoldersForUser(r.Context(), generated.ListSavedViewFoldersForUserParams{
		UserID: user.ID, Feature: feature,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load folders")
		return
	}
	items := make([]savedViewFolderDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toSavedViewFolderDTO(row))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"folders": items})
}

type createSavedViewFolderRequest struct {
	Feature string `json:"feature"`
	Name    string `json:"name"`
}

// FolderCreate handles POST /api/saved-view-folders.
func (h *SavedViewsHandler) FolderCreate(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req createSavedViewFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validSavedViewFeatures[req.Feature] {
		httpx.WriteError(w, http.StatusBadRequest, "unknown feature")
		return
	}
	if req.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	folder, err := h.store.CreateSavedViewFolder(r.Context(), generated.CreateSavedViewFolderParams{
		UserID: user.ID, Feature: req.Feature, Name: req.Name,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, "a folder with that name already exists")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toSavedViewFolderDTO(folder))
}

// FolderDelete handles DELETE /api/saved-view-folders/:id -- deletes the
// folder and (via ON DELETE CASCADE) every dashboard saved inside it. The
// frontend confirms this with the caller before calling it.
func (h *SavedViewsHandler) FolderDelete(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "folder not found")
		return
	}
	if err := h.store.DeleteSavedViewFolder(r.Context(), generated.DeleteSavedViewFolderParams{ID: id, UserID: user.ID}); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to delete folder")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
