package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// jsonRawOrNil unmarshals a jsonb column's raw bytes into an any so it
// serializes back out as a nested JSON object/array rather than a base64
// string. Malformed/empty input (should never happen -- these columns are
// only ever written by this application's own json.Marshal calls) simply
// renders as absent.
func jsonRawOrNil(raw []byte) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

// RecommendationHandler implements the cross-resource /recommendations
// dashboard (Step 7 spec §38-39, extended by Step 14 to also cover
// standalone databases): ADMIN sees every recommendation across every
// VM/database; MEMBER sees only recommendations for resources they're
// individually authorized on. The restriction is enforced by the SQL
// query itself (resource_ids filter), never by trusting the frontend to
// only ask for resources it already knows about.
type RecommendationHandler struct {
	store *repository.Store
	authz *services.AuthorizationService
}

// NewRecommendationHandler creates a RecommendationHandler.
func NewRecommendationHandler(store *repository.Store, authz *services.AuthorizationService) *RecommendationHandler {
	return &RecommendationHandler{store: store, authz: authz}
}

// resourceType distinguishes a VM recommendation from a DATABASE one so
// the frontend's "Review" action can route to the right detail page
// (/vms/:id vs /databases/:id) instead of assuming every recommendation
// is VM-shaped.
type recommendationDTO struct {
	ID           string  `json:"id"`
	ResourceID   string  `json:"resource_id"`
	ResourceName string  `json:"resource_name"`
	ResourceType string  `json:"resource_type"`
	Type         string  `json:"type"`
	Severity     string  `json:"severity"`
	Title        string  `json:"title"`
	Description  string  `json:"description,omitempty"`
	Status       string  `json:"status"`
	Metadata     any     `json:"metadata,omitempty"`
	DetectedAt   string  `json:"detected_at"`
	ResolvedAt   *string `json:"resolved_at,omitempty"`
}

// List handles GET /api/recommendations?type=&status=&severity=&resource_id=&page=&page_size=.
func (h *RecommendationHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// ADMIN: no resource_ids restriction (NULL narg = unrestricted, see
	// ListRecommendationsFiltered's query). MEMBER: restricted to exactly
	// the VMs, databases, and object storages they're individually
	// authorized on, merged -- an empty slice here correctly matches
	// nothing, never "everything" (spec §39: never show a member the
	// global count). Reuses the same shared merge AlertsHandler uses
	// (services.GetUserAlertAccessResourceIDs) rather than a second,
	// separately-maintained VM+DB(+object storage) merge -- before Step 14
	// this only ever consulted VM access (a Member could never see a
	// recommendation for an authorized database), and before this fix it
	// never consulted object storage access either.
	var resourceIDs []uuid.UUID
	restrictToMember := !user.IsAdmin()
	if restrictToMember {
		ids, err := services.GetUserAlertAccessResourceIDs(r.Context(), h.authz, user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = ids
	}

	limit, offset, page, pageSize := pagination(r)
	q := r.URL.Query()

	// An optional single-resource scope (spec's per-database "Review
	// Recommendation" panel): when present, this always restricts the
	// result to that one resource -- for a Member, intersected with their
	// already-computed authorized set (never widened by it); for an
	// Admin, applied directly since Admin has no restriction to intersect
	// with.
	restrictToResource := false
	if raw := q.Get("resource_id"); raw != "" {
		resourceID, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid resource_id")
			return
		}
		restrictToResource = true
		if restrictToMember {
			authorized := false
			for _, id := range resourceIDs {
				if id == resourceID {
					authorized = true
					break
				}
			}
			if authorized {
				resourceIDs = []uuid.UUID{resourceID}
			} else {
				resourceIDs = []uuid.UUID{}
			}
		} else {
			resourceIDs = []uuid.UUID{resourceID}
		}
	}
	applyResourceFilter := restrictToMember || restrictToResource

	params := generated.ListRecommendationsFilteredParams{
		Limit: limit, Offset: offset,
		Type: optionalText(q.Get("type")), Status: optionalText(q.Get("status")),
		Severity: optionalText(q.Get("severity")),
	}
	if applyResourceFilter {
		params.ResourceIds = resourceIDs
	}

	rows, err := h.store.ListRecommendationsFiltered(r.Context(), params)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load recommendations")
		return
	}
	countParams := generated.CountRecommendationsFilteredParams{Type: params.Type, Status: params.Status, Severity: params.Severity}
	if applyResourceFilter {
		countParams.ResourceIds = resourceIDs
	}
	total, err := h.store.CountRecommendationsFiltered(r.Context(), countParams)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to count recommendations")
		return
	}

	items := make([]recommendationDTO, 0, len(rows))
	for _, row := range rows {
		item := recommendationDTO{
			ID: row.ID.String(), ResourceID: row.ResourceID.String(), ResourceName: row.ResourceName, ResourceType: row.ResourceType,
			Type: row.Type, Severity: row.Severity, Title: row.Title,
			Description: pgutil.TextOrEmpty(row.Description), Status: row.Status,
			DetectedAt: row.DetectedAt.Time.Format(time.RFC3339),
		}
		if len(row.Metadata) > 0 {
			item.Metadata = jsonRawOrNil(row.Metadata)
		}
		if t := pgutil.TimePtr(row.ResolvedAt); t != nil {
			formatted := t.Format(time.RFC3339)
			item.ResolvedAt = &formatted
		}
		items = append(items, item)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recommendations": items, "page": page, "page_size": pageSize, "total": total,
	})
}
