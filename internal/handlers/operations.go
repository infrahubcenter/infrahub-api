// Package handlers: operations.go implements Step 21's unified /operations
// page. It is a read-only merge of the three existing controlled-operation
// families -- update execution (Step 10), VM reboot (Step 11), and
// database operations (Step 14) -- into one filterable, paginated list
// plus summary counts, reusing each family's own already-authorization-
// scoped store query completely unchanged (ListUpdateOperationsGlobal/
// ListRebootOperationsGlobal/ListDatabaseOperationsGlobal, the exact same
// queries GET /api/update-operations, /api/reboot-operations, and
// /api/database-operations already use).
//
// There is no new "operations" table and no new execution path here.
// Every mutating action (confirm/execute/cancel/retry) continues to
// happen on that operation's own existing, tested detail page
// (/update-operations/:id, /reboot-operations/:id,
// /databases/:id/operations/:operationId) -- this handler is a list/
// overview surface only, deliberately not a fourth place those actions
// could be triggered from.
package handlers

import (
	"context"
	"sort"
	"strings"
	"time"

	"net/http"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

type OperationsHandler struct {
	store *repository.Store
	authz *services.AuthorizationService
}

func NewOperationsHandler(store *repository.Store, authz *services.AuthorizationService) *OperationsHandler {
	return &OperationsHandler{store: store, authz: authz}
}

// maxOperationsAggregateFetch bounds how many rows are pulled from each of
// the three sources before merge/filter/paginate -- generous for any
// realistic operation history on this kind of admin tool, while still
// guaranteeing the browser is never handed the entire table (spec §8).
const maxOperationsAggregateFetch = 1000

// unifiedOperation is one row of the merged /operations list, normalized
// across all three source families.
type unifiedOperation struct {
	ID               string
	Family           string // "UPDATE" | "REBOOT" | "DATABASE"
	OperationType    string
	ResourceID       uuid.UUID
	ResourceName     string
	ResourceType     string // "VM" | "DATABASE"
	WorkspaceID      string
	Status           string
	RequestedByName  string
	RequestedByEmail string
	Summary          string
	ErrorSummary     string
	CreatedAt        time.Time
	StartedAt        *time.Time
	CompletedAt      *time.Time
}

// loadUnifiedOperations fetches and normalizes every operation the caller
// is authorized to see, unfiltered and unpaginated (callers filter/
// paginate the result) -- mirrors monitoring_dashboard.go's own
// "authorize first, merge, then let filters only ever narrow" shape.
func (h *OperationsHandler) loadUnifiedOperations(ctx context.Context, user services.AuthenticatedUser) ([]unifiedOperation, error) {
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		access, err := h.authz.GetUserVMAccess(ctx, user)
		if err != nil {
			return nil, err
		}
		resourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			resourceIDs = append(resourceIDs, a.ResourceID)
		}
	}

	var out []unifiedOperation

	updateRows, err := h.store.Queries.ListUpdateOperationsGlobal(ctx, generated.ListUpdateOperationsGlobalParams{
		Limit: maxOperationsAggregateFetch, Offset: 0, ResourceIds: resourceIDs,
	})
	if err != nil {
		return nil, err
	}
	for _, row := range updateRows {
		out = append(out, unifiedOperation{
			ID: row.ID.String(), Family: "UPDATE", OperationType: row.OperationType,
			ResourceID: pgutil.UUID(row.ResourceID), ResourceName: row.VmName, ResourceType: "VM",
			Status: row.Status, RequestedByName: pgutil.TextOrEmpty(row.CreatedByName), RequestedByEmail: pgutil.TextOrEmpty(row.CreatedByEmail),
			Summary: pgutil.TextOrEmpty(row.Summary), CreatedAt: row.CreatedAt.Time,
			StartedAt: pgutil.TimePtr(row.StartedAt), CompletedAt: pgutil.TimePtr(row.CompletedAt),
		})
	}

	rebootRows, err := h.store.Queries.ListRebootOperationsGlobal(ctx, generated.ListRebootOperationsGlobalParams{
		Limit: maxOperationsAggregateFetch, Offset: 0, ResourceIds: resourceIDs,
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rebootRows {
		out = append(out, unifiedOperation{
			ID: row.ID.String(), Family: "REBOOT", OperationType: "REBOOT",
			ResourceID: row.VmResourceID, ResourceName: row.VmName, ResourceType: "VM",
			Status: row.Status, RequestedByName: pgutil.TextOrEmpty(row.CreatedByName), RequestedByEmail: pgutil.TextOrEmpty(row.CreatedByEmail),
			ErrorSummary: pgutil.TextOrEmpty(row.ErrorSummary), CreatedAt: row.CreatedAt.Time,
			StartedAt: pgutil.TimePtr(row.StartedAt), CompletedAt: pgutil.TimePtr(row.CompletedAt),
		})
	}

	// Database operations have no Member grant path at all (Step 14: "no
	// grant path around this" -- requireAdmin gates the real REST endpoint
	// at the router level); mirror that exactly here rather than calling
	// the query for a Member, whose resourceIDs slice would incorrectly
	// suggest "scope to these" when the real rule is "never for Members."
	if user.IsAdmin() {
		dbRows, err := h.store.Queries.ListDatabaseOperationsGlobal(ctx, generated.ListDatabaseOperationsGlobalParams{
			Limit: maxOperationsAggregateFetch, Offset: 0,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range dbRows {
			out = append(out, unifiedOperation{
				ID: row.ID.String(), Family: "DATABASE", OperationType: row.OperationType,
				ResourceID: row.DatabaseResourceID, ResourceName: row.DatabaseName, ResourceType: "DATABASE",
				Status: row.Status, RequestedByName: pgutil.TextOrEmpty(row.RequestedByName), RequestedByEmail: pgutil.TextOrEmpty(row.RequestedByEmail),
				Summary: pgutil.TextOrEmpty(row.ResultSummary), ErrorSummary: pgutil.TextOrEmpty(row.ErrorSummary),
				CreatedAt: row.CreatedAt.Time, StartedAt: pgutil.TimePtr(row.StartedAt), CompletedAt: pgutil.TimePtr(row.CompletedAt),
			})
		}
	}

	if err := h.enrichProjectAndGroup(ctx, out); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// enrichProjectAndGroup batch-resolves each row's resource_id to its
// project_id/group_id (a single ListResourcesByIDs call, never one query
// per row) and fills them in place.
func (h *OperationsHandler) enrichProjectAndGroup(ctx context.Context, ops []unifiedOperation) error {
	seen := map[uuid.UUID]bool{}
	ids := make([]uuid.UUID, 0, len(ops))
	for _, op := range ops {
		if !seen[op.ResourceID] {
			seen[op.ResourceID] = true
			ids = append(ids, op.ResourceID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	resources, err := h.store.Queries.ListResourcesByIDs(ctx, ids)
	if err != nil {
		return err
	}
	byID := make(map[uuid.UUID]generated.ListResourcesByIDsRow, len(resources))
	for _, r := range resources {
		byID[r.ID] = r
	}
	for i := range ops {
		if r, ok := byID[ops[i].ResourceID]; ok {
			ops[i].WorkspaceID = r.WorkspaceID.String()
		}
	}
	return nil
}

// operationStatusBucket collapses every family's status vocabulary into
// the six summary-card buckets spec §1 asks for. TIMEOUT/PARTIAL/
// INTERRUPTED/UNKNOWN are outcomes that didn't cleanly succeed, so they
// count toward Failed rather than inventing extra cards the spec doesn't
// list.
func operationStatusBucket(status string) string {
	switch status {
	case "WAITING_CONFIRMATION":
		return "PENDING_CONFIRMATION"
	case "SUCCESS":
		return "SUCCESS"
	case "CANCELLED":
		return "CANCELLED"
	case "FAILED", "PARTIAL", "TIMEOUT", "INTERRUPTED", "UNKNOWN":
		return "FAILED"
	default: // PENDING, PRECHECK, CONNECTING, RUNNING, REBOOTING, WAITING_FOR_VM, RECONNECTING, VERIFYING
		return "RUNNING"
	}
}

type unifiedOperationDTO struct {
	ID               string  `json:"id"`
	Family           string  `json:"family"`
	OperationType    string  `json:"operation_type"`
	ResourceID       string  `json:"resource_id"`
	ResourceName     string  `json:"resource_name"`
	ResourceType     string  `json:"resource_type"`
	WorkspaceID      string  `json:"workspace_id,omitempty"`
	Status           string  `json:"status"`
	RequestedByName  string  `json:"requested_by_name,omitempty"`
	RequestedByEmail string  `json:"requested_by_email,omitempty"`
	Summary          string  `json:"summary,omitempty"`
	ErrorSummary     string  `json:"error_summary,omitempty"`
	CreatedAt        string  `json:"created_at"`
	StartedAt        *string `json:"started_at,omitempty"`
	CompletedAt      *string `json:"completed_at,omitempty"`
}

func toUnifiedOperationDTO(op unifiedOperation) unifiedOperationDTO {
	dto := unifiedOperationDTO{
		ID: op.ID, Family: op.Family, OperationType: op.OperationType,
		ResourceID: op.ResourceID.String(), ResourceName: op.ResourceName, ResourceType: op.ResourceType,
		WorkspaceID: op.WorkspaceID, Status: op.Status,
		RequestedByName: op.RequestedByName, RequestedByEmail: op.RequestedByEmail,
		Summary: op.Summary, ErrorSummary: op.ErrorSummary, CreatedAt: op.CreatedAt.Format(time.RFC3339),
	}
	if op.StartedAt != nil {
		s := op.StartedAt.Format(time.RFC3339)
		dto.StartedAt = &s
	}
	if op.CompletedAt != nil {
		s := op.CompletedAt.Format(time.RFC3339)
		dto.CompletedAt = &s
	}
	return dto
}

// List handles GET /api/operations. Authenticated any role -- exactly like
// /api/alerts and /api/my-access, the response scoping inside
// loadUnifiedOperations (VM-access-restricted for Members, Admin sees
// everything, database operations never appear for a Member at all) is the
// security boundary, not a route-level role gate. Every filter below is
// applied strictly after that scoping, so a filter can only ever narrow an
// already-authorized set, never widen it (spec §7's IDOR requirement).
func (h *OperationsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	ops, err := h.loadUnifiedOperations(r.Context(), user)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load operations")
		return
	}

	q := r.URL.Query()
	ops = filterOperations(ops, operationsFilter{
		status: q.Get("status"), family: q.Get("family"), resourceType: q.Get("resource_type"),
		operationType: q.Get("operation_type"), workspaceID: q.Get("workspace_id"),
		search: q.Get("search"), from: parseTimeParam(q.Get("from")), to: parseTimeParam(q.Get("to")),
	})

	total := len(ops)
	limit, offset := parsePagination(r, 25, 200)
	start := int(offset)
	if start > total {
		start = total
	}
	end := start + int(limit)
	if end > total {
		end = total
	}
	page := ops[start:end]

	items := make([]unifiedOperationDTO, 0, len(page))
	for _, op := range page {
		items = append(items, toUnifiedOperationDTO(op))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"operations": items, "total": total})
}

type operationsFilter struct {
	status, family, resourceType, operationType, workspaceID, search string
	from, to                                                         *time.Time
}

func parseTimeParam(v string) *time.Time {
	if v == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return &t
	}
	return nil
}

func filterOperations(ops []unifiedOperation, f operationsFilter) []unifiedOperation {
	search := strings.ToLower(strings.TrimSpace(f.search))
	out := make([]unifiedOperation, 0, len(ops))
	for _, op := range ops {
		if f.status != "" && op.Status != f.status {
			continue
		}
		if f.family != "" && op.Family != f.family {
			continue
		}
		if f.resourceType != "" && op.ResourceType != f.resourceType {
			continue
		}
		if f.operationType != "" && op.OperationType != f.operationType {
			continue
		}
		if f.workspaceID != "" && op.WorkspaceID != f.workspaceID {
			continue
		}
		if f.from != nil && op.CreatedAt.Before(*f.from) {
			continue
		}
		if f.to != nil && op.CreatedAt.After(*f.to) {
			continue
		}
		if search != "" {
			haystack := strings.ToLower(op.ResourceName + " " + op.OperationType + " " + op.Summary + " " + op.ErrorSummary + " " + op.RequestedByName)
			if !strings.Contains(haystack, search) {
				continue
			}
		}
		out = append(out, op)
	}
	return out
}

type operationsSummaryDTO struct {
	Total               int `json:"total"`
	Running             int `json:"running"`
	PendingConfirmation int `json:"pending_confirmation"`
	Successful          int `json:"successful"`
	Failed              int `json:"failed"`
	Cancelled           int `json:"cancelled"`
}

// Summary handles GET /api/operations/summary -- same authorization
// scoping as List, computed over the same merged set.
func (h *OperationsHandler) Summary(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	ops, err := h.loadUnifiedOperations(r.Context(), user)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load operations summary")
		return
	}
	summary := operationsSummaryDTO{Total: len(ops)}
	for _, op := range ops {
		switch operationStatusBucket(op.Status) {
		case "RUNNING":
			summary.Running++
		case "PENDING_CONFIRMATION":
			summary.PendingConfirmation++
		case "SUCCESS":
			summary.Successful++
		case "FAILED":
			summary.Failed++
		case "CANCELLED":
			summary.Cancelled++
		}
	}
	httpx.WriteJSON(w, http.StatusOK, summary)
}
