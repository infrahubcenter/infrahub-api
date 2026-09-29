package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// DatabaseOperationsHandler implements Step 14's controlled database
// operations API: Recommendation -> Review -> Operation Plan ->
// Confirmation -> Execute -> Live Output -> Result -> Audit. Every
// endpoint here is Admin-only (spec: "Admin-only by default... Members:
// NO database remediation access by default") -- unlike the rest of the
// database API surface, there is no grantable per-database permission
// that lets a Member reach any of this, mirroring vm.reboot's precedent
// exactly. POST /operations/:id/confirm is the only endpoint in this
// project (alongside VM reboot/update execute) that can cause a real
// change on a database -- it never accepts a raw command, only a
// previously-created, backend-validated operation plan.
type DatabaseOperationsHandler struct {
	store          *repository.Store
	exec           *services.DatabaseOperationService
	worker         *services.DatabaseOperationWorker
	audit          *services.AuditService
	frontendOrigin string
}

// NewDatabaseOperationsHandler creates a DatabaseOperationsHandler.
func NewDatabaseOperationsHandler(
	store *repository.Store, exec *services.DatabaseOperationService, worker *services.DatabaseOperationWorker,
	audit *services.AuditService, frontendOrigin string,
) *DatabaseOperationsHandler {
	return &DatabaseOperationsHandler{store: store, exec: exec, worker: worker, audit: audit, frontendOrigin: frontendOrigin}
}

// authorizeAdminDatabase resolves :id (the database), requires the caller
// be an authenticated Admin, and confirms the database actually exists
// (not soft-deleted) -- 404-not-403 for a nonexistent database, matching
// every other database-scoped endpoint's IDOR discipline, but a plain 403
// for "authenticated, not Admin" since that fact itself is not sensitive
// (spec's Member-vs-Admin distinction is meant to be visible, unlike a
// resource's mere existence).
func (h *DatabaseOperationsHandler) authorizeAdminDatabase(w http.ResponseWriter, r *http.Request) (generated.Database, services.AuthenticatedUser, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.Database{}, services.AuthenticatedUser{}, false
	}
	if !user.IsAdmin() {
		httpx.WriteError(w, http.StatusForbidden, "database operations are Admin-only")
		return generated.Database{}, services.AuthenticatedUser{}, false
	}
	databaseID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return generated.Database{}, services.AuthenticatedUser{}, false
	}
	db, err := h.store.GetDatabaseByID(r.Context(), databaseID)
	if err != nil || db.DeletedAt.Valid {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return generated.Database{}, services.AuthenticatedUser{}, false
	}
	return db, user, true
}

// authorizeAdminOperation resolves :operationId, requires Admin, and
// confirms it belongs to the :id in the path -- never trusts operationId
// alone (spec's "Unauthorized operation ID: DENY" / no IDOR across
// databases).
func (h *DatabaseOperationsHandler) authorizeAdminOperation(w http.ResponseWriter, r *http.Request) (generated.Database, generated.DatabaseOperation, services.AuthenticatedUser, bool) {
	db, user, ok := h.authorizeAdminDatabase(w, r)
	if !ok {
		return generated.Database{}, generated.DatabaseOperation{}, services.AuthenticatedUser{}, false
	}
	operationID, err := uuid.Parse(r.PathValue("operationId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "database operation not found")
		return generated.Database{}, generated.DatabaseOperation{}, services.AuthenticatedUser{}, false
	}
	op, err := h.store.GetDatabaseOperationByID(r.Context(), operationID)
	if err != nil || op.DatabaseID != db.ID {
		httpx.WriteError(w, http.StatusNotFound, "database operation not found")
		return generated.Database{}, generated.DatabaseOperation{}, services.AuthenticatedUser{}, false
	}
	return db, op, user, true
}

// --- DTOs ---

type databaseOperationCapabilityDTO struct {
	Type              string `json:"type"`
	Label             string `json:"label"`
	Destructive       bool   `json:"destructive"`
	Reversible        string `json:"reversible"`
	RequiresTargetID  bool   `json:"requires_target_id"`
	ImpactDescription string `json:"impact_description"`
}

// Capabilities handles GET /api/databases/:id/operations/capabilities:
// which operation types this specific database's engine actually
// supports -- drives the frontend's operation buttons (spec: "Do not
// force unsupported operations onto adapters").
func (h *DatabaseOperationsHandler) Capabilities(w http.ResponseWriter, r *http.Request) {
	db, _, ok := h.authorizeAdminDatabase(w, r)
	if !ok {
		return
	}
	caps := services.GetOperationCapabilities(services.DatabaseType(db.Type))
	items := make([]databaseOperationCapabilityDTO, 0, len(caps))
	for _, c := range caps {
		items = append(items, databaseOperationCapabilityDTO{
			Type: string(c.Type), Label: c.Label, Destructive: c.Destructive, Reversible: c.Reversible,
			RequiresTargetID: c.RequiresTargetID, ImpactDescription: c.ImpactDescription,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"capabilities": items})
}

type operationRequestBody struct {
	OperationType    string            `json:"operation_type"`
	Parameters       map[string]string `json:"parameters"`
	Reason           string            `json:"reason"`
	RecommendationID string            `json:"recommendation_id,omitempty"`
}

// Preview handles POST /api/databases/:id/operations/preview: a pure dry
// run -- never creates a database_operations row, never opens a
// connection (spec: "Preview must show target, operation, expected
// impact, commands/actions. No execution.").
func (h *DatabaseOperationsHandler) Preview(w http.ResponseWriter, r *http.Request) {
	db, _, ok := h.authorizeAdminDatabase(w, r)
	if !ok {
		return
	}
	var req operationRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	preview, impact, err := h.exec.Preview(r.Context(), db.ID, services.DatabaseOperationType(req.OperationType), req.Parameters)
	if err != nil {
		writeOperationError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"database_id": db.ID.String(), "operation_type": req.OperationType,
		"command_preview": preview, "expected_impact": impact,
	})
}

// Create handles POST /api/databases/:id/operations: builds the Operation
// Plan (WAITING_CONFIRMATION) -- still does not execute anything.
func (h *DatabaseOperationsHandler) Create(w http.ResponseWriter, r *http.Request) {
	db, user, ok := h.authorizeAdminDatabase(w, r)
	if !ok {
		return
	}
	var req operationRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var recommendationID *uuid.UUID
	if req.RecommendationID != "" {
		id, err := uuid.Parse(req.RecommendationID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid recommendation_id")
			return
		}
		recommendationID = &id
	}

	op, err := h.exec.RequestOperation(r.Context(), db.ID, services.DatabaseOperationType(req.OperationType), req.Parameters, req.Reason, recommendationID, user.ID)
	if err != nil {
		writeOperationError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, toDatabaseOperationDTO(generated.GetDatabaseOperationDetailRow{
		ID: op.ID, DatabaseID: op.DatabaseID, OperationType: op.OperationType, Status: op.Status, RequestedBy: op.RequestedBy,
		Reason: op.Reason, Parameters: op.Parameters, CommandPreview: op.CommandPreview, RecommendationID: op.RecommendationID,
		ConfirmedAt: op.ConfirmedAt, StartedAt: op.StartedAt, CompletedAt: op.CompletedAt, TimeoutAt: op.TimeoutAt,
		ResultSummary: op.ResultSummary, ResultDetail: op.ResultDetail, ErrorSummary: op.ErrorSummary,
		HealthBefore: op.HealthBefore, HealthAfter: op.HealthAfter, CreatedAt: op.CreatedAt, UpdatedAt: op.UpdatedAt,
	}))
}

// Get handles GET /api/databases/:id/operations/:operationId.
func (h *DatabaseOperationsHandler) Get(w http.ResponseWriter, r *http.Request) {
	_, op, _, ok := h.authorizeAdminOperation(w, r)
	if !ok {
		return
	}
	detail, err := h.store.GetDatabaseOperationDetail(r.Context(), op.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load operation")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toDatabaseOperationDTO(detail))
}

// ListForDatabase handles GET /api/databases/:id/operations (paginated).
func (h *DatabaseOperationsHandler) ListForDatabase(w http.ResponseWriter, r *http.Request) {
	db, _, ok := h.authorizeAdminDatabase(w, r)
	if !ok {
		return
	}
	limit, offset := parsePagination(r, 50, 200)
	rows, err := h.store.ListDatabaseOperationsByDatabase(r.Context(), generated.ListDatabaseOperationsByDatabaseParams{DatabaseID: db.ID, Limit: limit, Offset: offset})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load operations")
		return
	}
	total, _ := h.store.CountDatabaseOperationsByDatabase(r.Context(), db.ID)
	items := make([]databaseOperationDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDatabaseOperationDTO(generated.GetDatabaseOperationDetailRow{
			ID: row.ID, DatabaseID: row.DatabaseID, OperationType: row.OperationType, Status: row.Status, RequestedBy: row.RequestedBy,
			Reason: row.Reason, Parameters: row.Parameters, CommandPreview: row.CommandPreview, RecommendationID: row.RecommendationID,
			ConfirmedAt: row.ConfirmedAt, StartedAt: row.StartedAt, CompletedAt: row.CompletedAt, TimeoutAt: row.TimeoutAt,
			ResultSummary: row.ResultSummary, ResultDetail: row.ResultDetail, ErrorSummary: row.ErrorSummary,
			HealthBefore: row.HealthBefore, HealthAfter: row.HealthAfter, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
			RequestedByName: row.RequestedByName, RequestedByEmail: row.RequestedByEmail,
		}))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"operations": items, "total": total})
}

// ListGlobal handles GET /api/database-operations (Admin-only, every
// database -- there is no Member-scoped variant since Members never reach
// any endpoint in this handler).
func (h *DatabaseOperationsHandler) ListGlobal(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		httpx.WriteError(w, http.StatusForbidden, "database operations are Admin-only")
		return
	}
	limit, offset := parsePagination(r, 50, 200)
	rows, err := h.store.ListDatabaseOperationsGlobal(r.Context(), generated.ListDatabaseOperationsGlobalParams{Limit: limit, Offset: offset})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load operations")
		return
	}
	items := make([]databaseOperationDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDatabaseOperationDTO(generated.GetDatabaseOperationDetailRow{
			ID: row.ID, DatabaseID: row.DatabaseID, OperationType: row.OperationType, Status: row.Status, RequestedBy: row.RequestedBy,
			Reason: row.Reason, Parameters: row.Parameters, CommandPreview: row.CommandPreview, RecommendationID: row.RecommendationID,
			ConfirmedAt: row.ConfirmedAt, StartedAt: row.StartedAt, CompletedAt: row.CompletedAt, TimeoutAt: row.TimeoutAt,
			ResultSummary: row.ResultSummary, ResultDetail: row.ResultDetail, ErrorSummary: row.ErrorSummary,
			HealthBefore: row.HealthBefore, HealthAfter: row.HealthAfter, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
			DatabaseType: row.DatabaseType, DatabaseName: row.DatabaseName, DatabaseResourceID: row.DatabaseResourceID,
			RequestedByName: row.RequestedByName, RequestedByEmail: row.RequestedByEmail,
		}))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"operations": items})
}

// Confirm handles POST /api/databases/:id/operations/:operationId/confirm
// -- the only endpoint that can actually enqueue an operation for
// execution. Requires the plan to still be WAITING_CONFIRMATION.
func (h *DatabaseOperationsHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	_, op, user, ok := h.authorizeAdminOperation(w, r)
	if !ok {
		return
	}
	confirmed, err := h.exec.Confirm(r.Context(), op.ID, user.ID)
	if err != nil {
		writeOperationError(w, err)
		return
	}
	h.worker.Enqueue(confirmed.ID)
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"id": confirmed.ID.String(), "status": confirmed.Status})
}

// Cancel handles POST /api/databases/:id/operations/:operationId/cancel.
func (h *DatabaseOperationsHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	_, op, user, ok := h.authorizeAdminOperation(w, r)
	if !ok {
		return
	}
	cancelled, err := h.exec.Cancel(r.Context(), op.ID, user.ID)
	if err != nil {
		writeOperationError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": cancelled.ID.String(), "status": cancelled.Status})
}

// Retry handles POST /api/databases/:id/operations/:operationId/retry --
// creates a brand new plan, still requires its own fresh confirmation.
func (h *DatabaseOperationsHandler) Retry(w http.ResponseWriter, r *http.Request) {
	_, op, user, ok := h.authorizeAdminOperation(w, r)
	if !ok {
		return
	}
	retried, err := h.exec.Retry(r.Context(), op.ID, user.ID)
	if err != nil {
		writeOperationError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": retried.ID.String(), "status": retried.Status, "retry_of": op.ID.String()})
}

// Delete handles DELETE /api/databases/:id/operations/:operationId --
// permanently removes one history row. Only permitted once the operation
// has reached a terminal status (SUCCESS/FAILED/CANCELLED/TIMEOUT); one
// still WAITING_CONFIRMATION/PENDING/RUNNING can't be deleted out from
// under the worker that may still be executing it.
func (h *DatabaseOperationsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	_, op, user, ok := h.authorizeAdminOperation(w, r)
	if !ok {
		return
	}
	if err := h.exec.Delete(r.Context(), op.ID, user.ID); err != nil {
		writeOperationError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// Logs handles GET /api/databases/:id/operations/:operationId/logs.
func (h *DatabaseOperationsHandler) Logs(w http.ResponseWriter, r *http.Request) {
	_, op, _, ok := h.authorizeAdminOperation(w, r)
	if !ok {
		return
	}
	logs, err := h.store.ListDatabaseOperationLogs(r.Context(), op.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load logs")
		return
	}
	items := make([]map[string]any, 0, len(logs))
	for _, l := range logs {
		items = append(items, map[string]any{"sequence": l.SequenceNumber, "stream": l.Stream, "message": l.Message, "created_at": l.CreatedAt.Time.Format(time.RFC3339)})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"logs": items})
}

// LogsStream handles GET /api/databases/:id/operations/:operationId/logs/stream,
// reusing the exact gorilla/websocket + ticker-polls-a-store pattern
// established by DockerHandler.Stream and RebootOperationsHandler.LogsStream.
func (h *DatabaseOperationsHandler) LogsStream(w http.ResponseWriter, r *http.Request) {
	_, op, _, ok := h.authorizeAdminOperation(w, r)
	if !ok {
		return
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == h.frontendOrigin
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx := r.Context()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var lastSeq int32
	push := func() bool {
		logs, err := h.store.ListDatabaseOperationLogsAfter(ctx, generated.ListDatabaseOperationLogsAfterParams{DatabaseOperationID: op.ID, SequenceNumber: lastSeq})
		if err == nil {
			for _, l := range logs {
				lastSeq = l.SequenceNumber
				if conn.WriteJSON(map[string]any{"type": "log", "stream": l.Stream, "message": l.Message, "sequence": l.SequenceNumber}) != nil {
					return false
				}
			}
		}
		if current, err := h.store.GetDatabaseOperationByID(ctx, op.ID); err == nil {
			if services.IsTerminalDatabaseOperationStatus(services.DatabaseOperationStatus(current.Status)) {
				_ = conn.WriteJSON(map[string]any{"type": "done", "status": current.Status})
				return false
			}
		}
		return true
	}

	if !push() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			if !push() {
				return
			}
		}
	}
}

// --- shared helpers ---

type databaseOperationDTO struct {
	ID               string          `json:"id"`
	DatabaseID       string          `json:"database_id"`
	DatabaseType     string          `json:"database_type,omitempty"`
	DatabaseName     string          `json:"database_name,omitempty"`
	OperationType    string          `json:"operation_type"`
	Status           string          `json:"status"`
	RequestedBy      *string         `json:"requested_by,omitempty"`
	Reason           string          `json:"reason,omitempty"`
	Parameters       json.RawMessage `json:"parameters,omitempty"`
	CommandPreview   string          `json:"command_preview"`
	RecommendationID *string         `json:"recommendation_id,omitempty"`
	ConfirmedAt      *string         `json:"confirmed_at,omitempty"`
	StartedAt        *string         `json:"started_at,omitempty"`
	CompletedAt      *string         `json:"completed_at,omitempty"`
	TimeoutAt        *string         `json:"timeout_at,omitempty"`
	ResultSummary    string          `json:"result_summary,omitempty"`
	ResultDetail     json.RawMessage `json:"result_detail,omitempty"`
	ErrorSummary     string          `json:"error_summary,omitempty"`
	HealthBefore     string          `json:"health_before,omitempty"`
	HealthAfter      string          `json:"health_after,omitempty"`
	CreatedAt        string          `json:"created_at"`
}

// toDatabaseOperationDTO never includes credentials or raw query/command
// text -- CommandPreview is always a backend-generated template string
// (spec: "Do not expose credentials"), never anything client-supplied.
func toDatabaseOperationDTO(row generated.GetDatabaseOperationDetailRow) databaseOperationDTO {
	dto := databaseOperationDTO{
		ID: row.ID.String(), DatabaseID: row.DatabaseID.String(), DatabaseType: row.DatabaseType, DatabaseName: row.DatabaseName,
		OperationType: row.OperationType, Status: row.Status, Reason: pgutil.TextOrEmpty(row.Reason),
		CommandPreview: row.CommandPreview, ResultSummary: pgutil.TextOrEmpty(row.ResultSummary),
		ErrorSummary: pgutil.TextOrEmpty(row.ErrorSummary), HealthBefore: pgutil.TextOrEmpty(row.HealthBefore), HealthAfter: pgutil.TextOrEmpty(row.HealthAfter),
		CreatedAt:   row.CreatedAt.Time.Format(time.RFC3339),
		ConfirmedAt: formatTimestamptz(row.ConfirmedAt), StartedAt: formatTimestamptz(row.StartedAt),
		CompletedAt: formatTimestamptz(row.CompletedAt), TimeoutAt: formatTimestamptz(row.TimeoutAt),
	}
	if len(row.Parameters) > 0 {
		dto.Parameters = row.Parameters
	}
	if len(row.ResultDetail) > 0 {
		dto.ResultDetail = row.ResultDetail
	}
	if row.RecommendationID.Valid {
		id := pgutil.UUID(row.RecommendationID).String()
		dto.RecommendationID = &id
	}
	if name := pgutil.TextOrEmpty(row.RequestedByName); name != "" {
		dto.RequestedBy = &name
	}
	return dto
}

func parsePagination(r *http.Request, defaultLimit, maxLimit int32) (limit, offset int32) {
	limit = defaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && int32(parsed) <= maxLimit {
			limit = int32(parsed)
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = int32(parsed)
		}
	}
	return limit, offset
}

func writeOperationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, services.ErrDBOpDatabaseNotFound):
		httpx.WriteError(w, http.StatusNotFound, "database not found")
	case errors.Is(err, services.ErrDBOpNotFound):
		httpx.WriteError(w, http.StatusNotFound, "database operation not found")
	case errors.Is(err, services.ErrDatabaseOperationUnsupported):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrDatabaseOperationInvalidParams):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, services.ErrDBOpAlreadyActive):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, services.ErrDBOpCancelUnavailable):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, services.ErrDBOpNotWaitingConfirmation):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, services.ErrDBOpNotFailed):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, services.ErrDBOpNotTerminal):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	default:
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
	}
}
