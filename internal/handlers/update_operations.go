package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// UpdateOperationsHandler implements Step 10's execution engine API: the
// one place in this project where an HTTP request can trigger an actual
// change on a remote VM (POST .../execute), plus read-only status/log/
// result/history endpoints. Every mutating action is Admin-only,
// enforced at the router via requireAdmin; every operation-scoped GET
// resolves the operation's VM and checks vm.view (404, not 403, on
// failure -- the same IDOR-safe pattern used everywhere else).
type UpdateOperationsHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	exec           *services.UpdateExecutionService
	worker         *services.UpdateExecutionWorker
	audit          *services.AuditService
	frontendOrigin string
}

// NewUpdateOperationsHandler creates an UpdateOperationsHandler.
func NewUpdateOperationsHandler(
	store *repository.Store, authz *services.AuthorizationService, exec *services.UpdateExecutionService,
	worker *services.UpdateExecutionWorker, audit *services.AuditService, frontendOrigin string,
) *UpdateOperationsHandler {
	return &UpdateOperationsHandler{store: store, authz: authz, exec: exec, worker: worker, audit: audit, frontendOrigin: frontendOrigin}
}

type operationDTO struct {
	ID             string  `json:"id"`
	VMID           string  `json:"vm_id,omitempty"`
	VMName         string  `json:"vm_name,omitempty"`
	UpdatePlanID   *string `json:"update_plan_id,omitempty"`
	Status         string  `json:"status"`
	CommandPreview string  `json:"command_preview,omitempty"`
	CommandHash    string  `json:"command_hash,omitempty"`
	CreatedBy      *string `json:"created_by,omitempty"`
	StartedAt      *string `json:"started_at,omitempty"`
	CompletedAt    *string `json:"completed_at,omitempty"`
	ExitCode       *int32  `json:"exit_code,omitempty"`
	Summary        string  `json:"summary,omitempty"`
	CreatedAt      string  `json:"created_at"`
}

func toOperationDTO(row generated.GetUpdateOperationDetailRow) operationDTO {
	dto := operationDTO{
		ID: row.ID.String(), Status: row.Status, CommandPreview: pgutil.TextOrEmpty(row.CommandPreview),
		CommandHash: pgutil.TextOrEmpty(row.CommandHash), Summary: pgutil.TextOrEmpty(row.Summary),
		VMName: row.VmName, VMID: row.VmResourceID.String(), CreatedAt: row.CreatedAt.Time.Format(time.RFC3339),
		StartedAt: formatTimestamptz(row.StartedAt), CompletedAt: formatTimestamptz(row.CompletedAt),
		ExitCode: pgutil.Int4Ptr(row.ExitCode),
	}
	if row.UpdatePlanID.Valid {
		id := pgutil.UUID(row.UpdatePlanID).String()
		dto.UpdatePlanID = &id
	}
	if name := pgutil.TextOrEmpty(row.CreatedByName); name != "" {
		dto.CreatedBy = &name
	}
	return dto
}

// authorizeOperationView loads the operation for :id and checks vm.view on
// its VM, 404-not-403 on any failure.
func (h *UpdateOperationsHandler) authorizeOperationView(w http.ResponseWriter, r *http.Request) (generated.GetUpdateOperationDetailRow, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.GetUpdateOperationDetailRow{}, false
	}
	operationID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update operation not found")
		return generated.GetUpdateOperationDetailRow{}, false
	}
	detail, err := h.store.GetUpdateOperationDetail(r.Context(), operationID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update operation not found")
		return generated.GetUpdateOperationDetailRow{}, false
	}
	allowed, err := h.authz.CanAccessVMAny(r.Context(), user, detail.VmResourceID, services.PermVMView, services.PermVMUpdates)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return generated.GetUpdateOperationDetailRow{}, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "update operation not found")
		return generated.GetUpdateOperationDetailRow{}, false
	}
	return detail, true
}

// Execute handles POST /api/update-plans/:id/execute (admin-only). This is
// the ONLY endpoint that can ever cause a real change on a VM. It never
// accepts a raw command -- only {"confirmation": true} against an already
// admin-approved plan; the backend generates and hashes the command
// itself. Returns immediately with PENDING; the HTTP request never blocks
// for the duration of execution.
func (h *UpdateOperationsHandler) Execute(w http.ResponseWriter, r *http.Request) {
	planID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		return
	}
	var req struct {
		Confirmation bool `json:"confirmation"`
	}
	if decErr := json.NewDecoder(r.Body).Decode(&req); decErr != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	op, err := h.exec.RequestExecution(r.Context(), planID, actor.ID, req.Confirmation)
	if err != nil {
		var precheckErr services.ExecutionPrecheckFailedError
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			httpx.WriteError(w, http.StatusNotFound, "update plan not found")
		case errors.Is(err, services.ErrUpdateConfirmationReq):
			httpx.WriteError(w, http.StatusBadRequest, "execution requires {\"confirmation\": true}")
		case errors.Is(err, services.ErrUpdatePlanNotReady), errors.Is(err, services.ErrUpdateAlreadyExecuting),
			errors.Is(err, services.ErrUpdateTooManyPackages), errors.Is(err, services.ErrUpdateVMRebooting):
			httpx.WriteError(w, http.StatusConflict, err.Error())
		case errors.As(err, &precheckErr):
			httpx.WriteJSON(w, http.StatusConflict, map[string]any{
				"error": "update plan failed pre-execution revalidation and was marked STALE",
				"precheck": map[string]any{
					"all_passed": precheckErr.Result.Report.AllPassed,
					"stale":      precheckErr.Result.Stale,
				},
			})
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to start execution")
		}
		return
	}

	h.worker.Enqueue(op.ID)

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"operation_id": op.ID.String(), "status": op.Status, "vm_id": op.ResourceID,
	})
}

// List handles GET /api/update-operations. Same member-scoping shape as
// UpdatesHandler.List: MEMBER only ever sees operations for VMs they're
// currently authorized on (spec: "If VM access is revoked, Member must no
// longer see that VM's update operations... Default: DENY").
func (h *UpdateOperationsHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var resourceIDs []uuid.UUID
	if !user.IsAdmin() {
		access, err := h.authz.GetUserVMAccess(r.Context(), user)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
			return
		}
		resourceIDs = make([]uuid.UUID, 0, len(access))
		for _, a := range access {
			resourceIDs = append(resourceIDs, a.ResourceID)
		}
	}

	limit := int32(50)
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 200 {
			limit = int32(parsed)
		}
	}
	offset := int32(0)
	if v := r.URL.Query().Get("offset"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = int32(parsed)
		}
	}

	rows, err := h.store.ListUpdateOperationsGlobal(r.Context(), generated.ListUpdateOperationsGlobalParams{
		Limit: limit, Offset: offset, ResourceIds: resourceIDs,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load update operations")
		return
	}
	items := make([]operationDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toOperationDTO(generated.GetUpdateOperationDetailRow(row)))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"operations": items})
}

// ListForVM handles GET /api/vms/:id/update-operations.
func (h *UpdateOperationsHandler) ListForVM(w http.ResponseWriter, r *http.Request) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	allowed, err := h.authz.CanAccessVMAny(r.Context(), user, resourceID, services.PermVMView, services.PermVMUpdates)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	rows, err := h.store.ListUpdateOperationsByResource(r.Context(), pgutil.NullUUID(&resourceID))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load update operations")
		return
	}
	items := make([]operationDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toOperationDTO(generated.GetUpdateOperationDetailRow{
			ID: row.ID, ResourceID: row.ResourceID, OperationType: row.OperationType, RequestedBy: row.RequestedBy,
			Status: row.Status, CommandPreview: row.CommandPreview, StartedAt: row.StartedAt, CompletedAt: row.CompletedAt,
			ExitCode: row.ExitCode, Summary: row.Summary, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
			UpdatePlanID: row.UpdatePlanID, CommandHash: row.CommandHash, VmName: row.VmName, VmResourceID: resourceID,
			CreatedByName: row.CreatedByName, CreatedByEmail: row.CreatedByEmail,
		}))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"operations": items})
}

// Get handles GET /api/update-operations/:id.
func (h *UpdateOperationsHandler) Get(w http.ResponseWriter, r *http.Request) {
	detail, ok := h.authorizeOperationView(w, r)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toOperationDTO(detail))
}

// Logs handles GET /api/update-operations/:id/logs -- the full persisted
// transcript in one response, for clients that don't need live streaming
// (e.g. loading a completed operation's page directly).
func (h *UpdateOperationsHandler) Logs(w http.ResponseWriter, r *http.Request) {
	detail, ok := h.authorizeOperationView(w, r)
	if !ok {
		return
	}
	logs, err := h.store.ListOperationLogs(r.Context(), detail.ID)
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

// LogsStream handles GET /api/update-operations/:id/logs/stream: a
// WebSocket that tails operation_logs, reusing the exact
// gorilla/websocket + ticker-polls-a-store-not-SSH pattern established by
// DockerHandler.Stream (Step 8) -- the only difference is polling an
// append-only cursor (sequence_number) instead of a latest-value cache,
// since logs are a transcript, not a single current sample. Closes itself
// (after a final "done" frame) once the operation reaches a terminal
// status, so a viewer never needs to keep the socket open forever.
func (h *UpdateOperationsHandler) LogsStream(w http.ResponseWriter, r *http.Request) {
	detail, ok := h.authorizeOperationView(w, r)
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
		logs, err := h.store.ListOperationLogsAfter(ctx, generated.ListOperationLogsAfterParams{OperationID: detail.ID, SequenceNumber: lastSeq})
		if err == nil {
			for _, l := range logs {
				lastSeq = l.SequenceNumber
				if conn.WriteJSON(map[string]any{"type": "log", "stream": l.Stream, "message": l.Message, "sequence": l.SequenceNumber}) != nil {
					return false
				}
			}
		}
		if current, err := h.store.GetOperationByID(ctx, detail.ID); err == nil {
			if services.IsTerminalOperationStatus(services.OperationStatus(current.Status)) {
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

// Steps handles GET /api/update-operations/:id/steps -- the progress
// checklist (Pre-check/Connect/Refresh metadata/Update/Verify/Discovery).
// Only ever reflects steps the backend has actually created/updated; a
// step not yet in this list has simply not started -- the UI must never
// fabricate progress beyond what this endpoint reports.
func (h *UpdateOperationsHandler) Steps(w http.ResponseWriter, r *http.Request) {
	detail, ok := h.authorizeOperationView(w, r)
	if !ok {
		return
	}
	steps, err := h.store.ListOperationSteps(r.Context(), detail.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load steps")
		return
	}
	items := make([]map[string]any, 0, len(steps))
	for _, s := range steps {
		items = append(items, map[string]any{
			"step_number": s.StepNumber, "step_type": s.StepType, "status": s.Status,
			"started_at": formatTimestamptz(s.StartedAt), "completed_at": formatTimestamptz(s.CompletedAt),
			"output_summary": pgutil.TextOrEmpty(s.OutputSummary), "error_summary": pgutil.TextOrEmpty(s.ErrorSummary),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"steps": items})
}

// Results handles GET /api/update-operations/:id/results.
func (h *UpdateOperationsHandler) Results(w http.ResponseWriter, r *http.Request) {
	detail, ok := h.authorizeOperationView(w, r)
	if !ok {
		return
	}
	results, err := h.store.ListOperationResults(r.Context(), detail.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load results")
		return
	}
	items := make([]map[string]any, 0, len(results))
	for _, res := range results {
		items = append(items, map[string]any{
			"package_name": res.PackageName, "before_version": res.BeforeVersion, "target_version": res.TargetVersion,
			"after_version": pgutil.TextOrEmpty(res.AfterVersion), "status": res.Status,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"results": items})
}

// Cancel handles POST /api/update-operations/:id/cancel (admin-only).
func (h *UpdateOperationsHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	operationID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update operation not found")
		return
	}
	op, err := h.exec.Cancel(r.Context(), operationID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrUpdateOperationNotFound):
			httpx.WriteError(w, http.StatusNotFound, "update operation not found")
		case errors.Is(err, services.ErrUpdateCancelUnavailable):
			httpx.WriteError(w, http.StatusConflict, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to cancel update operation")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": op.ID.String(), "status": op.Status})
}

// Verify handles POST /api/update-operations/:id/verify (admin-only,
// read-only): re-checks actual installed package versions on the VM.
// Never re-executes the update command and never changes operations.status.
func (h *UpdateOperationsHandler) Verify(w http.ResponseWriter, r *http.Request) {
	operationID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "update operation not found")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	results, err := h.exec.Verify(r.Context(), operationID, actor.ID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrUpdateOperationNotFound):
			httpx.WriteError(w, http.StatusNotFound, "update operation not found")
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to verify update operation")
		}
		return
	}
	items := make([]map[string]any, 0, len(results))
	for _, res := range results {
		items = append(items, map[string]any{
			"package_name": res.PackageName, "before_version": res.BeforeVersion, "target_version": res.TargetVersion,
			"after_version": pgutil.TextOrEmpty(res.AfterVersion), "status": res.Status,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"results": items})
}
