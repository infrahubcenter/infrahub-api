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

// RebootOperationsHandler implements Step 11's controlled-reboot API.
// POST /api/vms/:id/reboot is the only endpoint that can send a real
// reboot command -- admin-only, requires explicit {"confirmation": true},
// never accepts a raw command. Every other mutating endpoint (cancel,
// verify) is admin-only too; every GET is any authenticated role with
// per-operation vm.view authorization inside the handler, mirroring
// UpdateOperationsHandler exactly.
type RebootOperationsHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	exec           *services.RebootExecutionService
	worker         *services.RebootExecutionWorker
	audit          *services.AuditService
	frontendOrigin string
}

// NewRebootOperationsHandler creates a RebootOperationsHandler.
func NewRebootOperationsHandler(
	store *repository.Store, authz *services.AuthorizationService, exec *services.RebootExecutionService,
	worker *services.RebootExecutionWorker, audit *services.AuditService, frontendOrigin string,
) *RebootOperationsHandler {
	return &RebootOperationsHandler{store: store, authz: authz, exec: exec, worker: worker, audit: audit, frontendOrigin: frontendOrigin}
}

type rebootOperationDTO struct {
	ID             string  `json:"id"`
	VMID           string  `json:"vm_id,omitempty"`
	VMName         string  `json:"vm_name,omitempty"`
	Reason         string  `json:"reason"`
	Status         string  `json:"status"`
	CreatedBy      *string `json:"created_by,omitempty"`
	StartedAt      *string `json:"started_at,omitempty"`
	RebootSentAt   *string `json:"reboot_sent_at,omitempty"`
	DisconnectedAt *string `json:"disconnected_at,omitempty"`
	ReconnectedAt  *string `json:"reconnected_at,omitempty"`
	CompletedAt    *string `json:"completed_at,omitempty"`
	TimeoutAt      *string `json:"timeout_at,omitempty"`
	ErrorSummary   string  `json:"error_summary,omitempty"`
	CreatedAt      string  `json:"created_at"`
}

func toRebootOperationDTO(row generated.GetRebootOperationDetailRow) rebootOperationDTO {
	dto := rebootOperationDTO{
		ID: row.ID.String(), VMID: row.VmResourceID.String(), VMName: row.VmName,
		Reason: row.Reason, Status: row.Status, ErrorSummary: pgutil.TextOrEmpty(row.ErrorSummary),
		CreatedAt: row.CreatedAt.Time.Format(time.RFC3339),
		StartedAt: formatTimestamptz(row.StartedAt), RebootSentAt: formatTimestamptz(row.RebootSentAt),
		DisconnectedAt: formatTimestamptz(row.DisconnectedAt), ReconnectedAt: formatTimestamptz(row.ReconnectedAt),
		CompletedAt: formatTimestamptz(row.CompletedAt), TimeoutAt: formatTimestamptz(row.TimeoutAt),
	}
	if name := pgutil.TextOrEmpty(row.CreatedByName); name != "" {
		dto.CreatedBy = &name
	}
	return dto
}

func (h *RebootOperationsHandler) authorizeOperationView(w http.ResponseWriter, r *http.Request) (generated.GetRebootOperationDetailRow, bool) {
	user, authed := services.UserFromContext(r.Context())
	if !authed {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return generated.GetRebootOperationDetailRow{}, false
	}
	operationID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "reboot operation not found")
		return generated.GetRebootOperationDetailRow{}, false
	}
	detail, err := h.store.GetRebootOperationDetail(r.Context(), operationID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "reboot operation not found")
		return generated.GetRebootOperationDetailRow{}, false
	}
	allowed, err := h.authz.CanAccessVMAny(r.Context(), user, detail.VmResourceID, services.PermVMView, services.PermVMUpdates)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "authorization check failed")
		return generated.GetRebootOperationDetailRow{}, false
	}
	if !allowed {
		httpx.WriteError(w, http.StatusNotFound, "reboot operation not found")
		return generated.GetRebootOperationDetailRow{}, false
	}
	return detail, true
}

// Precheck handles POST /api/vms/:id/reboot/precheck (admin-only,
// read-only -- never sends a reboot command).
func (h *RebootOperationsHandler) Precheck(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	if _, err := h.store.GetVMResourceByID(r.Context(), resourceID); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	report, err := h.exec.RunPrecheck(r.Context(), resourceID, uuid.Nil)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to run reboot prechecks")
		return
	}
	items := make([]precheckItemDTO, 0, len(report.Items))
	for _, item := range report.Items {
		items = append(items, precheckItemDTO{Name: item.Name, Status: string(item.Status), Message: item.Message})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ready": report.AllPassed, "checks": items})
}

// Reboot handles POST /api/vms/:id/reboot (admin-only). The only endpoint
// in this project that can send a real reboot command to a VM.
func (h *RebootOperationsHandler) Reboot(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	var req struct {
		Confirmation bool   `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if decErr := json.NewDecoder(r.Body).Decode(&req); decErr != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	op, err := h.exec.RequestReboot(r.Context(), resourceID, actor.ID, req.Reason, req.Confirmation)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrRebootConfirmationReq):
			httpx.WriteError(w, http.StatusBadRequest, "reboot requires {\"confirmation\": true}")
		case errors.Is(err, services.ErrRebootInvalidReason):
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, services.ErrRebootNotRequired), errors.Is(err, services.ErrRebootUpdateRunning),
			errors.Is(err, services.ErrRebootAlreadyRunning), errors.Is(err, services.ErrRebootChecksFailed):
			httpx.WriteError(w, http.StatusConflict, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to start reboot")
		}
		return
	}

	h.worker.Enqueue(op.ID)

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"operation_id": op.ID.String(), "status": op.Status, "vm_id": resourceID.String(),
	})
}

// List handles GET /api/reboot-operations.
func (h *RebootOperationsHandler) List(w http.ResponseWriter, r *http.Request) {
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

	rows, err := h.store.ListRebootOperationsGlobal(r.Context(), generated.ListRebootOperationsGlobalParams{
		Limit: limit, Offset: offset, ResourceIds: resourceIDs,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load reboot operations")
		return
	}
	items := make([]rebootOperationDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toRebootOperationDTO(generated.GetRebootOperationDetailRow(row)))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"reboot_operations": items})
}

// ListForVM handles GET /api/vms/:id/reboot-operations.
func (h *RebootOperationsHandler) ListForVM(w http.ResponseWriter, r *http.Request) {
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
	vm, err := h.store.GetVMByResourceID(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	rows, err := h.store.ListRebootOperationsByVM(r.Context(), vm.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load reboot operations")
		return
	}
	items := make([]rebootOperationDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, toRebootOperationDTO(generated.GetRebootOperationDetailRow{
			ID: row.ID, VmID: row.VmID, CreatedBy: row.CreatedBy, Reason: row.Reason, Status: row.Status,
			StartedAt: row.StartedAt, RebootSentAt: row.RebootSentAt, DisconnectedAt: row.DisconnectedAt,
			ReconnectedAt: row.ReconnectedAt, CompletedAt: row.CompletedAt, TimeoutAt: row.TimeoutAt,
			ErrorSummary: row.ErrorSummary, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
			VmName: row.VmName, VmResourceID: resourceID, CreatedByName: row.CreatedByName, CreatedByEmail: row.CreatedByEmail,
		}))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"reboot_operations": items})
}

// Get handles GET /api/reboot-operations/:id and .../status (an alias --
// both return the same operation detail; a dedicated lightweight status
// endpoint would only save a handful of bytes here).
func (h *RebootOperationsHandler) Get(w http.ResponseWriter, r *http.Request) {
	detail, ok := h.authorizeOperationView(w, r)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toRebootOperationDTO(detail))
}

// Logs handles GET /api/reboot-operations/:id/logs.
func (h *RebootOperationsHandler) Logs(w http.ResponseWriter, r *http.Request) {
	detail, ok := h.authorizeOperationView(w, r)
	if !ok {
		return
	}
	logs, err := h.store.ListRebootOperationLogs(r.Context(), detail.ID)
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

// LogsStream handles GET /api/reboot-operations/:id/logs/stream, reusing
// the exact gorilla/websocket + ticker-polls-a-store pattern established
// by Step 8's DockerHandler.Stream and reused by Step 10's
// UpdateOperationsHandler.LogsStream.
func (h *RebootOperationsHandler) LogsStream(w http.ResponseWriter, r *http.Request) {
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
		logs, err := h.store.ListRebootOperationLogsAfter(ctx, generated.ListRebootOperationLogsAfterParams{RebootOperationID: detail.ID, SequenceNumber: lastSeq})
		if err == nil {
			for _, l := range logs {
				lastSeq = l.SequenceNumber
				if conn.WriteJSON(map[string]any{"type": "log", "stream": l.Stream, "message": l.Message, "sequence": l.SequenceNumber}) != nil {
					return false
				}
			}
		}
		if current, err := h.store.GetRebootOperationByID(ctx, detail.ID); err == nil {
			if services.IsTerminalRebootStatus(services.RebootStatus(current.Status)) {
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

// Results handles GET /api/reboot-operations/:id/results -- the
// before/after comparison table.
func (h *RebootOperationsHandler) Results(w http.ResponseWriter, r *http.Request) {
	detail, ok := h.authorizeOperationView(w, r)
	if !ok {
		return
	}
	results, err := h.store.ListRebootVerificationResults(r.Context(), detail.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load results")
		return
	}
	items := make([]map[string]any, 0, len(results))
	for _, res := range results {
		items = append(items, map[string]any{
			"check_type": res.CheckType, "expected_value": pgutil.TextOrEmpty(res.ExpectedValue),
			"actual_value": pgutil.TextOrEmpty(res.ActualValue), "status": res.Status,
			"error_summary": pgutil.TextOrEmpty(res.ErrorSummary), "checked_at": res.CheckedAt.Time.Format(time.RFC3339),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"results": items})
}

// Cancel handles POST /api/reboot-operations/:id/cancel (admin-only).
func (h *RebootOperationsHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	operationID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "reboot operation not found")
		return
	}
	op, err := h.exec.Cancel(r.Context(), operationID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrRebootOperationNotFound):
			httpx.WriteError(w, http.StatusNotFound, "reboot operation not found")
		case errors.Is(err, services.ErrRebootCancelUnavailable):
			httpx.WriteError(w, http.StatusConflict, err.Error())
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to cancel reboot operation")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"id": op.ID.String(), "status": op.Status})
}

// Verify handles POST /api/reboot-operations/:id/verify (admin-only,
// read-only). Never sends another reboot command.
func (h *RebootOperationsHandler) Verify(w http.ResponseWriter, r *http.Request) {
	operationID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "reboot operation not found")
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	results, err := h.exec.Verify(r.Context(), operationID, actor.ID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrRebootOperationNotFound):
			httpx.WriteError(w, http.StatusNotFound, "reboot operation not found")
		default:
			httpx.WriteError(w, http.StatusInternalServerError, "failed to verify reboot operation")
		}
		return
	}
	items := make([]map[string]any, 0, len(results))
	for _, res := range results {
		items = append(items, map[string]any{
			"check_type": res.CheckType, "expected_value": pgutil.TextOrEmpty(res.ExpectedValue),
			"actual_value": pgutil.TextOrEmpty(res.ActualValue), "status": res.Status,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"results": items})
}
