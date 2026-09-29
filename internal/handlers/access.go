package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

// AccessHandler implements direct VM access grant/revoke
// (POST/DELETE /api/users/:id/vm-access...). Group membership endpoints
// live in GroupHandler. Every route here is mounted behind
// RequireRole(ADMIN).
type AccessHandler struct {
	access *services.AccessService
	audit  *services.AuditService
}

// NewAccessHandler creates an AccessHandler.
func NewAccessHandler(access *services.AccessService, audit *services.AuditService) *AccessHandler {
	return &AccessHandler{access: access, audit: audit}
}

type grantVMAccessRequest struct {
	VMID        string   `json:"vm_id"`
	Permissions []string `json:"permissions"`
}

// GrantVMAccess handles POST /api/users/:id/vm-access.
func (h *AccessHandler) GrantVMAccess(w http.ResponseWriter, r *http.Request) {
	targetUserID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "user not found")
		return
	}

	var req grantVMAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	vmID, err := uuid.Parse(req.VMID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid vm_id")
		return
	}

	if err := h.access.GrantVMAccess(r.Context(), targetUserID, vmID, req.Permissions); err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID:       &actor.ID,
		Action:       services.AuditVMAccessGranted,
		ResourceType: "VM",
		ResourceID:   &vmID,
		Metadata:     map[string]any{"target_user_id": targetUserID.String(), "permissions": req.Permissions},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// RevokeVMAccess handles DELETE /api/users/:id/vm-access/:vmId.
func (h *AccessHandler) RevokeVMAccess(w http.ResponseWriter, r *http.Request) {
	targetUserID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	vmID, err := uuid.Parse(r.PathValue("vmId"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	if err := h.access.RevokeVMAccess(r.Context(), targetUserID, vmID); err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID:       &actor.ID,
		Action:       services.AuditVMAccessRevoked,
		ResourceType: "VM",
		ResourceID:   &vmID,
		Metadata:     map[string]any{"target_user_id": targetUserID.String()},
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
