// Package handlers: ssh_key_credentials.go implements admin-only CRUD for
// named, reusable SSH key credentials (services.SSHKeyCredentialService) --
// the replacement for the old per-VM "paste a key" flow. Every route is
// mounted behind requireAdmin in router.go: only an admin can attach a
// credential to a VM (VM create/update are already admin-only), so a
// non-admin has no use for even the list/fingerprint view, and these stay
// sensitive security configuration objects regardless.
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/services"
)

type SSHKeyCredentialHandler struct {
	credentials *services.SSHKeyCredentialService
	audit       *services.AuditService
}

func NewSSHKeyCredentialHandler(credentials *services.SSHKeyCredentialService, audit *services.AuditService) *SSHKeyCredentialHandler {
	return &SSHKeyCredentialHandler{credentials: credentials, audit: audit}
}

type sshKeyCredentialResponse struct {
	ID          string  `json:"id"`
	WorkspaceID string  `json:"workspace_id"`
	Name        string  `json:"name"`
	Fingerprint string  `json:"fingerprint"`
	CreatedBy   *string `json:"created_by,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	InUseCount  int64   `json:"in_use_count"`
}

func toSSHKeyCredentialResponse(s services.SSHKeyCredentialSummary) sshKeyCredentialResponse {
	resp := sshKeyCredentialResponse{
		ID: s.ID.String(), WorkspaceID: s.WorkspaceID.String(), Name: s.Name, Fingerprint: s.Fingerprint,
		CreatedAt: s.CreatedAt.Format(time.RFC3339), UpdatedAt: s.UpdatedAt.Format(time.RFC3339), InUseCount: s.InUseCount,
	}
	if s.CreatedBy != nil {
		id := s.CreatedBy.String()
		resp.CreatedBy = &id
	}
	return resp
}

type createSSHKeyCredentialRequest struct {
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	PrivateKey  string `json:"private_key"`
}

// Create handles POST /api/ssh-key-credentials.
func (h *SSHKeyCredentialHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createSSHKeyCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}
	if req.PrivateKey == "" {
		httpx.WriteError(w, http.StatusBadRequest, "private_key is required")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	cred, err := h.credentials.Create(r.Context(), workspaceID, req.Name, []byte(req.PrivateKey), actor.ID)
	if err != nil {
		writeSSHKeyCredentialError(w, err)
		return
	}

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditSSHKeyCredentialCreated, ResourceType: "SSH_KEY_CREDENTIAL", ResourceID: &cred.ID,
		Metadata: map[string]any{"name": cred.Name, "workspace_id": cred.WorkspaceID.String()},
	})
	httpx.WriteJSON(w, http.StatusCreated, toSSHKeyCredentialResponse(cred))
}

// List handles GET /api/ssh-key-credentials?workspace_id=.
func (h *SSHKeyCredentialHandler) List(w http.ResponseWriter, r *http.Request) {
	workspaceID, err := uuid.Parse(r.URL.Query().Get("workspace_id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "workspace_id is required")
		return
	}
	creds, err := h.credentials.List(r.Context(), workspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load ssh key credentials")
		return
	}
	items := make([]sshKeyCredentialResponse, 0, len(creds))
	for _, c := range creds {
		items = append(items, toSSHKeyCredentialResponse(c))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"credentials": items})
}

// Get handles GET /api/ssh-key-credentials/{id}.
func (h *SSHKeyCredentialHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "ssh key credential not found")
		return
	}
	cred, err := h.credentials.Get(r.Context(), id)
	if err != nil {
		writeSSHKeyCredentialError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toSSHKeyCredentialResponse(cred))
}

type renameSSHKeyCredentialRequest struct {
	Name string `json:"name"`
}

// Rename handles PATCH /api/ssh-key-credentials/{id}.
func (h *SSHKeyCredentialHandler) Rename(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "ssh key credential not found")
		return
	}
	var req renameSSHKeyCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cred, err := h.credentials.Rename(r.Context(), id, req.Name)
	if err != nil {
		writeSSHKeyCredentialError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditSSHKeyCredentialRenamed, ResourceType: "SSH_KEY_CREDENTIAL", ResourceID: &id,
		Metadata: map[string]any{"name": cred.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, toSSHKeyCredentialResponse(cred))
}

// Delete handles DELETE /api/ssh-key-credentials/{id}.
func (h *SSHKeyCredentialHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "ssh key credential not found")
		return
	}
	cred, err := h.credentials.Get(r.Context(), id)
	if err != nil {
		writeSSHKeyCredentialError(w, err)
		return
	}
	if err := h.credentials.Delete(r.Context(), id); err != nil {
		writeSSHKeyCredentialError(w, err)
		return
	}
	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditSSHKeyCredentialDeleted, ResourceType: "SSH_KEY_CREDENTIAL", ResourceID: &id,
		Metadata: map[string]any{"name": cred.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func writeSSHKeyCredentialError(w http.ResponseWriter, err error) {
	writeServiceError(w, err)
}
