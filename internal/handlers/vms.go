package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/services"
)

// VMHandler implements the VM listing/detail/create/update endpoints.
// Every response is filtered through VMService, which itself defers to
// AuthorizationService: an ADMIN sees every VM, a MEMBER sees only VMs
// they have direct or group-derived access to. Unauthorized VMs are never
// returned or acknowledged to exist -- see docs/authorization.md's
// 404-not-403 policy.
type VMHandler struct {
	vms   *services.VMService
	audit *services.AuditService
}

// NewVMHandler creates a VMHandler.
func NewVMHandler(vms *services.VMService, audit *services.AuditService) *VMHandler {
	return &VMHandler{vms: vms, audit: audit}
}

// vmSummary is the list-view shape: enough to render a VM card/row
// without pulling full system-info fields nobody asked to see yet.
type vmSummary struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Workspace    string   `json:"workspace"`
	Status       string   `json:"status"`
	Address      string   `json:"address"`
	OSName       string   `json:"os_name,omitempty"`
	OSVersion    string   `json:"os_version,omitempty"`
	LastSeenAt   *string  `json:"last_seen_at,omitempty"`
	Permissions  []string `json:"permissions"`
	AccessSource string   `json:"access_source"`
	// WorkspaceID is purely additive alongside the Workspace name-string
	// field above -- needed so the monitoring dashboard's workspace filter
	// can match resources by ID rather than by display name (which is not
	// guaranteed unique).
	WorkspaceID string `json:"workspace_id"`
	// Agent-reported host identity -- current-value fields off the vms row
	// (migrations/060_vm_agent_host_identity.sql), populated only once the
	// VM Agent has pushed at least one sample; nil/omitted otherwise, never
	// fabricated. Backs the Metrics card grid's OS badge/filter.
	AgentOS            *string `json:"agent_os,omitempty"`
	AgentOSVersion     *string `json:"agent_os_version,omitempty"`
	AgentKernelVersion *string `json:"agent_kernel_version,omitempty"`
	AgentHostname      *string `json:"agent_hostname,omitempty"`
}

// vmDetail is the detail-view shape: every non-secret field on the VM.
// Discovery fields are nil/"Not discovered" until a later step's
// discovery job runs -- never fabricated (Step 4 spec §45).
type vmDetail struct {
	vmSummary
	Description       string  `json:"description,omitempty"`
	Hostname          string  `json:"hostname"`
	Username          string  `json:"username,omitempty"`
	SSHPort           int32   `json:"ssh_port"`
	KernelVersion     *string `json:"kernel_version,omitempty"`
	Architecture      *string `json:"architecture,omitempty"`
	CPUCores          *int32  `json:"cpu_cores,omitempty"`
	TotalMemoryBytes  *int64  `json:"total_memory_bytes,omitempty"`
	TotalStorageBytes *int64  `json:"total_storage_bytes,omitempty"`
	DockerInstalled   bool    `json:"docker_installed"`
	LastDiscoveredAt  *string `json:"last_discovered_at,omitempty"`
	MonitoringEnabled bool    `json:"monitoring_enabled"`
	// SSHKeyCredentialID/Name are set only when a named credential is
	// currently attached (see ssh_key_credentials.go) -- nil means this VM
	// is keyless and Console always prompts for an ephemeral key.
	SSHKeyCredentialID   *string `json:"ssh_key_credential_id,omitempty"`
	SSHKeyCredentialName *string `json:"ssh_key_credential_name,omitempty"`
}

func toVMSummary(row generated.GetVMDetailByResourceIDRow, permissions []string, source services.AccessSource) vmSummary {
	return vmSummary{
		ID:                 row.ResourceID.String(),
		Name:               row.Name,
		Workspace:          row.WorkspaceName,
		Status:             row.Status,
		Address:            row.Address,
		OSName:             pgutil.TextOrEmpty(row.OsName),
		OSVersion:          pgutil.TextOrEmpty(row.OsVersion),
		LastSeenAt:         formatTimestamptz(row.LastSeenAt),
		Permissions:        permissions,
		AccessSource:       string(source),
		WorkspaceID:        row.WorkspaceID.String(),
		AgentOS:            pgutil.StringPtr(row.VmAgentOs),
		AgentOSVersion:     pgutil.StringPtr(row.VmAgentOsVersion),
		AgentKernelVersion: pgutil.StringPtr(row.VmAgentKernelVersion),
		AgentHostname:      pgutil.StringPtr(row.VmAgentHostname),
	}
}

func toVMDetail(row generated.GetVMDetailByResourceIDRow, permissions []string, source services.AccessSource) vmDetail {
	return vmDetail{
		vmSummary:            toVMSummary(row, permissions, source),
		Description:          pgutil.TextOrEmpty(row.Description),
		Hostname:             row.Hostname,
		Username:             pgutil.TextOrEmpty(row.Username),
		SSHPort:              row.SshPort,
		KernelVersion:        pgutil.StringPtr(row.KernelVersion),
		Architecture:         pgutil.StringPtr(row.Architecture),
		CPUCores:             pgutil.Int4Ptr(row.CpuCores),
		TotalMemoryBytes:     pgutil.Int8Ptr(row.TotalMemoryBytes),
		TotalStorageBytes:    pgutil.Int8Ptr(row.TotalStorageBytes),
		DockerInstalled:      row.DockerInstalled,
		LastDiscoveredAt:     formatTimestamptz(row.LastDiscoveredAt),
		MonitoringEnabled:    row.MonitoringEnabled,
		SSHKeyCredentialID:   pgutil.UUIDPtr(row.SshKeyCredentialID),
		SSHKeyCredentialName: pgutil.StringPtr(row.SshKeyCredentialName),
	}
}

// formatTimestamptz renders a nullable timestamp as RFC 3339, or nil (so
// it's omitted from the JSON response) when the column is NULL -- e.g.
// "Never" for a VM that's never been seen, "Not discovered" for one never
// scanned.
func formatTimestamptz(t pgtype.Timestamptz) *string {
	tp := pgutil.TimePtr(t)
	if tp == nil {
		return nil
	}
	formatted := tp.Format(time.RFC3339)
	return &formatted
}

// List handles GET /api/vms: all VMs for ADMIN, only authorized VMs for
// MEMBER. Never a raw `SELECT * FROM vms` -- always filtered through
// VMService.List, which defers to AuthorizationService.GetUserVMAccess.
func (h *VMHandler) List(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	items, err := h.vms.List(r.Context(), user)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	summaries := make([]vmSummary, 0, len(items))
	for _, item := range items {
		summaries = append(summaries, toVMSummary(item.Detail, item.Permissions, item.Source))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"vms": summaries})
}

// Get handles GET /api/vms/:id. Authorization failure and "VM does not
// exist" are indistinguishable to the caller (404) so a member can never
// learn whether an unauthorized ID is a real VM.
func (h *VMHandler) Get(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	vmID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	item, err := h.vms.Get(r.Context(), user, vmID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, toVMDetail(item.Detail, item.Permissions, item.Source))
}

type createVMRequest struct {
	WorkspaceID        string `json:"workspace_id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	Address            string `json:"address"`
	Username           string `json:"username"`
	SSHPort            int32  `json:"ssh_port"`
	SSHKeyCredentialID string `json:"ssh_key_credential_id,omitempty"` // "" = keyless
}

// Create handles POST /api/vms: creates the resources+vms pair atomically
// with status UNKNOWN. No SSH connection or discovery happens here -- see
// Step 4 spec §13. ssh_key_credential_id optionally attaches an existing
// named credential (see ssh_key_credentials.go); omitted/empty leaves the
// VM keyless.
func (h *VMHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createVMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
		return
	}
	var sshKeyCredentialID *uuid.UUID
	if req.SSHKeyCredentialID != "" {
		id, err := uuid.Parse(req.SSHKeyCredentialID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid ssh_key_credential_id")
			return
		}
		sshKeyCredentialID = &id
	}

	resourceID, err := h.vms.Create(r.Context(), services.CreateVMInput{
		WorkspaceID: workspaceID, Name: req.Name,
		Description: req.Description, Address: req.Address, Username: req.Username, SSHPort: req.SSHPort,
		SSHKeyCredentialID: sshKeyCredentialID,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	metadata := map[string]any{"workspace_id": workspaceID.String(), "name": req.Name}
	if sshKeyCredentialID != nil {
		metadata["ssh_key_credential_id"] = sshKeyCredentialID.String()
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditVMCreated,
		ResourceType: "VM", ResourceID: &resourceID,
		Metadata: metadata,
	})

	created, err := h.vms.Get(r.Context(), actor, resourceID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, toVMDetail(created.Detail, created.Permissions, created.Source))
}

type updateVMRequest struct {
	Name              *string `json:"name,omitempty"`
	Description       *string `json:"description,omitempty"`
	WorkspaceID       *string `json:"workspace_id,omitempty"`
	Status            *string `json:"status,omitempty"`
	Username          *string `json:"username,omitempty"`
	Address           *string `json:"address,omitempty"`
	SSHPort           *int32  `json:"ssh_port,omitempty"`
	MonitoringEnabled *bool   `json:"monitoring_enabled,omitempty"`
	// SSHKeyCredentialID is three-state: absent (nil) leaves the current
	// credential unchanged, "" detaches it (VM becomes keyless), and a
	// uuid string attaches/replaces it.
	SSHKeyCredentialID *string `json:"ssh_key_credential_id,omitempty"`
}

// Update handles PATCH /api/vms/:id, including deactivation
// (status: "DISABLED") -- Step 4 §33 prefers this to physical deletion so
// audit/operation/monitoring history tied to the resource is preserved.
func (h *VMHandler) Update(w http.ResponseWriter, r *http.Request) {
	vmID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	var req updateVMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	before, err := h.vms.Get(r.Context(), actor, vmID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	in := services.UpdateVMInput{
		Name: req.Name, Description: req.Description, Status: req.Status,
		Username: req.Username, Address: req.Address, SSHPort: req.SSHPort,
		MonitoringEnabled: req.MonitoringEnabled,
	}
	if req.WorkspaceID != nil {
		parsedID, err := uuid.Parse(*req.WorkspaceID)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid workspace_id")
			return
		}
		in.WorkspaceID = &parsedID
	}
	if req.SSHKeyCredentialID != nil {
		if *req.SSHKeyCredentialID == "" {
			in.ClearSSHKeyCredential = true
		} else {
			parsedID, err := uuid.Parse(*req.SSHKeyCredentialID)
			if err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "invalid ssh_key_credential_id")
				return
			}
			in.SSHKeyCredentialID = &parsedID
		}
	}

	updated, err := h.vms.Update(r.Context(), vmID, in)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	action := services.AuditVMUpdated
	switch {
	case before.Detail.Status != "DISABLED" && updated.Status == "DISABLED":
		action = services.AuditVMDeactivated
	case before.Detail.SshKeyCredentialID != updated.SshKeyCredentialID:
		if updated.SshKeyCredentialID.Valid {
			action = services.AuditVMSSHKeyAttached
		} else {
			action = services.AuditVMSSHKeyDetached
		}
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: action, ResourceType: "VM", ResourceID: &vmID,
	})

	httpx.WriteJSON(w, http.StatusOK, toVMDetail(updated, before.Permissions, before.Source))
}

type vmAccessMemberResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	View         bool   `json:"view"`
	Console      bool   `json:"console"`
	AccessSource string `json:"access_source"`
}

// ListAccess handles GET /api/vms/:id/access: the "Authorized Members"
// list on the VM detail page (Step 4 §23), merging direct grants with the
// VM's group members.
func (h *VMHandler) ListAccess(w http.ResponseWriter, r *http.Request) {
	vmID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	entries, err := h.vms.ListAccess(r.Context(), vmID)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	members := make([]vmAccessMemberResponse, 0, len(entries))
	for _, e := range entries {
		view, console := false, false
		for _, p := range e.Permissions {
			if p == services.PermVMView {
				view = true
			}
			if p == services.PermVMConnect {
				console = true
			}
		}
		members = append(members, vmAccessMemberResponse{
			ID: e.UserID.String(), Name: e.Name, Email: e.Email,
			View: view, Console: console, AccessSource: string(e.Source),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"members": members})
}

// Delete handles DELETE /api/vms/:id (Step 22): removes the VM resource
// from Infra Hub Center only -- it never touches the actual remote
// server (see VMService.Delete's own doc comment for exactly what this
// does and doesn't affect). Requires the VM's exact current resource name
// as confirmation_name, independently validated server-side.
func (h *VMHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	var req deleteConfirmationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	actor, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	existing, err := h.vms.Get(r.Context(), actor, id)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	if err := h.vms.Delete(r.Context(), id, req.ConfirmationName); err != nil {
		writeServiceError(w, err)
		return
	}

	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditVMDeleted,
		ResourceType: "VM", ResourceID: &id,
		Metadata: map[string]any{"name": existing.Detail.Name},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
