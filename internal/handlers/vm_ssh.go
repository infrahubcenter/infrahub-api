package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/httpx"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

// SSHHandler implements connection testing, host-key trust, and
// discovery. Write operations (test connection, discover, trust host key)
// are ADMIN-only (mounted behind RequireRole(ADMIN) in router.go, Step 5
// §44); the two GET endpoints are any authenticated role but still
// individually check VM authorization, since a member may only see
// connection/discovery information for VMs they're authorized for
// (Step 5 §45-47). SSH credential management itself moved to
// SSHKeyCredentialHandler (ssh_key_credentials.go) -- a VM now points at
// a named, reusable credential (vms.ssh_key_credential_id) rather than
// having one uploaded to it directly.
type SSHHandler struct {
	store          *repository.Store
	authz          *services.AuthorizationService
	hostKeys       *services.HostKeyService
	ssh            *services.SSHService
	discovery      *services.VMDiscoveryService
	audit          *services.AuditService
	connectTimeout time.Duration
}

// NewSSHHandler creates an SSHHandler.
func NewSSHHandler(
	store *repository.Store,
	authz *services.AuthorizationService,
	hostKeys *services.HostKeyService,
	ssh *services.SSHService,
	discovery *services.VMDiscoveryService,
	audit *services.AuditService,
	connectTimeout time.Duration,
) *SSHHandler {
	return &SSHHandler{
		store: store, authz: authz, hostKeys: hostKeys,
		ssh: ssh, discovery: discovery, audit: audit, connectTimeout: connectTimeout,
	}
}

// loadVM resolves the :id path value to a VM, checked against the
// resources table (so it must be a non-deleted VM-type resource) and
// returns both identifiers every SSH handler needs: resourceID (the
// authorization/audit key, per docs/database-architecture.md) and the
// vms.id row ID (what the connection-status/discovery-run columns key
// off).
func (h *SSHHandler) loadVM(w http.ResponseWriter, r *http.Request) (resourceID uuid.UUID, vmRowID uuid.UUID, ok bool) {
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, uuid.Nil, false
	}
	if _, err := h.store.GetVMResourceByID(r.Context(), resourceID); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, uuid.Nil, false
	}
	vmRow, err := h.store.GetVMByResourceID(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return uuid.Nil, uuid.Nil, false
	}
	return resourceID, vmRow.ID, true
}

type connectionTestResponse struct {
	Status    string        `json:"status"`
	Host      string        `json:"host,omitempty"`
	Port      int           `json:"port,omitempty"`
	Username  string        `json:"username,omitempty"`
	LatencyMS int64         `json:"latency_ms,omitempty"`
	ErrorCode string        `json:"error_code,omitempty"`
	Message   string        `json:"message,omitempty"`
	HostKey   *hostKeyBrief `json:"host_key,omitempty"`
}

type hostKeyBrief struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
}

// TestConnection handles POST /api/vms/:id/connection-test. This is an
// operation endpoint: it always returns 200 with a structured body
// describing the outcome (Step 5 §16/§17), reserving HTTP error statuses
// for request-level problems (not found, not authorized, bad body).
func (h *SSHHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	resourceID, vmRowID, ok := h.loadVM(w, r)
	if !ok {
		return
	}

	result, connErr := h.ssh.TestConnection(r.Context(), resourceID)
	if err := recordOutcomeAndAudit(r, h, resourceID, vmRowID, connErr); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to record connection outcome")
		return
	}

	if connErr == nil {
		httpx.WriteJSON(w, http.StatusOK, connectionTestResponse{
			Status: "connected", Host: result.Host, Port: result.Port,
			Username: result.Username, LatencyMS: result.LatencyMS,
		})
		return
	}

	httpx.WriteJSON(w, http.StatusOK, sshErrorToResponse(connErr))
}

func sshErrorToResponse(connErr error) connectionTestResponse {
	var sshErr *services.SSHError
	if !errors.As(connErr, &sshErr) {
		return connectionTestResponse{Status: "failed", Message: "Connection failed."}
	}

	resp := connectionTestResponse{Status: "failed", ErrorCode: sshErr.Code, Message: sshErr.Message}

	var unknown *services.HostKeyUnknownError
	if errors.As(connErr, &unknown) {
		resp.Status = "host_key_unknown"
		resp.HostKey = &hostKeyBrief{Host: unknown.Host, Port: unknown.Port, Algorithm: unknown.Algorithm, Fingerprint: unknown.Fingerprint}
	}
	var changed *services.HostKeyChangedError
	if errors.As(connErr, &changed) {
		resp.Status = "host_key_changed"
		resp.HostKey = &hostKeyBrief{Host: changed.Host, Port: changed.Port, Algorithm: changed.Algorithm, Fingerprint: changed.NewFingerprint}
	}
	return resp
}

func recordOutcomeAndAudit(r *http.Request, h *SSHHandler, resourceID, vmRowID uuid.UUID, connErr error) error {
	if err := services.RecordConnectionOutcome(r.Context(), h.store, resourceID, vmRowID, connErr); err != nil {
		return err
	}
	actor, _ := services.UserFromContext(r.Context())
	action := services.AuditSSHConnectionTest
	if connErr != nil {
		action = services.AuditSSHConnectionFailed
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: action, ResourceType: "VM", ResourceID: &resourceID,
	})
	return nil
}

type discoverResponse struct {
	Status string              `json:"status"`
	VM     *vmDiscovery        `json:"vm,omitempty"`
	Error  string              `json:"error,omitempty"`
	Fields []discoveryFieldDTO `json:"fields,omitempty"`
}

type discoveryFieldDTO struct {
	Name      string `json:"name"`
	Succeeded bool   `json:"succeeded"`
	Error     string `json:"error,omitempty"`
}

type vmDiscovery struct {
	ID              string  `json:"id"`
	Hostname        *string `json:"hostname,omitempty"`
	OSName          *string `json:"os_name,omitempty"`
	OSVersion       *string `json:"os_version,omitempty"`
	DistributionID  *string `json:"distribution_id,omitempty"`
	Kernel          *string `json:"kernel,omitempty"`
	Architecture    *string `json:"architecture,omitempty"`
	CPUCores        *int32  `json:"cpu_cores,omitempty"`
	MemoryBytes     *int64  `json:"memory_bytes,omitempty"`
	StorageBytes    *int64  `json:"storage_bytes,omitempty"`
	DockerInstalled *bool   `json:"docker_installed,omitempty"`
}

// Discover handles POST /api/vms/:id/discover.
func (h *SSHHandler) Discover(w http.ResponseWriter, r *http.Request) {
	resourceID, _, ok := h.loadVM(w, r)
	if !ok {
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: services.AuditVMDiscoveryStarted, ResourceType: "VM", ResourceID: &resourceID,
	})

	result, err := h.discovery.Discover(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "discovery failed")
		return
	}

	action := services.AuditVMDiscoveryCompleted
	if result.Status == "FAILED" {
		action = services.AuditVMDiscoveryFailed
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: action, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"status": result.Status},
	})

	resp := discoverResponse{Status: toLowerStatus(result.Status), Error: result.ErrorSummary}
	if result.Status != "FAILED" {
		resp.VM = &vmDiscovery{
			ID: resourceID.String(), Hostname: result.Hostname, OSName: result.OSName, OSVersion: result.OSVersion,
			DistributionID: result.DistributionID, Kernel: result.KernelVersion, Architecture: result.Architecture,
			CPUCores: result.CPUCores, MemoryBytes: result.TotalMemoryBytes, StorageBytes: result.TotalStorageBytes,
			DockerInstalled: result.DockerInstalled,
		}
	}
	for _, f := range result.Fields {
		resp.Fields = append(resp.Fields, discoveryFieldDTO{Name: f.Name, Succeeded: f.Succeeded, Error: f.Error})
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type connectionStatusResponse struct {
	ConnectionStatus     string  `json:"connection_status"`
	CredentialConfigured bool    `json:"credential_configured"`
	SSHKeyCredentialID   *string `json:"ssh_key_credential_id,omitempty"`
	LastConnectionAt     *string `json:"last_connection_at,omitempty"`
	LastConnectionError  *string `json:"last_connection_error,omitempty"`
}

// GetConnectionStatus handles GET /api/vms/:id/connection-status. Any
// authenticated role, gated by VM authorization (same 404-not-403 policy
// as GET /api/vms/:id).
func (h *SSHHandler) GetConnectionStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	allowed, err := h.authz.CanAccessVM(r.Context(), user, resourceID, services.PermVMView)
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

	resp := connectionStatusResponse{ConnectionStatus: vm.ConnectionStatus, CredentialConfigured: vm.SshKeyCredentialID.Valid}
	if vm.SshKeyCredentialID.Valid {
		id := pgutil.UUID(vm.SshKeyCredentialID).String()
		resp.SSHKeyCredentialID = &id
	}
	if t := pgutil.TimePtr(vm.LastConnectionAt); t != nil {
		formatted := t.Format(time.RFC3339)
		resp.LastConnectionAt = &formatted
	}
	if msg := pgutil.StringPtr(vm.LastConnectionError); msg != nil {
		resp.LastConnectionError = msg
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type discoveryRunResponse struct {
	ID           string  `json:"id"`
	Status       string  `json:"status"`
	StartedAt    string  `json:"started_at"`
	CompletedAt  *string `json:"completed_at,omitempty"`
	ErrorSummary *string `json:"error_summary,omitempty"`
}

// GetDiscoveryHistory handles GET /api/vms/:id/discovery. Any
// authenticated role, gated by VM authorization.
func (h *SSHHandler) GetDiscoveryHistory(w http.ResponseWriter, r *http.Request) {
	user, ok := services.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	resourceID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}
	allowed, err := h.authz.CanAccessVM(r.Context(), user, resourceID, services.PermVMView)
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
	runs, err := h.store.ListDiscoveryRunsByVM(r.Context(), generated.ListDiscoveryRunsByVMParams{VmID: vm.ID, Limit: 20})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load discovery history")
		return
	}

	items := make([]discoveryRunResponse, 0, len(runs))
	for _, run := range runs {
		item := discoveryRunResponse{ID: run.ID.String(), Status: run.Status, StartedAt: run.StartedAt.Time.Format(time.RFC3339)}
		if t := pgutil.TimePtr(run.CompletedAt); t != nil {
			formatted := t.Format(time.RFC3339)
			item.CompletedAt = &formatted
		}
		item.ErrorSummary = pgutil.StringPtr(run.ErrorSummary)
		items = append(items, item)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"runs": items})
}

type trustHostKeyResponse struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
}

// TrustHostKey handles POST /api/vms/:id/host-key/trust. It independently
// re-dials the VM to fetch its current host key rather than trusting a
// client-supplied fingerprint (Step 5 §12) -- see HostKeyService.Trust.
func (h *SSHHandler) TrustHostKey(w http.ResponseWriter, r *http.Request) {
	resourceID, _, ok := h.loadVM(w, r)
	if !ok {
		return
	}

	vm, err := h.store.GetVMByResourceID(r.Context(), resourceID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "VM not found")
		return
	}

	_, existingErr := h.store.GetHostKeyByResource(r.Context(), resourceID)
	hadTrustedKey := !errors.Is(existingErr, pgx.ErrNoRows)

	info, err := h.hostKeys.Trust(r.Context(), resourceID, vm.Address, int(vm.SshPort), h.connectTimeout)
	if err != nil {
		sshErr := classifyForHandler(err)
		httpx.WriteError(w, http.StatusBadGateway, sshErr)
		return
	}

	actor, _ := services.UserFromContext(r.Context())
	action := services.AuditSSHHostKeyTrusted
	if hadTrustedKey {
		action = services.AuditSSHHostKeyChanged
	}
	_ = h.audit.LogFrom(r, services.AuditEvent{
		UserID: &actor.ID, Action: action, ResourceType: "VM", ResourceID: &resourceID,
		Metadata: map[string]any{"algorithm": info.Algorithm, "fingerprint": info.Fingerprint},
	})

	httpx.WriteJSON(w, http.StatusOK, trustHostKeyResponse{
		Host: info.Host, Port: info.Port, Algorithm: info.Algorithm, Fingerprint: info.Fingerprint,
	})
}

func toLowerStatus(s string) string {
	switch s {
	case "SUCCESS":
		return "success"
	case "PARTIAL":
		return "partial"
	case "FAILED":
		return "failed"
	default:
		return "unknown"
	}
}

func classifyForHandler(err error) string {
	var sshErr *services.SSHError
	if errors.As(err, &sshErr) {
		return sshErr.Message
	}
	return "Could not verify host key."
}
