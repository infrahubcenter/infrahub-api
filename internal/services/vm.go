package services

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

const defaultSSHPort = 22

// VMService implements VM resource registration and retrieval. Creating a
// VM writes both the common resources row and the vms detail row in one
// transaction (Step 4 spec §48) -- a VM never exists as one without the
// other.
type VMService struct {
	store *repository.Store
	authz *AuthorizationService
}

// NewVMService creates a VMService.
func NewVMService(store *repository.Store, authz *AuthorizationService) *VMService {
	return &VMService{store: store, authz: authz}
}

// CreateVMInput is the non-secret VM configuration captured at
// registration time. SSHKeyCredentialID optionally attaches an existing
// named credential (SSHKeyCredentialService) -- nil leaves the VM keyless,
// in which case Console always prompts for an ephemeral key.
type CreateVMInput struct {
	WorkspaceID        uuid.UUID
	Name               string
	Description        string
	Address            string
	Username           string
	SSHPort            int32
	SSHKeyCredentialID *uuid.UUID
}

// Create validates input, verifies the workspace exists, and creates the
// resource+vms pair atomically. The resource starts with status UNKNOWN --
// registering a VM is not the same as confirming it's reachable (Step 4
// spec §17); only a future discovery step can change that.
func (s *VMService) Create(ctx context.Context, in CreateVMInput) (uuid.UUID, error) {
	name, err := validateName("VM name", in.Name)
	if err != nil {
		return uuid.Nil, err
	}
	address, err := validateAddress(in.Address)
	if err != nil {
		return uuid.Nil, err
	}
	sshPort := in.SSHPort
	if sshPort == 0 {
		sshPort = defaultSSHPort
	}
	if err := validateSSHPort(sshPort); err != nil {
		return uuid.Nil, err
	}

	if _, err := s.store.GetWorkspaceByID(ctx, in.WorkspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, fmt.Errorf("%w: workspace", ErrNotFound)
		}
		return uuid.Nil, fmt.Errorf("load workspace: %w", err)
	}
	if in.SSHKeyCredentialID != nil {
		cred, err := s.store.GetSSHKeyCredentialByID(ctx, *in.SSHKeyCredentialID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return uuid.Nil, fmt.Errorf("%w: ssh_key_credential_id", ErrNotFound)
			}
			return uuid.Nil, fmt.Errorf("load ssh key credential: %w", err)
		}
		if cred.WorkspaceID != in.WorkspaceID {
			return uuid.Nil, fmt.Errorf("%w: ssh key credential belongs to a different workspace", ErrValidation)
		}
	}

	var resourceID uuid.UUID
	err = s.store.WithTx(ctx, func(q *generated.Queries) error {
		resource, err := q.CreateResource(ctx, generated.CreateResourceParams{
			WorkspaceID:  in.WorkspaceID,
			Name:         name,
			ResourceType: "VM",
			Description:  pgutil.Text(in.Description),
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: a resource named %q already exists", ErrDuplicateName, name)
			}
			return fmt.Errorf("create resource: %w", err)
		}

		// hostname defaults to the resource name at registration; a later
		// discovery step overwrites it with the OS-reported hostname.
		if _, err := q.CreateVM(ctx, generated.CreateVMParams{
			ResourceID:         resource.ID,
			Hostname:           name,
			Username:           pgutil.Text(in.Username),
			Address:            address,
			SshPort:            sshPort,
			SshKeyCredentialID: pgutil.NullUUID(in.SSHKeyCredentialID),
		}); err != nil {
			return fmt.Errorf("create vm: %w", err)
		}

		resourceID = resource.ID
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return resourceID, nil
}

// CreateAgentOnlyInput is a "Connect VM" request -- no SSH fields at
// all, mirroring DockerHostService.Configure's input exactly.
type CreateAgentOnlyInput struct {
	WorkspaceID uuid.UUID
	Name        string
}

// CreateAgentOnly registers a VM with no SSH connectivity whatsoever --
// address is stored as "" (the vms.address column stays NOT NULL; an
// empty string is the sentinel for "never had one," same discipline
// used elsewhere in this codebase rather than widening a column's
// nullability just to represent absence). This is deliberately a
// separate, minimal path from Create: it skips validateAddress/
// validateSSHPort entirely, and never sets a credential, so the VM is
// -- and will remain -- a "keyless VM" in every existing sense. Every
// recurring SSH scheduler (monitoring/packages/docker-over-ssh discovery
// and metrics) already excludes keyless VMs via its own
// ssh_key_credential_id IS NOT NULL filter, so nothing else needs to
// change for this VM to be correctly left alone by all of them. The
// only intended way to reach it is the push-based VM Agent (see
// VMAgentInstallService/VMAgentHandler.ManualInstall), never SSH.
func (s *VMService) CreateAgentOnly(ctx context.Context, in CreateAgentOnlyInput) (uuid.UUID, error) {
	name, err := validateName("VM name", in.Name)
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := s.store.GetWorkspaceByID(ctx, in.WorkspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, fmt.Errorf("%w: workspace", ErrNotFound)
		}
		return uuid.Nil, fmt.Errorf("load workspace: %w", err)
	}

	var resourceID uuid.UUID
	err = s.store.WithTx(ctx, func(q *generated.Queries) error {
		resource, err := q.CreateResource(ctx, generated.CreateResourceParams{
			WorkspaceID:  in.WorkspaceID,
			Name:         name,
			ResourceType: "VM",
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: a resource named %q already exists", ErrDuplicateName, name)
			}
			return fmt.Errorf("create resource: %w", err)
		}

		if _, err := q.CreateVM(ctx, generated.CreateVMParams{
			ResourceID: resource.ID, Hostname: name, Address: "", SshPort: defaultSSHPort,
		}); err != nil {
			return fmt.Errorf("create vm: %w", err)
		}

		resourceID = resource.ID
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return resourceID, nil
}

// VMWithAccess bundles a VM's joined detail row with the calling user's
// effective permissions/source on it.
type VMWithAccess struct {
	Detail      generated.GetVMDetailByResourceIDRow
	Permissions []string
	Source      AccessSource
}

// Get loads a VM by resource ID, enforcing Step 3's authorization
// (CanAccessVM via EffectiveVMAccess) before returning anything. Returns
// ErrNotFound both when the VM genuinely doesn't exist and when the
// caller isn't authorized for it -- see docs/authorization.md's
// 404-not-403 policy; the handler is what turns ErrNotFound into a 404.
func (s *VMService) Get(ctx context.Context, user AuthenticatedUser, resourceID uuid.UUID) (VMWithAccess, error) {
	var permissions []string
	source := SourceAdmin

	if !user.IsAdmin() {
		access, err := s.authz.EffectiveVMAccess(ctx, user.ID, resourceID)
		if err != nil {
			return VMWithAccess{}, fmt.Errorf("check access: %w", err)
		}
		if access == nil {
			return VMWithAccess{}, ErrNotFound
		}
		permissions = access.Permissions
		source = access.Source
	} else {
		permissions = []string{PermVMView, PermVMConnect}
	}

	detail, err := s.store.GetVMDetailByResourceID(ctx, resourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return VMWithAccess{}, ErrNotFound
		}
		return VMWithAccess{}, fmt.Errorf("load vm: %w", err)
	}

	return VMWithAccess{Detail: detail, Permissions: permissions, Source: source}, nil
}

// List returns every VM user has access to (all of them for ADMIN, only
// authorized ones for MEMBER), each annotated with its effective
// permissions/source. Never queries "all VMs then filters in Go/frontend"
// for a MEMBER -- GetUserVMAccess already computes exactly the accessible
// set from the database (Step 4 spec §20).
func (s *VMService) List(ctx context.Context, user AuthenticatedUser) ([]VMWithAccess, error) {
	access, err := s.authz.GetUserVMAccess(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("load vm access: %w", err)
	}
	if len(access) == 0 {
		return []VMWithAccess{}, nil
	}

	ids := make([]uuid.UUID, 0, len(access))
	accessByID := map[uuid.UUID]VMAccess{}
	for _, a := range access {
		ids = append(ids, a.ResourceID)
		accessByID[a.ResourceID] = a
	}

	rows, err := s.store.ListVMDetailsByResourceIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("load vms: %w", err)
	}

	result := make([]VMWithAccess, 0, len(rows))
	for _, row := range rows {
		a := accessByID[row.ResourceID]
		result = append(result, VMWithAccess{Detail: vmDetailRowFromList(row), Permissions: a.Permissions, Source: a.Source})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Detail.Name < result[j].Detail.Name })
	return result, nil
}

// vmDetailRowFromList adapts ListVMDetailsByResourceIDsRow (sqlc gives it
// a distinct type from GetVMDetailByResourceIDRow despite the identical
// shape) into the common GetVMDetailByResourceIDRow so callers only deal
// with one type.
func vmDetailRowFromList(row generated.ListVMDetailsByResourceIDsRow) generated.GetVMDetailByResourceIDRow {
	return generated.GetVMDetailByResourceIDRow(row)
}

// Delete removes a VM resource from Infra Hub Center (Step 22) -- it never
// touches the actual remote server, only this application's own record of
// it. Reuses resources.deleted_at (SoftDeleteResource, sql/queries/
// resources.sql) exactly as already written -- every VM read/list/
// authorization query already filters on "resource_type = 'VM' AND
// deleted_at IS NULL" (GetVMResourceByID, GetVMDetailByResourceID,
// ListAllVMDetails, ...), so this single UPDATE makes the VM immediately
// invisible and inaccessible everywhere without touching a single other
// row: monitoring history, Docker inventory, alerts, recommendations,
// operations, and audit log entries referencing this resource_id all
// survive untouched (irreversible only in the sense that there is no UI
// path back -- the historical rows themselves are never destroyed).
// confirmationName must equal the VM's current resource name exactly.
func (s *VMService) Delete(ctx context.Context, resourceID uuid.UUID, confirmationName string) error {
	resource, err := s.store.GetVMResourceByID(ctx, resourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("load vm: %w", err)
	}
	if confirmationName != resource.Name {
		return ErrConfirmationMismatch
	}
	if err := s.store.SoftDeleteResource(ctx, resourceID); err != nil {
		return fmt.Errorf("delete vm: %w", err)
	}
	return nil
}

// VMAccessEntry is one user's effective access to a single VM, for the
// VM-centric "Authorized Members" view (Step 4 §23) -- the mirror image of
// AuthorizationService.GetUserVMAccess, which is user-centric.
type VMAccessEntry struct {
	UserID      uuid.UUID
	Name        string
	Email       string
	Permissions []string
	Source      AccessSource
}

// ListAccess returns every user with access to vmResourceID -- direct
// grants merged with the VM's group members (if it belongs to an active
// group), using the same merge rule as GetUserVMAccess: a user with both
// direct and group access is reported once, as DIRECT, with the union of
// permissions.
func (s *VMService) ListAccess(ctx context.Context, vmResourceID uuid.UUID) ([]VMAccessEntry, error) {
	resource, err := s.store.GetVMResourceByID(ctx, vmResourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("load vm: %w", err)
	}

	merged := map[uuid.UUID]*VMAccessEntry{}

	directRows, err := s.store.ListDirectAccessForResource(ctx, vmResourceID)
	if err != nil {
		return nil, fmt.Errorf("list direct access: %w", err)
	}
	for _, row := range directRows {
		entry, ok := merged[row.UserID]
		if !ok {
			entry = &VMAccessEntry{UserID: row.UserID, Name: row.Name, Email: row.Email, Source: SourceDirect}
			merged[row.UserID] = entry
		}
		entry.Permissions = appendUnique(entry.Permissions, row.PermissionName)
	}

	members, err := s.store.ListWorkspaceMembers(ctx, resource.WorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("list workspace members: %w", err)
	}
	for _, m := range members {
		entry, ok := merged[m.ID]
		if !ok {
			merged[m.ID] = &VMAccessEntry{
				UserID: m.ID, Name: m.Name, Email: m.Email,
				Permissions: []string{PermVMView, PermVMConnect}, Source: SourceWorkspace,
			}
			continue
		}
		entry.Permissions = appendUnique(entry.Permissions, PermVMView, PermVMConnect)
	}

	result := make([]VMAccessEntry, 0, len(merged))
	for _, entry := range merged {
		sort.Strings(entry.Permissions)
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Email < result[j].Email })
	return result, nil
}

// UpdateVMInput carries only the fields Step 4 allows changing after
// registration: identity/network configuration and lifecycle status.
// Discovery fields (os_name, cpu_cores, ...) are never settable through
// this path -- see UpdateVMFields' comment in sql/queries/vms.sql.
type UpdateVMInput struct {
	Name              *string
	Description       *string
	WorkspaceID       *uuid.UUID // nil = unchanged
	Status            *string
	Username          *string
	Address           *string
	SSHPort           *int32
	MonitoringEnabled *bool

	// SSHKeyCredentialID non-nil attaches/replaces the VM's named SSH
	// credential; ClearSSHKeyCredential detaches it (VM becomes keyless).
	// The two are mutually exclusive -- the handler enforces this via its
	// own three-state request parsing (absent/empty-string/uuid).
	SSHKeyCredentialID    *uuid.UUID
	ClearSSHKeyCredential bool
}

// Update applies a partial update to a VM's resource+vms rows atomically.
func (s *VMService) Update(ctx context.Context, resourceID uuid.UUID, in UpdateVMInput) (generated.GetVMDetailByResourceIDRow, error) {
	resource, err := s.store.GetVMResourceByID(ctx, resourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.GetVMDetailByResourceIDRow{}, ErrNotFound
		}
		return generated.GetVMDetailByResourceIDRow{}, fmt.Errorf("load vm: %w", err)
	}
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return generated.GetVMDetailByResourceIDRow{}, fmt.Errorf("load vm detail: %w", err)
	}

	name := resource.Name
	if in.Name != nil {
		trimmed, err := validateName("VM name", *in.Name)
		if err != nil {
			return generated.GetVMDetailByResourceIDRow{}, err
		}
		name = trimmed
	}
	description := pgutil.TextOrEmpty(resource.Description)
	if in.Description != nil {
		description = *in.Description
	}
	workspaceID := resource.WorkspaceID
	if in.WorkspaceID != nil {
		if _, err := s.store.GetWorkspaceByID(ctx, *in.WorkspaceID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return generated.GetVMDetailByResourceIDRow{}, fmt.Errorf("%w: workspace", ErrNotFound)
			}
			return generated.GetVMDetailByResourceIDRow{}, fmt.Errorf("load workspace: %w", err)
		}
		workspaceID = *in.WorkspaceID
	}
	status := resource.Status
	if in.Status != nil {
		status = *in.Status
	}
	monitoringEnabled := resource.MonitoringEnabled
	if in.MonitoringEnabled != nil {
		monitoringEnabled = *in.MonitoringEnabled
	}

	username := pgutil.TextOrEmpty(vm.Username)
	if in.Username != nil {
		username = *in.Username
	}
	address := vm.Address
	if in.Address != nil {
		addr, err := validateAddress(*in.Address)
		if err != nil {
			return generated.GetVMDetailByResourceIDRow{}, err
		}
		address = addr
	}
	sshPort := vm.SshPort
	if in.SSHPort != nil {
		if err := validateSSHPort(*in.SSHPort); err != nil {
			return generated.GetVMDetailByResourceIDRow{}, err
		}
		sshPort = *in.SSHPort
	}

	sshKeyCredentialID := vm.SshKeyCredentialID
	switch {
	case in.ClearSSHKeyCredential:
		sshKeyCredentialID = pgtype.UUID{}
	case in.SSHKeyCredentialID != nil:
		cred, err := s.store.GetSSHKeyCredentialByID(ctx, *in.SSHKeyCredentialID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return generated.GetVMDetailByResourceIDRow{}, fmt.Errorf("%w: ssh_key_credential_id", ErrNotFound)
			}
			return generated.GetVMDetailByResourceIDRow{}, fmt.Errorf("load ssh key credential: %w", err)
		}
		if cred.WorkspaceID != workspaceID {
			return generated.GetVMDetailByResourceIDRow{}, fmt.Errorf("%w: ssh key credential belongs to a different workspace", ErrValidation)
		}
		sshKeyCredentialID = pgutil.NullUUID(in.SSHKeyCredentialID)
	case in.WorkspaceID != nil && sshKeyCredentialID.Valid:
		// Workspace is moving and this request isn't touching the
		// credential -- if the currently-attached credential doesn't
		// belong to the new workspace, silently leaving the cross-
		// workspace reference in place would be worse than asking the
		// admin to resolve it explicitly.
		existingID := pgutil.UUID(sshKeyCredentialID)
		cred, err := s.store.GetSSHKeyCredentialByID(ctx, existingID)
		if err != nil {
			return generated.GetVMDetailByResourceIDRow{}, fmt.Errorf("load ssh key credential: %w", err)
		}
		if cred.WorkspaceID != workspaceID {
			return generated.GetVMDetailByResourceIDRow{}, fmt.Errorf("%w: moving this VM to a different workspace requires detaching or reattaching its SSH key credential", ErrValidation)
		}
	}

	err = s.store.WithTx(ctx, func(q *generated.Queries) error {
		if _, err := q.UpdateResource(ctx, generated.UpdateResourceParams{
			ID: resourceID, Name: name, Description: pgutil.Text(description), WorkspaceID: workspaceID, Status: status,
			MonitoringEnabled: monitoringEnabled,
		}); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: a resource named %q already exists", ErrDuplicateName, name)
			}
			return fmt.Errorf("update resource: %w", err)
		}
		if _, err := q.UpdateVMFields(ctx, generated.UpdateVMFieldsParams{
			ID: vm.ID, Hostname: vm.Hostname, Username: pgutil.Text(username), Address: address, SshPort: sshPort,
			SshKeyCredentialID: sshKeyCredentialID,
		}); err != nil {
			return fmt.Errorf("update vm: %w", err)
		}
		if in.ClearSSHKeyCredential {
			// Detaching leaves the VM with no way to connect, so any
			// previously-recorded connection state (e.g. a stale FAILED
			// from before the key was removed) no longer means anything --
			// reset it exactly like a never-configured VM.
			if _, err := q.UpdateVMConnectionStatus(ctx, generated.UpdateVMConnectionStatusParams{
				ID: vm.ID, ConnectionStatus: "NOT_CONFIGURED", LastConnectionError: pgtype.Text{},
			}); err != nil {
				return fmt.Errorf("reset connection status: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return generated.GetVMDetailByResourceIDRow{}, err
	}

	return s.store.GetVMDetailByResourceID(ctx, resourceID)
}
