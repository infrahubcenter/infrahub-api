package services

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
)

// AccessSource identifies why a user has access to a VM.
type AccessSource string

const (
	SourceAdmin     AccessSource = "ADMIN"
	SourceDirect    AccessSource = "DIRECT"
	SourceWorkspace AccessSource = "WORKSPACE"
)

// VMAccess is one VM's effective, merged access for a user.
type VMAccess struct {
	ResourceID  uuid.UUID
	Permissions []string
	Source      AccessSource
}

// AuthorizationService implements the deny-by-default VM authorization
// model described in docs/database-architecture.md: ADMIN role, then direct
// resource_permissions, then workspace_members-derived access, else deny.
type AuthorizationService struct {
	q generated.Querier
}

// NewAuthorizationService creates an AuthorizationService backed by q.
func NewAuthorizationService(q generated.Querier) *AuthorizationService {
	return &AuthorizationService{q: q}
}

// CanAccessVM reports whether user has permission on the VM identified by
// vmResourceID (a resources.id row with resource_type = 'VM'). It always
// defaults to deny: a VM that doesn't exist, isn't a VM, or is soft-deleted
// yields false with no error, exactly like one the user has no grant for --
// callers must not use the error return to distinguish "not found" from
// "not authorized" (see docs: that distinction is a 404 vs 403 choice made
// by the handler, not by this service).
func (s *AuthorizationService) CanAccessVM(ctx context.Context, user AuthenticatedUser, vmResourceID uuid.UUID, permission string) (bool, error) {
	if user.IsAdmin() {
		return true, nil
	}

	access, err := s.EffectiveVMAccess(ctx, user.ID, vmResourceID)
	if err != nil {
		return false, err
	}
	if access == nil {
		return false, nil
	}

	for _, p := range access.Permissions {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}

// CanAccessVMAny is CanAccessVM but true if the user holds ANY of
// permissions -- used by the Metrics-and-Logs and Updates trees, each
// reachable either via the broader vm.view or their own narrower
// vm.metrics/vm.updates grant (see identity.go's doc comment on those).
func (s *AuthorizationService) CanAccessVMAny(ctx context.Context, user AuthenticatedUser, vmResourceID uuid.UUID, permissions ...string) (bool, error) {
	if user.IsAdmin() {
		return true, nil
	}

	access, err := s.EffectiveVMAccess(ctx, user.ID, vmResourceID)
	if err != nil {
		return false, err
	}
	if access == nil {
		return false, nil
	}

	for _, p := range access.Permissions {
		for _, want := range permissions {
			if p == want {
				return true, nil
			}
		}
	}
	return false, nil
}

// CanAccessDockerFeature reports whether user may use the top-level Docker
// Monitoring/Logs section for resourceID (a VM or a standalone
// DOCKER_HOST resource) under permission (PermDockerMonitor or
// PermDockerLogs). Deliberately independent of CanAccessVM/vm.view --
// this checks docker_access_grants (Workspace-scoped, granted via
// DockerAccessService), never resource_permissions or workspace
// membership, per the "a separate access model" decision. Admin always
// bypasses, matching every other CanAccess* method.
func (s *AuthorizationService) CanAccessDockerFeature(ctx context.Context, user AuthenticatedUser, resourceID uuid.UUID, permission string) (bool, error) {
	if user.IsAdmin() {
		return true, nil
	}

	resource, err := resolveDockerFeatureResource(ctx, s.q, resourceID, permission)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if resource.Status == "DISABLED" {
		return false, nil
	}

	allowed, err := s.q.CheckDockerAccessGrant(ctx, generated.CheckDockerAccessGrantParams{
		UserID: user.ID, Permission: permission,
		WorkspaceID: pgutil.NullUUID(&resource.WorkspaceID), ResourceID: pgutil.NullUUID(&resourceID),
	})
	if err != nil {
		return false, fmt.Errorf("check docker access grant: %w", err)
	}
	if allowed {
		return true, nil
	}
	return s.checkMonitoringAccessGrantViaDashboard(ctx, user, resourceID, permission)
}

// checkMonitoringAccessGrantViaDashboard is CheckDockerAccessGrant's
// missing other half, shared by CanAccessDockerFeature/CanAccessK8sFeature
// -- see CheckMonitoringAccessGrantViaDashboard's own doc comment for why
// a FOLDER/DASHBOARD-scoped grant needs this second, resource-side check.
func (s *AuthorizationService) checkMonitoringAccessGrantViaDashboard(ctx context.Context, user AuthenticatedUser, resourceID uuid.UUID, permission string) (bool, error) {
	feature := monitoringFeatureForPermission(permission)
	if feature == "" {
		return false, nil
	}
	allowed, err := s.q.CheckMonitoringAccessGrantViaDashboard(ctx, generated.CheckMonitoringAccessGrantViaDashboardParams{
		UserID: user.ID, ResourceID: resourceID, Feature: feature, Permission: permission,
	})
	if err != nil {
		return false, fmt.Errorf("check monitoring access grant via dashboard: %w", err)
	}
	return allowed, nil
}

// AccessibleVMResourceIDsForDockerFeature returns the VM resource IDs user
// may see in the Docker section for permission -- Admin gets nil (the
// established NULL-means-unrestricted convention every cross-resource
// list query in this app already uses), a Member gets their dynamically
// computed set (possibly empty, never nil, so "no access" never
// accidentally reads as "unrestricted").
func (s *AuthorizationService) AccessibleVMResourceIDsForDockerFeature(ctx context.Context, user AuthenticatedUser, permission string) ([]uuid.UUID, error) {
	if user.IsAdmin() {
		return nil, nil
	}
	ids, err := s.q.ListVMResourceIDsForDockerPermission(ctx, generated.ListVMResourceIDsForDockerPermissionParams{
		UserID: user.ID, Permission: permission,
	})
	if err != nil {
		return nil, fmt.Errorf("list accessible vm resource ids: %w", err)
	}
	if ids == nil {
		ids = []uuid.UUID{}
	}
	return ids, nil
}

// AccessibleMonitoringFolderIDsForFeature returns the monitoring_folders
// IDs user holds a FOLDER-scoped docker_access_grants row on for
// permission -- Admin gets nil (unrestricted), a Member gets their
// possibly-empty, never-nil set. Unlike
// AccessibleVMResourceIDsForDockerFeature there is no workspace-wide
// fan-out to compute: a FOLDER grant only ever names the one folder it
// was created for.
func (s *AuthorizationService) AccessibleMonitoringFolderIDsForFeature(ctx context.Context, user AuthenticatedUser, permission string) ([]uuid.UUID, error) {
	if user.IsAdmin() {
		return nil, nil
	}
	rows, err := s.q.ListMonitoringFolderIDsForAccessGrant(ctx, generated.ListMonitoringFolderIDsForAccessGrantParams{
		UserID: user.ID, Permission: permission,
	})
	if err != nil {
		return nil, fmt.Errorf("list accessible monitoring folder ids: %w", err)
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, id := range rows {
		if id.Valid {
			ids = append(ids, pgutil.UUID(id))
		}
	}
	return ids, nil
}

// AccessibleMonitoringDashboardIDsForFeature is
// AccessibleMonitoringFolderIDsForFeature's exact counterpart for
// DASHBOARD-scoped grants.
func (s *AuthorizationService) AccessibleMonitoringDashboardIDsForFeature(ctx context.Context, user AuthenticatedUser, permission string) ([]uuid.UUID, error) {
	if user.IsAdmin() {
		return nil, nil
	}
	rows, err := s.q.ListMonitoringDashboardIDsForAccessGrant(ctx, generated.ListMonitoringDashboardIDsForAccessGrantParams{
		UserID: user.ID, Permission: permission,
	})
	if err != nil {
		return nil, fmt.Errorf("list accessible monitoring dashboard ids: %w", err)
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, id := range rows {
		if id.Valid {
			ids = append(ids, pgutil.UUID(id))
		}
	}
	return ids, nil
}

// CanAccessK8sFeature is CanAccessDockerFeature's exact counterpart for
// the K8s Monitoring/Logs section -- same docker_access_grants table,
// same Workspace scoping, just resolving a K8S_CLUSTER resource instead
// of a VM one.
func (s *AuthorizationService) CanAccessK8sFeature(ctx context.Context, user AuthenticatedUser, clusterResourceID uuid.UUID, permission string) (bool, error) {
	if user.IsAdmin() {
		return true, nil
	}

	resource, err := s.q.GetK8sClusterResourceByID(ctx, clusterResourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("load k8s cluster resource: %w", err)
	}
	if resource.Status == "DISABLED" {
		return false, nil
	}

	allowed, err := s.q.CheckDockerAccessGrant(ctx, generated.CheckDockerAccessGrantParams{
		UserID: user.ID, Permission: permission,
		WorkspaceID: pgutil.NullUUID(&resource.WorkspaceID), ResourceID: pgutil.NullUUID(&clusterResourceID),
	})
	if err != nil {
		return false, fmt.Errorf("check k8s access grant: %w", err)
	}
	if allowed {
		return true, nil
	}
	return s.checkMonitoringAccessGrantViaDashboard(ctx, user, clusterResourceID, permission)
}

// AccessibleK8sClusterResourceIDsForFeature is
// AccessibleVMResourceIDsForDockerFeature's exact counterpart for K8s
// clusters.
func (s *AuthorizationService) AccessibleK8sClusterResourceIDsForFeature(ctx context.Context, user AuthenticatedUser, permission string) ([]uuid.UUID, error) {
	if user.IsAdmin() {
		return nil, nil
	}
	ids, err := s.q.ListK8sClusterResourceIDsForAccessGrant(ctx, generated.ListK8sClusterResourceIDsForAccessGrantParams{
		UserID: user.ID, Permission: permission,
	})
	if err != nil {
		return nil, fmt.Errorf("list accessible k8s cluster resource ids: %w", err)
	}
	if ids == nil {
		ids = []uuid.UUID{}
	}
	return ids, nil
}

// EffectiveVMAccess computes one user's merged access to one VM, or nil if
// the VM doesn't exist (as a non-deleted VM resource), is deactivated
// (status DISABLED -- a deactivated VM must not be newly accessible even
// with an existing grant, Step 4 spec §33), or the user has no grant on
// it. Direct resource_permissions and group-derived access are unioned
// (Step 3 spec §19); when both exist, the reported Source is DIRECT since
// that reflects the more specific, explicitly intentional admin grant.
// Exported for reuse by VMService (which needs the same computation to
// annotate a single VM's permissions/source in its detail response).
func (s *AuthorizationService) EffectiveVMAccess(ctx context.Context, userID, vmResourceID uuid.UUID) (*VMAccess, error) {
	resource, err := s.q.GetVMResourceByID(ctx, vmResourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("load vm resource: %w", err)
	}
	if resource.Status == "DISABLED" {
		return nil, nil
	}

	permSet := map[string]struct{}{}
	source := AccessSource("")

	directPerms, err := s.q.ListDirectPermissionsForUserResource(ctx, generated.ListDirectPermissionsForUserResourceParams{
		UserID:     userID,
		ResourceID: vmResourceID,
	})
	if err != nil {
		return nil, fmt.Errorf("list direct permissions: %w", err)
	}
	if len(directPerms) > 0 {
		for _, p := range directPerms {
			permSet[p] = struct{}{}
		}
		source = SourceDirect
	}

	isMember, err := s.q.IsUserWorkspaceMember(ctx, generated.IsUserWorkspaceMemberParams{
		WorkspaceID: resource.WorkspaceID,
		UserID:      userID,
	})
	if err != nil {
		return nil, fmt.Errorf("check workspace membership: %w", err)
	}
	if isMember {
		// Workspace membership grants full VM access (view + connect); it
		// is a coarse "you're on this team" grant, unlike direct
		// access which lets an admin be more selective per VM.
		permSet[PermVMView] = struct{}{}
		permSet[PermVMConnect] = struct{}{}
		if source == "" {
			source = SourceWorkspace
		}
	}

	if len(permSet) == 0 {
		return nil, nil
	}

	return &VMAccess{
		ResourceID:  vmResourceID,
		Permissions: sortedKeys(permSet),
		Source:      source,
	}, nil
}

// GetUserVMAccess returns every VM user has access to, with merged
// permissions and a Source per VM. For an ADMIN it returns every VM in the
// system with Source ADMIN and full permissions -- this is what backs both
// GET /api/vms (admin) and GET /api/my-access (any role).
func (s *AuthorizationService) GetUserVMAccess(ctx context.Context, user AuthenticatedUser) ([]VMAccess, error) {
	if user.IsAdmin() {
		vms, err := s.q.ListAllVMDetails(ctx)
		if err != nil {
			return nil, fmt.Errorf("list all vms: %w", err)
		}
		access := make([]VMAccess, 0, len(vms))
		for _, vm := range vms {
			access = append(access, VMAccess{
				ResourceID:  vm.ResourceID,
				Permissions: []string{PermVMView, PermVMConnect},
				Source:      SourceAdmin,
			})
		}
		return access, nil
	}

	merged := map[uuid.UUID]*VMAccess{}

	directRows, err := s.q.ListDirectVMPermissionsForUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("list direct vm permissions: %w", err)
	}
	for _, row := range directRows {
		entry, ok := merged[row.ResourceID]
		if !ok {
			entry = &VMAccess{ResourceID: row.ResourceID, Source: SourceDirect}
			merged[row.ResourceID] = entry
		}
		entry.Permissions = appendUnique(entry.Permissions, row.PermissionName)
	}

	workspaceRows, err := s.q.ListVMResourceIDsForUserWorkspaces(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("list workspace vm access: %w", err)
	}
	for _, row := range workspaceRows {
		entry, ok := merged[row.ResourceID]
		if !ok {
			merged[row.ResourceID] = &VMAccess{
				ResourceID:  row.ResourceID,
				Permissions: []string{PermVMView, PermVMConnect},
				Source:      SourceWorkspace,
			}
			continue
		}
		entry.Permissions = appendUnique(entry.Permissions, PermVMView, PermVMConnect)
		// entry.Source stays DIRECT: a direct grant already exists for
		// this VM, and DIRECT is the more specific, intentional grant.
	}

	result := make([]VMAccess, 0, len(merged))
	for _, entry := range merged {
		sort.Strings(entry.Permissions)
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceID.String() < result[j].ResourceID.String() })
	return result, nil
}

// DatabaseAccess is one database's effective, merged access for a user --
// mirrors VMAccess exactly, for resource_type = 'DATABASE' resources.
type DatabaseAccess struct {
	ResourceID  uuid.UUID
	Permissions []string
	Source      AccessSource
}

// CanAccessDatabase reports whether user has permission on the database
// identified by databaseResourceID (a resources.id row with
// resource_type = 'DATABASE'). Always defaults to deny, exactly like
// CanAccessVM -- a database that doesn't exist, isn't a database, or is
// soft-deleted yields false with no error.
func (s *AuthorizationService) CanAccessDatabase(ctx context.Context, user AuthenticatedUser, databaseResourceID uuid.UUID, permission string) (bool, error) {
	if user.IsAdmin() {
		return true, nil
	}
	access, err := s.EffectiveDatabaseAccess(ctx, user.ID, databaseResourceID)
	if err != nil {
		return false, err
	}
	if access == nil {
		return false, nil
	}
	for _, p := range access.Permissions {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}

// EffectiveDatabaseAccess computes one user's merged access to one
// database -- mirrors EffectiveVMAccess exactly. Group membership grants
// only database.view + database.performance (spec §53's stated Member
// default) -- never database.browser/logs/query_details, which must be
// granted directly per spec §54-56.
func (s *AuthorizationService) EffectiveDatabaseAccess(ctx context.Context, userID, databaseResourceID uuid.UUID) (*DatabaseAccess, error) {
	resource, err := s.q.GetDatabaseResourceByID(ctx, databaseResourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("load database resource: %w", err)
	}
	if resource.Status == "DISABLED" {
		return nil, nil
	}

	permSet := map[string]struct{}{}
	source := AccessSource("")

	directPerms, err := s.q.ListDirectPermissionsForUserResource(ctx, generated.ListDirectPermissionsForUserResourceParams{
		UserID:     userID,
		ResourceID: databaseResourceID,
	})
	if err != nil {
		return nil, fmt.Errorf("list direct permissions: %w", err)
	}
	if len(directPerms) > 0 {
		for _, p := range directPerms {
			permSet[p] = struct{}{}
		}
		source = SourceDirect
	}

	isMember, err := s.q.IsUserWorkspaceMember(ctx, generated.IsUserWorkspaceMemberParams{
		WorkspaceID: resource.WorkspaceID,
		UserID:      userID,
	})
	if err != nil {
		return nil, fmt.Errorf("check workspace membership: %w", err)
	}
	if isMember {
		permSet[PermDatabaseView] = struct{}{}
		permSet[PermDatabasePerformance] = struct{}{}
		if source == "" {
			source = SourceWorkspace
		}
	}

	if len(permSet) == 0 {
		return nil, nil
	}
	return &DatabaseAccess{ResourceID: databaseResourceID, Permissions: sortedKeys(permSet), Source: source}, nil
}

// GetUserDatabaseAccess returns every database the user has access to,
// with merged permissions and a Source per database -- mirrors
// GetUserVMAccess exactly. For an ADMIN, the caller passes a nil
// resource_ids slice to the underlying dashboard query instead of
// enumerating every database here (unlike VMs, the database listing
// query already natively supports "NULL = unrestricted").
func (s *AuthorizationService) GetUserDatabaseAccess(ctx context.Context, user AuthenticatedUser) ([]DatabaseAccess, error) {
	merged := map[uuid.UUID]*DatabaseAccess{}

	directRows, err := s.q.ListDirectDatabasePermissionsForUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("list direct database permissions: %w", err)
	}
	for _, row := range directRows {
		entry, ok := merged[row.ResourceID]
		if !ok {
			entry = &DatabaseAccess{ResourceID: row.ResourceID, Source: SourceDirect}
			merged[row.ResourceID] = entry
		}
		entry.Permissions = appendUnique(entry.Permissions, row.PermissionName)
	}

	workspaceRows, err := s.q.ListDatabaseResourceIDsForUserWorkspaces(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("list workspace database access: %w", err)
	}
	for _, row := range workspaceRows {
		entry, ok := merged[row.ResourceID]
		if !ok {
			merged[row.ResourceID] = &DatabaseAccess{
				ResourceID: row.ResourceID, Permissions: []string{PermDatabaseView, PermDatabasePerformance}, Source: SourceWorkspace,
			}
			continue
		}
		entry.Permissions = appendUnique(entry.Permissions, PermDatabaseView, PermDatabasePerformance)
	}

	result := make([]DatabaseAccess, 0, len(merged))
	for _, entry := range merged {
		sort.Strings(entry.Permissions)
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceID.String() < result[j].ResourceID.String() })
	return result, nil
}

// ObjectStorageAccess is one object storage's effective, merged access
// for a user -- mirrors DatabaseAccess exactly, for resource_type =
// 'OBJECT_STORAGE' resources.
type ObjectStorageAccess struct {
	ResourceID  uuid.UUID
	Permissions []string
	Source      AccessSource
}

// CanAccessObjectStorage reports whether user has permission on the
// object storage identified by objectStorageResourceID (a resources.id
// row with resource_type = 'OBJECT_STORAGE'). Always defaults to deny,
// exactly like CanAccessDatabase -- an object storage that doesn't exist,
// isn't an object storage, or is soft-deleted yields false with no error.
func (s *AuthorizationService) CanAccessObjectStorage(ctx context.Context, user AuthenticatedUser, objectStorageResourceID uuid.UUID, permission string) (bool, error) {
	if user.IsAdmin() {
		return true, nil
	}
	access, err := s.EffectiveObjectStorageAccess(ctx, user.ID, objectStorageResourceID)
	if err != nil {
		return false, err
	}
	if access == nil {
		return false, nil
	}
	for _, p := range access.Permissions {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}

// EffectiveObjectStorageAccess computes one user's merged access to one
// object storage -- mirrors EffectiveDatabaseAccess exactly. Group
// membership grants only object_storage.view + object_storage.monitor
// (Step 17's stated Member default) -- never object_storage.browser/
// download, which must be granted directly.
func (s *AuthorizationService) EffectiveObjectStorageAccess(ctx context.Context, userID, objectStorageResourceID uuid.UUID) (*ObjectStorageAccess, error) {
	resource, err := s.q.GetObjectStorageResourceByID(ctx, objectStorageResourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("load object storage resource: %w", err)
	}
	if resource.Status == "DISABLED" {
		return nil, nil
	}

	permSet := map[string]struct{}{}
	source := AccessSource("")

	directPerms, err := s.q.ListDirectPermissionsForUserResource(ctx, generated.ListDirectPermissionsForUserResourceParams{
		UserID:     userID,
		ResourceID: objectStorageResourceID,
	})
	if err != nil {
		return nil, fmt.Errorf("list direct permissions: %w", err)
	}
	if len(directPerms) > 0 {
		for _, p := range directPerms {
			permSet[p] = struct{}{}
		}
		source = SourceDirect
	}

	isMember, err := s.q.IsUserWorkspaceMember(ctx, generated.IsUserWorkspaceMemberParams{
		WorkspaceID: resource.WorkspaceID,
		UserID:      userID,
	})
	if err != nil {
		return nil, fmt.Errorf("check workspace membership: %w", err)
	}
	if isMember {
		permSet[PermObjectStorageView] = struct{}{}
		permSet[PermObjectStorageMonitor] = struct{}{}
		if source == "" {
			source = SourceWorkspace
		}
	}

	if len(permSet) == 0 {
		return nil, nil
	}
	return &ObjectStorageAccess{ResourceID: objectStorageResourceID, Permissions: sortedKeys(permSet), Source: source}, nil
}

// GetUserObjectStorageAccess returns every object storage the user has
// access to, with merged permissions and a Source per object storage --
// mirrors GetUserDatabaseAccess exactly.
func (s *AuthorizationService) GetUserObjectStorageAccess(ctx context.Context, user AuthenticatedUser) ([]ObjectStorageAccess, error) {
	merged := map[uuid.UUID]*ObjectStorageAccess{}

	directRows, err := s.q.ListDirectObjectStoragePermissionsForUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("list direct object storage permissions: %w", err)
	}
	for _, row := range directRows {
		entry, ok := merged[row.ResourceID]
		if !ok {
			entry = &ObjectStorageAccess{ResourceID: row.ResourceID, Source: SourceDirect}
			merged[row.ResourceID] = entry
		}
		entry.Permissions = appendUnique(entry.Permissions, row.PermissionName)
	}

	workspaceRows, err := s.q.ListObjectStorageResourceIDsForUserWorkspaces(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("list workspace object storage access: %w", err)
	}
	for _, row := range workspaceRows {
		entry, ok := merged[row.ResourceID]
		if !ok {
			merged[row.ResourceID] = &ObjectStorageAccess{
				ResourceID: row.ResourceID, Permissions: []string{PermObjectStorageView, PermObjectStorageMonitor}, Source: SourceWorkspace,
			}
			continue
		}
		entry.Permissions = appendUnique(entry.Permissions, PermObjectStorageView, PermObjectStorageMonitor)
	}

	result := make([]ObjectStorageAccess, 0, len(merged))
	for _, entry := range merged {
		sort.Strings(entry.Permissions)
		result = append(result, *entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ResourceID.String() < result[j].ResourceID.String() })
	return result, nil
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func appendUnique(list []string, values ...string) []string {
	for _, v := range values {
		found := false
		for _, existing := range list {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			list = append(list, v)
		}
	}
	return list
}
