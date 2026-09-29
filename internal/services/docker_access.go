package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// validDockerPermissions also covers the K8s permissions --
// docker_access_grants is deliberately shared by both feature areas (see
// migration 032's widened permission CHECK constraint); which area a
// grant applies to is carried purely by the permission string itself.
var validDockerPermissions = map[string]bool{
	PermDockerMonitor: true, PermDockerLogs: true,
	PermK8sMonitor: true, PermK8sLogs: true,
}

// DockerAccessService manages docker_access_grants: Admin-only,
// Workspace-scoped, view-only grants for the top-level Docker and
// Kubernetes Monitoring/Logs sections. See
// migrations/031_docker_access_grants.sql, migrations/032_k8s_clusters.sql,
// migrations/043_workspaces.sql, and
// AuthorizationService.CanAccessDockerFeature/CanAccessK8sFeature, which
// are what actually enforce these grants on every request -- this service
// only manages the grant rows themselves. Auditing happens at the handler
// layer (LogFrom), matching every other admin grant/delete action in this
// codebase (it captures IP/UserAgent from the request, which a
// service-level Log call cannot) -- Grant/Revoke return what the handler
// needs for that instead of auditing internally.
type DockerAccessService struct {
	store      *repository.Store
	workspaces *WorkspaceService
}

// NewDockerAccessService creates a DockerAccessService. workspaces is
// reused (not duplicated) purely to validate a grant's workspace actually
// exists before creating it -- WorkspaceService.Get already does exactly
// that lookup and already returns ErrNotFound the same way every other
// service in this package does.
func NewDockerAccessService(store *repository.Store, workspaces *WorkspaceService) *DockerAccessService {
	return &DockerAccessService{store: store, workspaces: workspaces}
}

// dockerPermissionResourceTypes maps a permission to the resource_type(s)
// a RESOURCE-scoped grant for it may target -- docker.monitor/docker.logs
// make sense against either a VM (a docker daemon reached over SSH/its
// own installed agent) or a standalone DOCKER_HOST (agent-only, no VM at
// all); k8s.monitor/k8s.logs only against a K8S_CLUSTER.
var dockerPermissionResourceTypes = map[string]map[string]bool{
	PermDockerMonitor: {"VM": true, "DOCKER_HOST": true},
	PermDockerLogs:    {"VM": true, "DOCKER_HOST": true},
	PermK8sMonitor:    {"K8S_CLUSTER": true},
	PermK8sLogs:       {"K8S_CLUSTER": true},
}

// GrantInput describes a single docker_access_grants row to create --
// exactly one of WorkspaceID, ResourceID, MonitoringFolderID,
// MonitoringDashboardID must be set.
type GrantInput struct {
	UserID                uuid.UUID
	GrantedBy             uuid.UUID
	Permission            string
	WorkspaceID           *uuid.UUID
	ResourceID            *uuid.UUID
	MonitoringFolderID    *uuid.UUID
	MonitoringDashboardID *uuid.UUID
}

// Grant creates a docker.monitor/docker.logs/k8s.monitor/k8s.logs grant,
// scoped Workspace-wide, to one specific VM/K8s cluster resource, to one
// specific Monitoring Folder (every Dashboard filed under it), or to one
// specific Dashboard -- exactly one of in's four scope fields must be set.
// Returns the granted scope's display name for the caller's audit
// metadata. Idempotent: granting the same (user, scope, permission)
// combination twice is a quiet no-op (the unique constraint + the query's
// ON CONFLICT DO NOTHING), never a duplicate row or an error.
func (s *DockerAccessService) Grant(ctx context.Context, in GrantInput) (scopeName string, err error) {
	if !validDockerPermissions[in.Permission] {
		return "", fmt.Errorf("%w: unknown docker permission %q", ErrValidation, in.Permission)
	}
	set := 0
	for _, p := range []*uuid.UUID{in.WorkspaceID, in.ResourceID, in.MonitoringFolderID, in.MonitoringDashboardID} {
		if p != nil {
			set++
		}
	}
	if set != 1 {
		return "", fmt.Errorf("%w: exactly one of workspace_id, resource_id, folder_id, dashboard_id is required", ErrValidation)
	}

	switch {
	case in.ResourceID != nil:
		resource, err := s.store.GetResourceByID(ctx, *in.ResourceID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", ErrNotFound
			}
			return "", fmt.Errorf("load resource: %w", err)
		}
		if !dockerPermissionResourceTypes[in.Permission][resource.ResourceType] {
			return "", fmt.Errorf("%w: %s permission does not support a %s resource", ErrValidation, in.Permission, resource.ResourceType)
		}
		if _, err := s.store.CreateResourceDockerAccessGrant(ctx, generated.CreateResourceDockerAccessGrantParams{
			UserID: in.UserID, ResourceID: pgutil.NullUUID(in.ResourceID), Permission: in.Permission, GrantedBy: pgutil.NullUUID(&in.GrantedBy),
		}); err != nil && !errors.Is(err, pgx.ErrNoRows) { // ON CONFLICT DO NOTHING -- grant already existed, not an error
			return "", fmt.Errorf("create resource docker access grant: %w", err)
		}
		return resource.Name, nil

	case in.MonitoringFolderID != nil:
		folder, err := s.store.GetMonitoringFolderByID(ctx, *in.MonitoringFolderID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", ErrNotFound
			}
			return "", fmt.Errorf("load monitoring folder: %w", err)
		}
		if monitoringFeaturePermission(folder.Feature) != in.Permission {
			return "", fmt.Errorf("%w: %s permission does not support a %s folder", ErrValidation, in.Permission, folder.Feature)
		}
		if _, err := s.store.CreateFolderDockerAccessGrant(ctx, generated.CreateFolderDockerAccessGrantParams{
			UserID: in.UserID, MonitoringFolderID: pgutil.NullUUID(in.MonitoringFolderID), Permission: in.Permission, GrantedBy: pgutil.NullUUID(&in.GrantedBy),
		}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("create folder docker access grant: %w", err)
		}
		return folder.Name, nil

	case in.MonitoringDashboardID != nil:
		dashboard, err := s.store.GetMonitoringDashboardByID(ctx, *in.MonitoringDashboardID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", ErrNotFound
			}
			return "", fmt.Errorf("load monitoring dashboard: %w", err)
		}
		if monitoringFeaturePermission(dashboard.Feature) != in.Permission {
			return "", fmt.Errorf("%w: %s permission does not support a %s dashboard", ErrValidation, in.Permission, dashboard.Feature)
		}
		if _, err := s.store.CreateDashboardDockerAccessGrant(ctx, generated.CreateDashboardDockerAccessGrantParams{
			UserID: in.UserID, MonitoringDashboardID: pgutil.NullUUID(in.MonitoringDashboardID), Permission: in.Permission, GrantedBy: pgutil.NullUUID(&in.GrantedBy),
		}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("create dashboard docker access grant: %w", err)
		}
		return dashboard.Name, nil

	default: // in.WorkspaceID != nil
		workspace, err := s.workspaces.Get(ctx, *in.WorkspaceID)
		if err != nil {
			return "", err
		}
		if _, err := s.store.CreateDockerAccessGrant(ctx, generated.CreateDockerAccessGrantParams{
			UserID: in.UserID, WorkspaceID: pgutil.NullUUID(in.WorkspaceID), Permission: in.Permission, GrantedBy: pgutil.NullUUID(&in.GrantedBy),
		}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("create docker access grant: %w", err)
		}
		return workspace.Name, nil
	}
}

// resolveDockerFeatureResource loads resourceID as a plain resources row
// and confirms its resource_type is legal for permission per
// dockerPermissionResourceTypes -- the same check Grant applies before
// creating a resource-scoped grant, reused here so enforcement/dashboard-
// creation code never special-cases resource type on its own. Returns
// ErrNotFound if resourceID doesn't exist, is soft-deleted, or isn't a
// resource_type permission allows. q is generated.Querier (not
// *repository.Store) so it works from both AuthorizationService (which
// only holds a Querier) and *repository.Store callers.
func resolveDockerFeatureResource(ctx context.Context, q generated.Querier, resourceID uuid.UUID, permission string) (generated.Resource, error) {
	resource, err := q.GetResourceByID(ctx, resourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.Resource{}, ErrNotFound
		}
		return generated.Resource{}, fmt.Errorf("load resource: %w", err)
	}
	if !dockerPermissionResourceTypes[permission][resource.ResourceType] {
		return generated.Resource{}, ErrNotFound
	}
	return resource, nil
}

// Revoke deletes one grant by its own ID, returning the deleted row for
// the caller's audit metadata.
func (s *DockerAccessService) Revoke(ctx context.Context, grantID uuid.UUID) (generated.DockerAccessGrant, error) {
	grant, err := s.store.GetDockerAccessGrantByID(ctx, grantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.DockerAccessGrant{}, ErrNotFound
		}
		return generated.DockerAccessGrant{}, fmt.Errorf("load docker access grant: %w", err)
	}
	if err := s.store.DeleteDockerAccessGrant(ctx, grantID); err != nil {
		return generated.DockerAccessGrant{}, fmt.Errorf("delete docker access grant: %w", err)
	}
	return grant, nil
}
