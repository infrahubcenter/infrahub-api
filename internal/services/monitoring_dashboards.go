// Package services: monitoring_dashboards.go implements the new Folder >
// Dashboard model backing four independent trees -- Monitoring>Docker,
// Monitoring>Kubernetes, Logs>Docker, Logs>Kubernetes -- discriminated by
// `feature`. Replaces the retired dashboard_folders/dashboards (039/040,
// deleted), which bound one Dashboard to one VM/cluster with a single
// combined Monitoring/Logs/Alerts tab set. See
// migrations/042_monitoring_dashboards.sql for the full model/rationale.
//
// Unlike the old feature, a Monitoring dashboard and a Logs dashboard for
// the same VM/cluster are independent rows in independent trees, so
// CanView checks exactly one permission per feature (not "monitor OR
// logs qualifies" the way the old combined-tabs dashboard needed).
//
// Deliberately no new access-control table, same as before: a Dashboard
// is visible to whoever already holds the matching docker.monitor/
// docker.logs/k8s.monitor/k8s.logs grant on its Workspace via
// docker_access_grants (AuthorizationService).
package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

const (
	MonitoringFeatureDockerMonitoring = "DOCKER_MONITORING"
	MonitoringFeatureK8sMonitoring    = "K8S_MONITORING"
	MonitoringFeatureDockerLogs       = "DOCKER_LOGS"
	MonitoringFeatureK8sLogs          = "K8S_LOGS"
)

var validMonitoringFeatures = map[string]bool{
	MonitoringFeatureDockerMonitoring: true, MonitoringFeatureK8sMonitoring: true,
	MonitoringFeatureDockerLogs: true, MonitoringFeatureK8sLogs: true,
}

func monitoringFeatureIsDocker(feature string) bool {
	return feature == MonitoringFeatureDockerMonitoring || feature == MonitoringFeatureDockerLogs
}

func monitoringFeatureIsLogs(feature string) bool {
	return feature == MonitoringFeatureDockerLogs || feature == MonitoringFeatureK8sLogs
}

// monitoringFeaturePermission maps a feature to the exact single
// docker_access_grants permission that qualifies a Member to view it --
// unlike the old combined-tabs Dashboard, Monitoring and Logs are now
// separate trees, so exactly one permission applies per feature.
func monitoringFeaturePermission(feature string) string {
	switch feature {
	case MonitoringFeatureDockerMonitoring:
		return PermDockerMonitor
	case MonitoringFeatureDockerLogs:
		return PermDockerLogs
	case MonitoringFeatureK8sMonitoring:
		return PermK8sMonitor
	case MonitoringFeatureK8sLogs:
		return PermK8sLogs
	default:
		return ""
	}
}

// monitoringFeatureForPermission is monitoringFeaturePermission's exact
// inverse -- used by AuthorizationService.checkMonitoringAccessGrantViaDashboard,
// which starts from a permission (all it's given) and needs the one
// feature it maps to.
func monitoringFeatureForPermission(permission string) string {
	switch permission {
	case PermDockerMonitor:
		return MonitoringFeatureDockerMonitoring
	case PermDockerLogs:
		return MonitoringFeatureDockerLogs
	case PermK8sMonitor:
		return MonitoringFeatureK8sMonitoring
	case PermK8sLogs:
		return MonitoringFeatureK8sLogs
	default:
		return ""
	}
}

type MonitoringFolderService struct {
	store *repository.Store
}

func NewMonitoringFolderService(store *repository.Store) *MonitoringFolderService {
	return &MonitoringFolderService{store: store}
}

func (s *MonitoringFolderService) Create(ctx context.Context, feature string, workspaceID uuid.UUID, name string, createdBy uuid.UUID) (generated.MonitoringFolder, error) {
	if !validMonitoringFeatures[feature] {
		return generated.MonitoringFolder{}, fmt.Errorf("%w: invalid feature", ErrValidation)
	}
	if strings.TrimSpace(name) == "" {
		return generated.MonitoringFolder{}, fmt.Errorf("%w: name is required", ErrValidation)
	}
	folder, err := s.store.CreateMonitoringFolder(ctx, generated.CreateMonitoringFolderParams{
		Feature: feature, WorkspaceID: workspaceID, Name: name, CreatedBy: pgutil.NullUUID(&createdBy),
	})
	if err != nil && isUniqueViolation(err) {
		return generated.MonitoringFolder{}, ErrDuplicateName
	}
	return folder, err
}

func (s *MonitoringFolderService) Get(ctx context.Context, id uuid.UUID) (generated.MonitoringFolder, error) {
	folder, err := s.store.GetMonitoringFolderByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.MonitoringFolder{}, ErrNotFound
		}
		return generated.MonitoringFolder{}, err
	}
	return folder, nil
}

func (s *MonitoringFolderService) ListForWorkspace(ctx context.Context, feature string, workspaceID uuid.UUID) ([]generated.MonitoringFolder, error) {
	return s.store.ListMonitoringFoldersForWorkspace(ctx, generated.ListMonitoringFoldersForWorkspaceParams{
		Feature: feature, WorkspaceID: workspaceID,
	})
}

func (s *MonitoringFolderService) Rename(ctx context.Context, id uuid.UUID, name string) (generated.MonitoringFolder, error) {
	if strings.TrimSpace(name) == "" {
		return generated.MonitoringFolder{}, fmt.Errorf("%w: name is required", ErrValidation)
	}
	folder, err := s.store.UpdateMonitoringFolderName(ctx, generated.UpdateMonitoringFolderNameParams{ID: id, Name: name})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.MonitoringFolder{}, ErrNotFound
		}
		return generated.MonitoringFolder{}, err
	}
	return folder, nil
}

// Delete removes the folder and, via ON DELETE CASCADE, every Dashboard
// filed inside it -- the caller (handler) confirms this with the admin
// first when the folder isn't empty.
func (s *MonitoringFolderService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.store.DeleteMonitoringFolder(ctx, id)
}

// MonitoringDashboardWithBinding unifies the differently-named sqlc row
// types that all carry the same Dashboard + bound-resource-display
// fields, so handlers never need to branch on which query produced a
// result -- mirrors DashboardWithBinding's exact role for the old feature.
type MonitoringDashboardWithBinding struct {
	generated.MonitoringDashboard
	BoundResourceName   string
	BoundResourceType   string
	BoundResourceStatus string
	WorkspaceName       string
	FolderName          pgtype.Text
}

func monitoringDashboardFromGetRow(row generated.GetMonitoringDashboardWithBindingByIDRow) MonitoringDashboardWithBinding {
	return MonitoringDashboardWithBinding{
		MonitoringDashboard: generated.MonitoringDashboard{
			ID: row.ID, MonitoringFolderID: row.MonitoringFolderID, Feature: row.Feature, WorkspaceID: row.WorkspaceID,
			Name: row.Name, Description: row.Description, VmResourceID: row.VmResourceID, K8sClusterResourceID: row.K8sClusterResourceID,
			RefreshIntervalSeconds: row.RefreshIntervalSeconds,
			CreatedBy:              row.CreatedBy, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		},
		BoundResourceName: row.BoundResourceName, BoundResourceType: row.BoundResourceType, BoundResourceStatus: row.BoundResourceStatus,
		WorkspaceName: row.WorkspaceName, FolderName: row.FolderName,
	}
}

func monitoringDashboardFromFilteredRow(row generated.ListMonitoringDashboardsFilteredRow) MonitoringDashboardWithBinding {
	return MonitoringDashboardWithBinding{
		MonitoringDashboard: generated.MonitoringDashboard{
			ID: row.ID, MonitoringFolderID: row.MonitoringFolderID, Feature: row.Feature, WorkspaceID: row.WorkspaceID,
			Name: row.Name, Description: row.Description, VmResourceID: row.VmResourceID, K8sClusterResourceID: row.K8sClusterResourceID,
			RefreshIntervalSeconds: row.RefreshIntervalSeconds,
			CreatedBy:              row.CreatedBy, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		},
		BoundResourceName: row.BoundResourceName, BoundResourceType: row.BoundResourceType, BoundResourceStatus: row.BoundResourceStatus,
		WorkspaceName: row.WorkspaceName, FolderName: row.FolderName,
	}
}

func monitoringDashboardFromByResourceRow(row generated.ListMonitoringDashboardsByResourceIDsRow) MonitoringDashboardWithBinding {
	return MonitoringDashboardWithBinding{
		MonitoringDashboard: generated.MonitoringDashboard{
			ID: row.ID, MonitoringFolderID: row.MonitoringFolderID, Feature: row.Feature, WorkspaceID: row.WorkspaceID,
			Name: row.Name, Description: row.Description, VmResourceID: row.VmResourceID, K8sClusterResourceID: row.K8sClusterResourceID,
			RefreshIntervalSeconds: row.RefreshIntervalSeconds,
			CreatedBy:              row.CreatedBy, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		},
		BoundResourceName: row.BoundResourceName, BoundResourceType: row.BoundResourceType, BoundResourceStatus: row.BoundResourceStatus,
		WorkspaceName: row.WorkspaceName, FolderName: row.FolderName,
	}
}

type MonitoringDashboardService struct {
	store *repository.Store
	authz *AuthorizationService
}

func NewMonitoringDashboardService(store *repository.Store, authz *AuthorizationService) *MonitoringDashboardService {
	return &MonitoringDashboardService{store: store, authz: authz}
}

type CreateMonitoringDashboardInput struct {
	Feature                string
	Name                   string
	Description            string
	MonitoringFolderID     *uuid.UUID
	VMResourceID           *uuid.UUID // set iff feature is a DOCKER_* feature
	ClusterResourceID      *uuid.UUID // set iff feature is a K8S_* feature
	RefreshIntervalSeconds int32
}

// Create resolves the bound resource server-side (never trusts a client-
// supplied workspace_id) and derives the Dashboard's own workspace_id
// from it, so nav placement and the actual docker_access_grants
// authorization check can never disagree. If a folder is given, its
// workspace AND feature must match.
func (s *MonitoringDashboardService) Create(ctx context.Context, in CreateMonitoringDashboardInput, createdBy uuid.UUID) (generated.MonitoringDashboard, error) {
	if strings.TrimSpace(in.Name) == "" {
		return generated.MonitoringDashboard{}, fmt.Errorf("%w: name is required", ErrValidation)
	}
	if !validMonitoringFeatures[in.Feature] {
		return generated.MonitoringDashboard{}, fmt.Errorf("%w: invalid feature", ErrValidation)
	}
	refreshInterval := in.RefreshIntervalSeconds
	if refreshInterval <= 0 {
		refreshInterval = 30
	}

	var resource generated.Resource
	var err error
	if monitoringFeatureIsDocker(in.Feature) {
		if in.VMResourceID == nil || in.ClusterResourceID != nil {
			return generated.MonitoringDashboard{}, fmt.Errorf("%w: exactly one bound resource (vm_resource_id) is required for a Docker dashboard", ErrValidation)
		}
		// vm_resource_id also accepts a standalone DOCKER_HOST resource --
		// dockerPermissionResourceTypes (docker_access.go) already permits
		// both for docker.monitor/docker.logs, this just stops assuming VM.
		resource, err = resolveDockerFeatureResource(ctx, s.store, *in.VMResourceID, monitoringFeaturePermission(in.Feature))
	} else {
		if in.ClusterResourceID == nil || in.VMResourceID != nil {
			return generated.MonitoringDashboard{}, fmt.Errorf("%w: exactly one bound resource (k8s_cluster_resource_id) is required for a Kubernetes dashboard", ErrValidation)
		}
		resource, err = s.store.GetK8sClusterResourceByID(ctx, *in.ClusterResourceID)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrNotFound) {
			return generated.MonitoringDashboard{}, fmt.Errorf("%w: bound resource", ErrNotFound)
		}
		return generated.MonitoringDashboard{}, fmt.Errorf("load bound resource: %w", err)
	}

	var folderID pgtype.UUID
	if in.MonitoringFolderID != nil {
		folder, err := s.store.GetMonitoringFolderByID(ctx, *in.MonitoringFolderID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return generated.MonitoringDashboard{}, fmt.Errorf("%w: folder", ErrNotFound)
			}
			return generated.MonitoringDashboard{}, fmt.Errorf("load folder: %w", err)
		}
		if folder.Feature != in.Feature {
			return generated.MonitoringDashboard{}, fmt.Errorf("%w: folder belongs to a different feature", ErrValidation)
		}
		if folder.WorkspaceID != resource.WorkspaceID {
			return generated.MonitoringDashboard{}, fmt.Errorf("%w: folder belongs to a different workspace than the bound resource", ErrValidation)
		}
		folderID = pgutil.NullUUID(in.MonitoringFolderID)
	}

	return s.store.CreateMonitoringDashboard(ctx, generated.CreateMonitoringDashboardParams{
		MonitoringFolderID: folderID, Feature: in.Feature, WorkspaceID: resource.WorkspaceID,
		Name: in.Name, Description: pgutil.Text(in.Description),
		VmResourceID: pgutil.NullUUID(in.VMResourceID), K8sClusterResourceID: pgutil.NullUUID(in.ClusterResourceID),
		RefreshIntervalSeconds: refreshInterval, CreatedBy: pgutil.NullUUID(&createdBy),
	})
}

func (s *MonitoringDashboardService) Get(ctx context.Context, id uuid.UUID) (MonitoringDashboardWithBinding, error) {
	row, err := s.store.GetMonitoringDashboardWithBindingByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MonitoringDashboardWithBinding{}, ErrNotFound
		}
		return MonitoringDashboardWithBinding{}, err
	}
	return monitoringDashboardFromGetRow(row), nil
}

func (s *MonitoringDashboardService) Rename(ctx context.Context, id uuid.UUID, name, description string) (generated.MonitoringDashboard, error) {
	if strings.TrimSpace(name) == "" {
		return generated.MonitoringDashboard{}, fmt.Errorf("%w: name is required", ErrValidation)
	}
	d, err := s.store.UpdateMonitoringDashboardName(ctx, generated.UpdateMonitoringDashboardNameParams{ID: id, Name: name, Description: pgutil.Text(description)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.MonitoringDashboard{}, ErrNotFound
		}
		return generated.MonitoringDashboard{}, err
	}
	return d, nil
}

// Move re-runs the same folder-placement check Create does: the target
// folder's feature/workspace must match this Dashboard's own (its bound
// resource never changes, so its workspace can't either).
func (s *MonitoringDashboardService) Move(ctx context.Context, id uuid.UUID, folderID *uuid.UUID) (generated.MonitoringDashboard, error) {
	d, err := s.store.GetMonitoringDashboardByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.MonitoringDashboard{}, ErrNotFound
		}
		return generated.MonitoringDashboard{}, err
	}
	if folderID != nil {
		folder, err := s.store.GetMonitoringFolderByID(ctx, *folderID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return generated.MonitoringDashboard{}, fmt.Errorf("%w: folder", ErrNotFound)
			}
			return generated.MonitoringDashboard{}, fmt.Errorf("load folder: %w", err)
		}
		if folder.Feature != d.Feature {
			return generated.MonitoringDashboard{}, fmt.Errorf("%w: folder belongs to a different feature", ErrValidation)
		}
		if folder.WorkspaceID != d.WorkspaceID {
			return generated.MonitoringDashboard{}, fmt.Errorf("%w: folder belongs to a different workspace", ErrValidation)
		}
	}
	return s.store.MoveMonitoringDashboardFolder(ctx, generated.MoveMonitoringDashboardFolderParams{ID: id, MonitoringFolderID: pgutil.NullUUID(folderID)})
}

func (s *MonitoringDashboardService) SetRefreshInterval(ctx context.Context, id uuid.UUID, seconds int32) (generated.MonitoringDashboard, error) {
	if seconds <= 0 {
		return generated.MonitoringDashboard{}, fmt.Errorf("%w: refresh_interval_seconds must be positive", ErrValidation)
	}
	d, err := s.store.UpdateMonitoringDashboardRefreshInterval(ctx, generated.UpdateMonitoringDashboardRefreshIntervalParams{ID: id, RefreshIntervalSeconds: seconds})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.MonitoringDashboard{}, ErrNotFound
		}
		return generated.MonitoringDashboard{}, err
	}
	return d, nil
}

func (s *MonitoringDashboardService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.store.DeleteMonitoringDashboard(ctx, id)
}

// FilterInput is one wizard "Resources" step selection.
type FilterInput struct {
	Type  string // CONTAINER | NAMESPACE | RESOURCE_TYPE
	Value string
}

var validFilterTypesByFeature = map[string]map[string]bool{
	MonitoringFeatureDockerMonitoring: {"CONTAINER": true},
	MonitoringFeatureDockerLogs:       {"CONTAINER": true},
	MonitoringFeatureK8sMonitoring:    {"NAMESPACE": true, "RESOURCE_TYPE": true},
	MonitoringFeatureK8sLogs:          {"NAMESPACE": true, "RESOURCE_TYPE": true},
}

// SetResourceSelection replaces dashboard id's Resources-step selection
// wholesale (mirrors syncContainerNetworkMemberships' own delete-then-
// reinsert convention for "current selection, not history"). Each
// filter's type must be legal for the dashboard's own feature (e.g. a
// K8S_MONITORING dashboard can never hold a CONTAINER filter).
func (s *MonitoringDashboardService) SetResourceSelection(ctx context.Context, id uuid.UUID, filters []FilterInput) ([]generated.MonitoringDashboardFilter, error) {
	d, err := s.store.GetMonitoringDashboardByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	allowed := validFilterTypesByFeature[d.Feature]
	for _, f := range filters {
		if !allowed[f.Type] {
			return nil, fmt.Errorf("%w: filter type %q is not valid for this dashboard's feature", ErrValidation, f.Type)
		}
		if strings.TrimSpace(f.Value) == "" {
			return nil, fmt.Errorf("%w: filter value is required", ErrValidation)
		}
	}
	if err := s.store.DeleteMonitoringDashboardFilters(ctx, id); err != nil {
		return nil, fmt.Errorf("clear resource selection: %w", err)
	}
	out := make([]generated.MonitoringDashboardFilter, 0, len(filters))
	for _, f := range filters {
		row, err := s.store.CreateMonitoringDashboardFilter(ctx, generated.CreateMonitoringDashboardFilterParams{
			MonitoringDashboardID: id, FilterType: f.Type, Value: f.Value,
		})
		if err != nil {
			return nil, fmt.Errorf("insert resource selection: %w", err)
		}
		out = append(out, row)
	}
	return out, nil
}

func (s *MonitoringDashboardService) ListResourceSelection(ctx context.Context, id uuid.UUID) ([]generated.MonitoringDashboardFilter, error) {
	return s.store.ListMonitoringDashboardFilters(ctx, id)
}

var validWidgetTypes = map[string]bool{
	"CPU_CHART": true, "MEMORY_CHART": true, "NETWORK_CHART": true, "STORAGE_CHART": true,
	"CONTAINER_COUNT": true, "POD_COUNT": true, "RESTART_COUNT": true, "LATENCY": true,
	"LOGS": true, "ERRORS": true, "RESOURCE_STATUS": true,
}

// SetWidgets replaces dashboard id's Metrics-step widget picks wholesale.
// Only valid for a *_MONITORING dashboard -- a *_LOGS dashboard's
// Configure wizard skips the Metrics/Review steps entirely (a log viewer
// has no widget picks), so setting widgets on one is rejected outright
// rather than silently accepted and never rendered.
func (s *MonitoringDashboardService) SetWidgets(ctx context.Context, id uuid.UUID, widgetTypes []string) ([]generated.MonitoringDashboardWidget, error) {
	d, err := s.store.GetMonitoringDashboardByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if monitoringFeatureIsLogs(d.Feature) {
		return nil, fmt.Errorf("%w: widgets are not applicable to a Logs dashboard", ErrValidation)
	}
	for _, wt := range widgetTypes {
		if !validWidgetTypes[wt] {
			return nil, fmt.Errorf("%w: unknown widget type %q", ErrValidation, wt)
		}
	}
	if err := s.store.DeleteMonitoringDashboardWidgets(ctx, id); err != nil {
		return nil, fmt.Errorf("clear widgets: %w", err)
	}
	out := make([]generated.MonitoringDashboardWidget, 0, len(widgetTypes))
	for i, wt := range widgetTypes {
		row, err := s.store.CreateMonitoringDashboardWidget(ctx, generated.CreateMonitoringDashboardWidgetParams{
			MonitoringDashboardID: id, WidgetType: wt, Position: int32(i),
		})
		if err != nil {
			return nil, fmt.Errorf("insert widget: %w", err)
		}
		out = append(out, row)
	}
	return out, nil
}

func (s *MonitoringDashboardService) ListWidgets(ctx context.Context, id uuid.UUID) ([]generated.MonitoringDashboardWidget, error) {
	return s.store.ListMonitoringDashboardWidgets(ctx, id)
}

// CanView reports whether user may open dashboard d at all -- exactly
// the one docker_access_grants permission matching d's feature qualifies
// (see monitoringFeaturePermission's doc comment for why this is a
// single check, unlike the old combined-tabs Dashboard's either-grant
// rule).
func (s *MonitoringDashboardService) CanView(ctx context.Context, user AuthenticatedUser, d generated.MonitoringDashboard) (bool, error) {
	if user.IsAdmin() {
		return true, nil
	}
	perm := monitoringFeaturePermission(d.Feature)
	if perm == "" {
		return false, nil
	}
	dashboardIDs, err := s.authz.AccessibleMonitoringDashboardIDsForFeature(ctx, user, perm)
	if err != nil {
		return false, err
	}
	if uuidSliceContains(dashboardIDs, d.ID) {
		return true, nil
	}
	if d.MonitoringFolderID.Valid {
		folderIDs, err := s.authz.AccessibleMonitoringFolderIDsForFeature(ctx, user, perm)
		if err != nil {
			return false, err
		}
		if uuidSliceContains(folderIDs, pgutil.UUID(d.MonitoringFolderID)) {
			return true, nil
		}
	}
	if monitoringFeatureIsDocker(d.Feature) {
		ids, err := s.authz.AccessibleVMResourceIDsForDockerFeature(ctx, user, perm)
		if err != nil {
			return false, err
		}
		return uuidSliceContains(ids, pgutil.UUID(d.VmResourceID)), nil
	}
	ids, err := s.authz.AccessibleK8sClusterResourceIDsForFeature(ctx, user, perm)
	if err != nil {
		return false, err
	}
	return uuidSliceContains(ids, pgutil.UUID(d.K8sClusterResourceID)), nil
}

// ListAccessibleForUser: Admin sees every Dashboard for feature matching
// the given (optional) filters; a Member sees Dashboards whose bound
// resource is in their feature-matching accessible set.
func (s *MonitoringDashboardService) ListAccessibleForUser(ctx context.Context, user AuthenticatedUser, feature string, workspaceID, folderID *uuid.UUID) ([]MonitoringDashboardWithBinding, error) {
	if user.IsAdmin() {
		rows, err := s.store.ListMonitoringDashboardsFiltered(ctx, generated.ListMonitoringDashboardsFilteredParams{
			Feature: feature, WorkspaceID: pgutil.NullUUID(workspaceID), MonitoringFolderID: pgutil.NullUUID(folderID),
		})
		if err != nil {
			return nil, err
		}
		out := make([]MonitoringDashboardWithBinding, 0, len(rows))
		for _, row := range rows {
			out = append(out, monitoringDashboardFromFilteredRow(row))
		}
		return out, nil
	}

	perm := monitoringFeaturePermission(feature)
	if perm == "" {
		return nil, fmt.Errorf("%w: invalid feature", ErrValidation)
	}
	var vmIDs, clusterIDs []uuid.UUID
	if monitoringFeatureIsDocker(feature) {
		ids, err := s.authz.AccessibleVMResourceIDsForDockerFeature(ctx, user, perm)
		if err != nil {
			return nil, err
		}
		vmIDs = ids
	} else {
		ids, err := s.authz.AccessibleK8sClusterResourceIDsForFeature(ctx, user, perm)
		if err != nil {
			return nil, err
		}
		clusterIDs = ids
	}
	folderIDs, err := s.authz.AccessibleMonitoringFolderIDsForFeature(ctx, user, perm)
	if err != nil {
		return nil, err
	}
	dashboardIDs, err := s.authz.AccessibleMonitoringDashboardIDsForFeature(ctx, user, perm)
	if err != nil {
		return nil, err
	}
	if vmIDs == nil {
		vmIDs = []uuid.UUID{}
	}
	if clusterIDs == nil {
		clusterIDs = []uuid.UUID{}
	}
	if folderIDs == nil {
		folderIDs = []uuid.UUID{}
	}
	if dashboardIDs == nil {
		dashboardIDs = []uuid.UUID{}
	}
	rows, err := s.store.ListMonitoringDashboardsByResourceIDs(ctx, generated.ListMonitoringDashboardsByResourceIDsParams{
		Feature: feature, VmResourceIds: vmIDs, K8sClusterResourceIds: clusterIDs, FolderIds: folderIDs, DashboardIds: dashboardIDs,
	})
	if err != nil {
		return nil, err
	}
	out := make([]MonitoringDashboardWithBinding, 0, len(rows))
	for _, row := range rows {
		if workspaceID != nil && row.WorkspaceID != *workspaceID {
			continue
		}
		if folderID != nil && pgutil.UUID(row.MonitoringFolderID) != *folderID {
			continue
		}
		out = append(out, monitoringDashboardFromByResourceRow(row))
	}
	return out, nil
}

func uuidSliceContains(ids []uuid.UUID, target uuid.UUID) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}
