package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// K8sClusterService is the CRUD/configuration layer for standalone
// Kubernetes clusters: a cluster is a first-class resource under a
// Workspace, never a VM child -- mirrors ObjectStorageService exactly.
// Admin-only end to end (enforced at the handler layer); a Member's only
// access to a cluster is the cross-cluster Monitoring/Logs dashboards,
// never this CRUD surface.
type K8sClusterService struct {
	store  *repository.Store
	tokens *K8sAgentTokenService
}

// NewK8sClusterService creates a K8sClusterService.
func NewK8sClusterService(store *repository.Store, tokens *K8sAgentTokenService) *K8sClusterService {
	return &K8sClusterService{store: store, tokens: tokens}
}

// ConfigureK8sClusterInput is POST /api/k8s/clusters' request shape.
type ConfigureK8sClusterInput struct {
	WorkspaceID     uuid.UUID
	Name            string
	NamespaceFilter string
}

// Configure creates a new standalone K8s cluster: a `resources` row
// (resource_type=K8S_CLUSTER, under the given workspace), its
// `k8s_clusters` row, and a freshly generated agent bearer token,
// atomically -- mirrors ObjectStorageService.Configure's transaction
// shape, except the credential this returns is a one-time-visible agent
// token rather than accepting a kubeconfig from the caller.
func (s *K8sClusterService) Configure(ctx context.Context, in ConfigureK8sClusterInput) (generated.K8sCluster, string, error) {
	if in.Name == "" {
		return generated.K8sCluster{}, "", fmt.Errorf("%w: name is required", ErrValidation)
	}
	if _, err := s.store.GetWorkspaceByID(ctx, in.WorkspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.K8sCluster{}, "", fmt.Errorf("%w: workspace", ErrNotFound)
		}
		return generated.K8sCluster{}, "", fmt.Errorf("load workspace: %w", err)
	}

	var cluster generated.K8sCluster
	err := s.store.WithTx(ctx, func(q *generated.Queries) error {
		resource, err := q.CreateResource(ctx, generated.CreateResourceParams{
			WorkspaceID: in.WorkspaceID, Name: in.Name, ResourceType: "K8S_CLUSTER",
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: a resource named %q already exists", ErrDuplicateName, in.Name)
			}
			return fmt.Errorf("create resource: %w", err)
		}
		created, err := q.CreateK8sCluster(ctx, generated.CreateK8sClusterParams{
			ResourceID: resource.ID, NamespaceFilter: pgutil.Text(in.NamespaceFilter),
		})
		if err != nil {
			return fmt.Errorf("create k8s cluster: %w", err)
		}
		cluster = created
		return nil
	})
	if err != nil {
		return generated.K8sCluster{}, "", err
	}

	token, err := s.tokens.GenerateToken(ctx, cluster.ID)
	if err != nil {
		return cluster, "", fmt.Errorf("generate agent token: %w", err)
	}
	return cluster, token, nil
}

// UpdateK8sClusterInput is PATCH /api/k8s/clusters/:id's request shape --
// every field optional, only supplied fields change.
type UpdateK8sClusterInput struct {
	NamespaceFilter *string
}

// Update edits a cluster's non-secret config -- partial update, mirrors
// ObjectStorageService.Update exactly.
func (s *K8sClusterService) Update(ctx context.Context, clusterID uuid.UUID, in UpdateK8sClusterInput) (generated.K8sCluster, error) {
	params := generated.UpdateK8sClusterConfigParams{ID: clusterID}
	if in.NamespaceFilter != nil {
		// Not pgutil.Text: that collapses "" to SQL NULL, which
		// UpdateK8sClusterConfig's COALESCE reads as "leave unchanged" --
		// making it impossible to ever clear namespace_filter back to
		// "" (list every namespace) once set. An explicit field here
		// always means "set it to exactly this", including empty.
		params.NamespaceFilter = pgtype.Text{String: *in.NamespaceFilter, Valid: true}
	}
	updated, err := s.store.UpdateK8sClusterConfig(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.K8sCluster{}, ErrNotFound
		}
		return generated.K8sCluster{}, fmt.Errorf("update k8s cluster: %w", err)
	}
	return updated, nil
}

// SetMonitoringEnabled turns discovery/metrics collection on/off --
// disabling stops a future scheduler from ever enqueueing this cluster
// again, but never deletes historical pod records.
func (s *K8sClusterService) SetMonitoringEnabled(ctx context.Context, clusterID uuid.UUID, enabled bool) (generated.K8sCluster, error) {
	return s.store.SetK8sClusterMonitoringEnabled(ctx, generated.SetK8sClusterMonitoringEnabledParams{ID: clusterID, MonitoringEnabled: enabled})
}

// RegenerateAgentToken issues a brand new token for an already-configured
// cluster, immediately invalidating whatever the currently-installed
// agent was using -- it must be reconfigured with the new token (and will
// then reconnect automatically) to resume working.
func (s *K8sClusterService) RegenerateAgentToken(ctx context.Context, clusterID uuid.UUID) (string, error) {
	if _, err := s.store.GetK8sClusterByID(ctx, clusterID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("load cluster: %w", err)
	}
	return s.tokens.GenerateToken(ctx, clusterID)
}

// Delete soft-deletes a cluster's monitoring registration only. It NEVER
// touches the real cluster -- this project has no cluster-mutating API
// surface anywhere (no kubectl apply/delete/exec of any kind beyond
// reading pod logs) -- mirrors ObjectStorageService.Delete exactly. The
// agent token row is left in place (this is a soft delete, not a hard
// one), but GetK8sClusterByAgentTokenHash's own deleted_at IS NULL filter
// means it stops authenticating immediately regardless -- an
// already-running agent simply fails to reconnect and can be uninstalled
// at leisure.
//
// Also cleans up any Monitoring/Logs dashboards still bound to this
// cluster's resource ID: the schema's own k8s_cluster_resource_id ON
// DELETE CASCADE never fires for a soft-delete (that only triggers on a
// real row DELETE), so without this a dashboard would be left dangling
// -- it still loads, but its pod picker renders permanently empty with
// nothing explaining why. See DeleteMonitoringDashboardsByResourceID.
func (s *K8sClusterService) Delete(ctx context.Context, clusterID uuid.UUID) error {
	cluster, err := s.store.GetK8sClusterByID(ctx, clusterID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("load cluster: %w", err)
	}
	if err := s.store.SoftDeleteK8sClusterResource(ctx, clusterID); err != nil {
		return err
	}
	if err := s.store.DeleteMonitoringDashboardsByResourceID(ctx, cluster.ResourceID); err != nil {
		return fmt.Errorf("clean up bound monitoring dashboards: %w", err)
	}
	return nil
}
