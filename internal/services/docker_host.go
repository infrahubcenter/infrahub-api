package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/repository"
)

// DockerHostService is the CRUD/configuration layer for standalone Docker
// Hosts: a host is a first-class resource under a Workspace, never a VM
// child -- mirrors K8sClusterService exactly (a Docker Host is to a VM's
// own SSH-installed Docker agent what a K8s Cluster is to a VM: the same
// agent-token-authenticated, bearer-connects-out model, with no SSH/VM
// record involved at all). Admin-only end to end (enforced at the handler
// layer); a Member's only access to a host is the cross-host Monitoring/
// Logs dashboards, never this CRUD surface.
type DockerHostService struct {
	store  *repository.Store
	tokens *DockerHostAgentTokenService
}

// NewDockerHostService creates a DockerHostService.
func NewDockerHostService(store *repository.Store, tokens *DockerHostAgentTokenService) *DockerHostService {
	return &DockerHostService{store: store, tokens: tokens}
}

// ConfigureDockerHostInput is POST /api/docker/hosts' request shape.
type ConfigureDockerHostInput struct {
	WorkspaceID uuid.UUID
	Name        string
}

// Configure creates a new standalone Docker Host: a `resources` row
// (resource_type=DOCKER_HOST, under the given workspace), its
// `docker_hosts` row, and a freshly generated agent bearer token,
// atomically -- mirrors K8sClusterService.Configure's transaction shape
// exactly, minus the K8s-specific namespace_filter (a Docker Host has no
// analogous concept).
func (s *DockerHostService) Configure(ctx context.Context, in ConfigureDockerHostInput) (generated.DockerHost, string, error) {
	if in.Name == "" {
		return generated.DockerHost{}, "", fmt.Errorf("%w: name is required", ErrValidation)
	}
	if _, err := s.store.GetWorkspaceByID(ctx, in.WorkspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.DockerHost{}, "", fmt.Errorf("%w: workspace", ErrNotFound)
		}
		return generated.DockerHost{}, "", fmt.Errorf("load workspace: %w", err)
	}

	var host generated.DockerHost
	err := s.store.WithTx(ctx, func(q *generated.Queries) error {
		resource, err := q.CreateResource(ctx, generated.CreateResourceParams{
			WorkspaceID: in.WorkspaceID, Name: in.Name, ResourceType: "DOCKER_HOST",
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: a resource named %q already exists", ErrDuplicateName, in.Name)
			}
			return fmt.Errorf("create resource: %w", err)
		}
		created, err := q.CreateDockerHost(ctx, resource.ID)
		if err != nil {
			return fmt.Errorf("create docker host: %w", err)
		}
		host = created
		return nil
	})
	if err != nil {
		return generated.DockerHost{}, "", err
	}

	token, err := s.tokens.GenerateToken(ctx, host.ID)
	if err != nil {
		return host, "", fmt.Errorf("generate agent token: %w", err)
	}
	return host, token, nil
}

// SetMonitoringEnabled turns metrics/logs collection on/off -- disabling
// stops a future scheduler from ever enqueueing this host again.
func (s *DockerHostService) SetMonitoringEnabled(ctx context.Context, hostID uuid.UUID, enabled bool) (generated.DockerHost, error) {
	return s.store.SetDockerHostMonitoringEnabled(ctx, generated.SetDockerHostMonitoringEnabledParams{ID: hostID, MonitoringEnabled: enabled})
}

// RegenerateAgentToken issues a brand new token for an already-configured
// host, immediately invalidating whatever the currently-running agent
// container was using -- it must be restarted with the new token (and
// will then reconnect automatically) to resume working.
func (s *DockerHostService) RegenerateAgentToken(ctx context.Context, hostID uuid.UUID) (string, error) {
	if _, err := s.store.GetDockerHostByID(ctx, hostID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("load docker host: %w", err)
	}
	return s.tokens.GenerateToken(ctx, hostID)
}

// Delete soft-deletes a host's monitoring registration only. It NEVER
// touches the real Docker daemon/containers -- mirrors
// K8sClusterService.Delete exactly. The agent token row is left in place,
// but GetDockerHostByAgentTokenHash's own deleted_at IS NULL filter means
// it stops authenticating immediately regardless -- an already-running
// agent container simply fails to reconnect and can be removed at
// leisure.
func (s *DockerHostService) Delete(ctx context.Context, hostID uuid.UUID) error {
	return s.store.SoftDeleteDockerHostResource(ctx, hostID)
}
