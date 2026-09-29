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

// WorkspaceService implements workspace management and workspace
// membership, the VM/Database/Object-Storage/Docker/Kubernetes-access-
// granting relationship. Workspace replaces the old two-tier
// Project->Group hierarchy with one flat tier (see migrations/
// 043_workspaces.sql for the cutover).
type WorkspaceService struct {
	store *repository.Store
}

// NewWorkspaceService creates a WorkspaceService.
func NewWorkspaceService(store *repository.Store) *WorkspaceService {
	return &WorkspaceService{store: store}
}

// Create validates and inserts a new workspace. Workspace names are not
// required to be unique -- see migrations/043_workspaces.sql's design note
// -- so this never fails on a name collision.
func (s *WorkspaceService) Create(ctx context.Context, name, description string) (generated.Workspace, error) {
	trimmedName, err := validateName("workspace name", name)
	if err != nil {
		return generated.Workspace{}, err
	}

	workspace, err := s.store.CreateWorkspace(ctx, generated.CreateWorkspaceParams{
		Name:        trimmedName,
		Description: pgutil.Text(description),
	})
	if err != nil {
		return generated.Workspace{}, fmt.Errorf("create workspace: %w", err)
	}
	return workspace, nil
}

// List returns every workspace with VM/database/object-storage/member
// counts.
func (s *WorkspaceService) List(ctx context.Context) ([]generated.ListWorkspacesWithCountsRow, error) {
	return s.store.ListWorkspacesWithCounts(ctx)
}

// Get returns one workspace with counts, or ErrNotFound.
func (s *WorkspaceService) Get(ctx context.Context, id uuid.UUID) (generated.GetWorkspaceWithCountsByIDRow, error) {
	row, err := s.store.GetWorkspaceWithCountsByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.GetWorkspaceWithCountsByIDRow{}, ErrNotFound
		}
		return generated.GetWorkspaceWithCountsByIDRow{}, fmt.Errorf("load workspace: %w", err)
	}
	return row, nil
}

// Update applies a full field update (name, description, is_active).
func (s *WorkspaceService) Update(ctx context.Context, id uuid.UUID, name, description string, isActive bool) (generated.Workspace, error) {
	trimmedName, err := validateName("workspace name", name)
	if err != nil {
		return generated.Workspace{}, err
	}

	updated, err := s.store.UpdateWorkspace(ctx, generated.UpdateWorkspaceParams{
		ID:          id,
		Name:        trimmedName,
		Description: pgutil.Text(description),
		IsActive:    isActive,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.Workspace{}, ErrNotFound
		}
		return generated.Workspace{}, fmt.Errorf("update workspace: %w", err)
	}
	return updated, nil
}

// Delete permanently removes a workspace -- distinct from Update's
// is_active deactivation, and irreversible. Callers must confirm via Get
// that the workspace has zero VMs/databases/object storage before calling
// this (resources.workspace_id has no ON DELETE behavior that would
// silently orphan them); workspace_members is ON DELETE CASCADE, so
// membership simply ends. confirmationName must equal the workspace's
// current name exactly.
func (s *WorkspaceService) Delete(ctx context.Context, id uuid.UUID, confirmationName string) error {
	existing, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if confirmationName != existing.Name {
		return ErrConfirmationMismatch
	}
	// Every resource kind that can live in a workspace must be checked
	// here -- Docker Host/K8s Cluster were added later (migrations 032/046)
	// and were missing from this check entirely, which let a workspace
	// containing one of those reach DeleteWorkspace below and fail on a
	// raw FK constraint (resources.workspace_id is NOT NULL, but its own
	// FK is ON DELETE SET NULL) instead of being blocked with this clear
	// message.
	if existing.VmCount > 0 || existing.DatabaseCount > 0 || existing.ObjectStorageCount > 0 || existing.DockerHostCount > 0 || existing.K8sClusterCount > 0 {
		return fmt.Errorf("%w: this workspace contains %d VM(s), %d database(s), %d object storage(s), %d docker host(s), %d kubernetes cluster(s)",
			ErrHasDependencies, existing.VmCount, existing.DatabaseCount, existing.ObjectStorageCount, existing.DockerHostCount, existing.K8sClusterCount)
	}
	// Any resource row still pointing at this workspace at this point is
	// guaranteed already soft-deleted (a live one would have failed the
	// check above) -- clear those out first so the workspace delete below
	// doesn't hit resources.workspace_id's NOT NULL vs. its own ON DELETE
	// SET NULL FK contradiction. See DeleteSoftDeletedResourcesByWorkspace's
	// own doc comment.
	if err := s.store.DeleteSoftDeletedResourcesByWorkspace(ctx, id); err != nil {
		return fmt.Errorf("clear soft-deleted resources: %w", err)
	}
	if err := s.store.DeleteWorkspace(ctx, id); err != nil {
		return fmt.Errorf("delete workspace: %w", err)
	}
	return nil
}

// ListMembers returns the users directly in workspaceID.
func (s *WorkspaceService) ListMembers(ctx context.Context, workspaceID uuid.UUID) ([]generated.User, error) {
	return s.store.ListWorkspaceMembers(ctx, workspaceID)
}

// AddMember adds userID to workspaceID. Both must already exist.
func (s *WorkspaceService) AddMember(ctx context.Context, workspaceID, userID uuid.UUID) error {
	if _, err := s.store.GetWorkspaceByID(ctx, workspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: workspace", ErrNotFound)
		}
		return fmt.Errorf("load workspace: %w", err)
	}
	if _, err := s.store.GetUserByID(ctx, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: user", ErrNotFound)
		}
		return fmt.Errorf("load user: %w", err)
	}
	if err := s.store.AddWorkspaceMember(ctx, generated.AddWorkspaceMemberParams{WorkspaceID: workspaceID, UserID: userID}); err != nil {
		return fmt.Errorf("add workspace member: %w", err)
	}
	return nil
}

// RemoveMember removes userID from workspaceID. Idempotent: removing a
// non-member is not an error.
func (s *WorkspaceService) RemoveMember(ctx context.Context, workspaceID, userID uuid.UUID) error {
	if err := s.store.RemoveWorkspaceMember(ctx, generated.RemoveWorkspaceMemberParams{WorkspaceID: workspaceID, UserID: userID}); err != nil {
		return fmt.Errorf("remove workspace member: %w", err)
	}
	return nil
}
