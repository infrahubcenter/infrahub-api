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

// ValidResourceTypes and ValidResourceStatuses are exported so handlers
// can validate query-string filters before they ever reach a service.
var ValidResourceTypes = map[string]bool{"VM": true, "DATABASE": true, "OBJECT_STORAGE": true}
var ValidResourceStatuses = map[string]bool{"UNKNOWN": true, "ONLINE": true, "OFFLINE": true, "WARNING": true, "ERROR": true, "DISABLED": true}

// ResourceService implements the generic, resource-type-agnostic
// endpoints (GET/POST/PATCH /api/resources). VM creation/update always
// goes through VMService instead, since a VM resource is meaningless
// without its paired vms row -- see CreatePlaceholder's doc comment.
type ResourceService struct {
	store *repository.Store
}

// NewResourceService creates a ResourceService.
func NewResourceService(store *repository.Store) *ResourceService {
	return &ResourceService{store: store}
}

// ResourceFilter is the optional filter set for List.
type ResourceFilter struct {
	WorkspaceID  *uuid.UUID
	ResourceType *string
	Status       *string
}

// List returns resources matching the given filters (any combination, or
// none). Unlike VM listing, this endpoint has no per-row authorization
// concept yet -- it's ADMIN-only end to end (see router.go) because only
// VM resources currently have a MEMBER-facing access model.
func (s *ResourceService) List(ctx context.Context, filter ResourceFilter) ([]generated.Resource, error) {
	params := generated.ListResourcesFilteredParams{
		WorkspaceID:  pgutil.NullUUID(filter.WorkspaceID),
		ResourceType: pgutil.Text(derefString(filter.ResourceType)),
		Status:       pgutil.Text(derefString(filter.Status)),
	}
	return s.store.ListResourcesFiltered(ctx, params)
}

// Get returns one resource by ID, or ErrNotFound.
func (s *ResourceService) Get(ctx context.Context, id uuid.UUID) (generated.Resource, error) {
	resource, err := s.store.GetResourceByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.Resource{}, ErrNotFound
		}
		return generated.Resource{}, fmt.Errorf("load resource: %w", err)
	}
	return resource, nil
}

// CreatePlaceholder creates a bare resources row for a DATABASE or
// OBJECT_STORAGE resource -- Step 4 §11's "basic placeholder management
// structure" for the two resource types this step doesn't build detail
// tables/connection logic for. VM is deliberately rejected here: a VM
// resource without a matching vms row breaks every VM-detail query (they
// INNER JOIN vms), so VM creation must go through VMService.Create, which
// keeps both rows in sync in one transaction.
func (s *ResourceService) CreatePlaceholder(ctx context.Context, workspaceID uuid.UUID, name, resourceType, description string) (generated.Resource, error) {
	if resourceType != "DATABASE" && resourceType != "OBJECT_STORAGE" {
		return generated.Resource{}, fmt.Errorf("%w: resource_type must be DATABASE or OBJECT_STORAGE here; create a VM via POST /api/vms", ErrValidation)
	}
	trimmedName, err := validateName("resource name", name)
	if err != nil {
		return generated.Resource{}, err
	}

	if _, err := s.store.GetWorkspaceByID(ctx, workspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.Resource{}, fmt.Errorf("%w: workspace", ErrNotFound)
		}
		return generated.Resource{}, fmt.Errorf("load workspace: %w", err)
	}

	resource, err := s.store.CreateResource(ctx, generated.CreateResourceParams{
		WorkspaceID:  workspaceID,
		Name:         trimmedName,
		ResourceType: resourceType,
		Description:  pgutil.Text(description),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return generated.Resource{}, fmt.Errorf("%w: a resource named %q already exists", ErrDuplicateName, trimmedName)
		}
		return generated.Resource{}, fmt.Errorf("create resource: %w", err)
	}
	return resource, nil
}

// UpdateResourceInput carries the fields allowed to change on a generic
// (non-VM) resource.
type UpdateResourceInput struct {
	Name        *string
	Description *string
	WorkspaceID *uuid.UUID
	Status      *string
}

// Update applies a partial update to a resource's name/description/
// workspace/status. VM resources should be updated via VMService.Update
// instead (it also updates the paired vms row); this still works for a VM
// row but will never touch vms fields.
func (s *ResourceService) Update(ctx context.Context, id uuid.UUID, in UpdateResourceInput) (generated.Resource, error) {
	existing, err := s.Get(ctx, id)
	if err != nil {
		return generated.Resource{}, err
	}

	name := existing.Name
	if in.Name != nil {
		trimmed, err := validateName("resource name", *in.Name)
		if err != nil {
			return generated.Resource{}, err
		}
		name = trimmed
	}
	description := pgutil.TextOrEmpty(existing.Description)
	if in.Description != nil {
		description = *in.Description
	}
	workspaceID := existing.WorkspaceID
	if in.WorkspaceID != nil {
		if _, err := s.store.GetWorkspaceByID(ctx, *in.WorkspaceID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return generated.Resource{}, fmt.Errorf("%w: workspace", ErrNotFound)
			}
			return generated.Resource{}, fmt.Errorf("load workspace: %w", err)
		}
		workspaceID = *in.WorkspaceID
	}
	status := existing.Status
	if in.Status != nil {
		if !ValidResourceStatuses[*in.Status] {
			return generated.Resource{}, fmt.Errorf("%w: invalid status %q", ErrValidation, *in.Status)
		}
		status = *in.Status
	}

	updated, err := s.store.UpdateResource(ctx, generated.UpdateResourceParams{
		ID: id, Name: name, Description: pgutil.Text(description), WorkspaceID: workspaceID, Status: status,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return generated.Resource{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return generated.Resource{}, fmt.Errorf("%w: a resource named %q already exists", ErrDuplicateName, name)
		}
		return generated.Resource{}, fmt.Errorf("update resource: %w", err)
	}
	return updated, nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
