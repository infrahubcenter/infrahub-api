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

// grantableVMPermissions is the allowlist for GrantVMAccess. vm.execute
// and vm.update are deliberately excluded -- not implemented yet (Step 3
// §14, still true in Step 4) and must not be grantable early.
var grantableVMPermissions = map[string]bool{
	PermVMView:    true,
	PermVMConnect: true,
	PermVMMetrics: true,
	PermVMUpdates: true,
}

// grantableDatabasePermissions is the allowlist for GrantDatabaseAccess
// (spec §53/#97). All four are grantable -- unlike vm.reboot's
// never-grantable precedent, an Admin is meant to be able to hand a
// Member deeper access (browser/logs/query text) on a per-database,
// explicit basis; the *default* (group membership) still only ever
// implies database.view + database.performance (see
// AuthorizationService.EffectiveDatabaseAccess).
var grantableDatabasePermissions = map[string]bool{
	PermDatabaseView:         true,
	PermDatabasePerformance:  true,
	PermDatabaseBrowser:      true,
	PermDatabaseLogs:         true,
	PermDatabaseQueryDetails: true,
}

// grantableObjectStoragePermissions is the allowlist for
// GrantObjectStorageAccess -- mirrors grantableDatabasePermissions
// exactly: all four are grantable, since an Admin is meant to be able to
// hand a Member deeper access (browser/download) on a per-storage,
// explicit basis. The *default* (group membership) still only ever
// implies object_storage.view + object_storage.monitor (see
// AuthorizationService.EffectiveObjectStorageAccess).
var grantableObjectStoragePermissions = map[string]bool{
	PermObjectStorageView:     true,
	PermObjectStorageMonitor:  true,
	PermObjectStorageBrowser:  true,
	PermObjectStorageDownload: true,
}

// AccessService implements direct VM permission grants (resource_permissions).
// Group membership (the other access mechanism) is owned by GroupService,
// since it's managed as part of group administration.
type AccessService struct {
	store *repository.Store
}

// NewAccessService creates an AccessService.
func NewAccessService(store *repository.Store) *AccessService {
	return &AccessService{store: store}
}

// GrantVMAccess grants targetUserID the given permissions (a subset of
// vm.view/vm.connect) on vmResourceID, atomically.
func (s *AccessService) GrantVMAccess(ctx context.Context, targetUserID, vmResourceID uuid.UUID, permissions []string) error {
	if len(permissions) == 0 {
		return fmt.Errorf("%w: at least one permission is required", ErrValidation)
	}
	for _, p := range permissions {
		if !grantableVMPermissions[p] {
			return fmt.Errorf("%w: permission not grantable: %s", ErrValidation, p)
		}
	}

	if _, err := s.store.GetUserByID(ctx, targetUserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: user", ErrNotFound)
		}
		return fmt.Errorf("load user: %w", err)
	}
	if _, err := s.store.GetVMResourceByID(ctx, vmResourceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: VM", ErrNotFound)
		}
		return fmt.Errorf("load vm: %w", err)
	}

	return s.store.WithTx(ctx, func(q *generated.Queries) error {
		for _, p := range permissions {
			perm, err := q.GetPermissionByName(ctx, p)
			if err != nil {
				return fmt.Errorf("load permission %s: %w", p, err)
			}
			if err := q.GrantResourcePermission(ctx, generated.GrantResourcePermissionParams{
				ResourceID:   vmResourceID,
				UserID:       targetUserID,
				PermissionID: perm.ID,
			}); err != nil {
				return fmt.Errorf("grant permission: %w", err)
			}
		}
		return nil
	})
}

// RevokeVMAccess removes every direct permission grant targetUserID has on
// vmResourceID. Group-derived access to the same VM, if any, is untouched
// (Step 3 §17 / Step 4 §34: direct and group access are independent).
func (s *AccessService) RevokeVMAccess(ctx context.Context, targetUserID, vmResourceID uuid.UUID) error {
	if err := s.store.RevokeAllResourcePermissionsForUser(ctx, generated.RevokeAllResourcePermissionsForUserParams{
		ResourceID: vmResourceID, UserID: targetUserID,
	}); err != nil {
		return fmt.Errorf("revoke access: %w", err)
	}
	return nil
}

// GrantDatabaseAccess grants targetUserID the given permissions (a
// subset of grantableDatabasePermissions) on databaseResourceID,
// atomically -- mirrors GrantVMAccess exactly (spec §51/#91's "Admin can
// assign Member -> Database without giving entire project/group access").
func (s *AccessService) GrantDatabaseAccess(ctx context.Context, targetUserID, databaseResourceID uuid.UUID, permissions []string) error {
	if len(permissions) == 0 {
		return fmt.Errorf("%w: at least one permission is required", ErrValidation)
	}
	for _, p := range permissions {
		if !grantableDatabasePermissions[p] {
			return fmt.Errorf("%w: permission not grantable: %s", ErrValidation, p)
		}
	}

	if _, err := s.store.GetUserByID(ctx, targetUserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: user", ErrNotFound)
		}
		return fmt.Errorf("load user: %w", err)
	}
	if _, err := s.store.GetDatabaseResourceByID(ctx, databaseResourceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: database", ErrNotFound)
		}
		return fmt.Errorf("load database: %w", err)
	}

	return s.store.WithTx(ctx, func(q *generated.Queries) error {
		for _, p := range permissions {
			perm, err := q.GetPermissionByName(ctx, p)
			if err != nil {
				return fmt.Errorf("load permission %s: %w", p, err)
			}
			if err := q.GrantResourcePermission(ctx, generated.GrantResourcePermissionParams{
				ResourceID: databaseResourceID, UserID: targetUserID, PermissionID: perm.ID,
			}); err != nil {
				return fmt.Errorf("grant permission: %w", err)
			}
		}
		return nil
	})
}

// RevokeDatabaseAccess removes every direct permission grant
// targetUserID has on databaseResourceID -- mirrors RevokeVMAccess exactly.
func (s *AccessService) RevokeDatabaseAccess(ctx context.Context, targetUserID, databaseResourceID uuid.UUID) error {
	if err := s.store.RevokeAllResourcePermissionsForUser(ctx, generated.RevokeAllResourcePermissionsForUserParams{
		ResourceID: databaseResourceID, UserID: targetUserID,
	}); err != nil {
		return fmt.Errorf("revoke access: %w", err)
	}
	return nil
}

// GrantObjectStorageAccess grants targetUserID the given permissions (a
// subset of grantableObjectStoragePermissions) on objectStorageResourceID,
// atomically -- mirrors GrantDatabaseAccess exactly.
func (s *AccessService) GrantObjectStorageAccess(ctx context.Context, targetUserID, objectStorageResourceID uuid.UUID, permissions []string) error {
	if len(permissions) == 0 {
		return fmt.Errorf("%w: at least one permission is required", ErrValidation)
	}
	for _, p := range permissions {
		if !grantableObjectStoragePermissions[p] {
			return fmt.Errorf("%w: permission not grantable: %s", ErrValidation, p)
		}
	}

	if _, err := s.store.GetUserByID(ctx, targetUserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: user", ErrNotFound)
		}
		return fmt.Errorf("load user: %w", err)
	}
	if _, err := s.store.GetObjectStorageResourceByID(ctx, objectStorageResourceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: object storage", ErrNotFound)
		}
		return fmt.Errorf("load object storage: %w", err)
	}

	return s.store.WithTx(ctx, func(q *generated.Queries) error {
		for _, p := range permissions {
			perm, err := q.GetPermissionByName(ctx, p)
			if err != nil {
				return fmt.Errorf("load permission %s: %w", p, err)
			}
			if err := q.GrantResourcePermission(ctx, generated.GrantResourcePermissionParams{
				ResourceID: objectStorageResourceID, UserID: targetUserID, PermissionID: perm.ID,
			}); err != nil {
				return fmt.Errorf("grant permission: %w", err)
			}
		}
		return nil
	})
}

// RevokeObjectStorageAccess removes every direct permission grant
// targetUserID has on objectStorageResourceID -- mirrors
// RevokeDatabaseAccess exactly.
func (s *AccessService) RevokeObjectStorageAccess(ctx context.Context, targetUserID, objectStorageResourceID uuid.UUID) error {
	if err := s.store.RevokeAllResourcePermissionsForUser(ctx, generated.RevokeAllResourcePermissionsForUserParams{
		ResourceID: objectStorageResourceID, UserID: targetUserID,
	}); err != nil {
		return fmt.Errorf("revoke access: %w", err)
	}
	return nil
}
