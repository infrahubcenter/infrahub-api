// Command seed populates static reference data required for the
// application to function in any environment: the ADMIN/MEMBER roles and
// the permission catalog. It is idempotent (safe to run repeatedly) and
// never creates a user account -- admin/user creation is implemented in the
// authentication step.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"vmcontrolcenter/backend/internal/config"
	"vmcontrolcenter/backend/internal/database"
	"vmcontrolcenter/backend/internal/database/generated"
)

// OWNER sits above ADMIN: every existing ADMIN-gated capability plus a
// couple of Owner-exclusive ones (editing sign-in-method configuration,
// inviting another Owner) -- see services.AuthenticatedUser.IsAdmin/
// IsOwner. Listed first only for readability; seeding order doesn't matter.
var roles = []string{"OWNER", "ADMIN", "MEMBER"}

var permissions = []string{
	"auth.manage",

	"user.view", "user.create", "user.update", "user.delete",

	"project.view", "project.create", "project.update", "project.delete",

	"group.view", "group.create", "group.update", "group.delete",

	"resource.view", "resource.create", "resource.update", "resource.delete",

	"vm.view", "vm.create", "vm.update", "vm.delete", "vm.connect", "vm.execute", "vm.reboot", "vm.metrics", "vm.updates",

	"package.view", "package.update",

	"docker.view", "docker.execute",

	"os.view", "os.update",

	"database.view", "database.manage", "database.performance", "database.logs", "database.browser", "database.query_details",
	"database.operations.view", "database.operations.execute", "database.operations.cancel", "database.operations.retry",

	"storage.view", "storage.manage",

	"object_storage.view", "object_storage.monitor", "object_storage.browser", "object_storage.download",

	"monitoring.view",

	"recommendation.view",

	"operation.view", "operation.execute",

	"audit.view",
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(logger); err != nil {
		logger.Error("seed failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx := context.Background()

	pool, err := database.NewPool(ctx, cfg.DatabaseURL, database.PoolConfig{
		MaxConns:       cfg.DBMaxConns,
		MinConns:       cfg.DBMinConns,
		ConnectTimeout: cfg.DBConnectTimeout,
	})
	if err != nil {
		return err
	}
	defer pool.Close()

	q := generated.New(pool)

	rolesCreated := 0
	for _, name := range roles {
		if _, err := q.GetRoleByName(ctx, name); err == nil {
			continue
		}
		if _, err := q.CreateRole(ctx, generated.CreateRoleParams{Name: name}); err != nil {
			return fmt.Errorf("create role %s: %w", name, err)
		}
		rolesCreated++
	}

	permissionsCreated := 0
	for _, name := range permissions {
		if _, err := q.GetPermissionByName(ctx, name); err == nil {
			continue
		}
		if _, err := q.CreatePermission(ctx, generated.CreatePermissionParams{Name: name}); err != nil {
			return fmt.Errorf("create permission %s: %w", name, err)
		}
		permissionsCreated++
	}

	logger.Info("seed complete",
		"roles_created", rolesCreated,
		"roles_total", len(roles),
		"permissions_created", permissionsCreated,
		"permissions_total", len(permissions),
	)

	return nil
}
