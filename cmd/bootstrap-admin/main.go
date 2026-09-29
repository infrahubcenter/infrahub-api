// Command bootstrap-admin creates the first ADMIN account. It reads
// credentials from BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_NAME /
// BOOTSTRAP_ADMIN_PASSWORD (see backend/.env.example) rather than accepting
// them as command-line flags, so a password never appears in shell
// history or process listings. It refuses to run if an ADMIN already
// exists, so it can never silently overwrite one.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"vmcontrolcenter/backend/internal/config"
	"vmcontrolcenter/backend/internal/database"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(logger); err != nil {
		logger.Error("bootstrap-admin failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if cfg.BootstrapAdminEmail == "" || cfg.BootstrapAdminName == "" || cfg.BootstrapAdminPassword == "" {
		return fmt.Errorf("BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_NAME, and BOOTSTRAP_ADMIN_PASSWORD are all required")
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

	store := repository.New(pool)
	tokens := services.NewTokenService(cfg.JWTSecret, cfg.AccessTokenTTL)
	auth := services.NewAuthService(store, tokens, cfg.RefreshTokenTTL)

	created, admin, err := auth.BootstrapAdmin(ctx, cfg.BootstrapAdminEmail, cfg.BootstrapAdminName, cfg.BootstrapAdminPassword)
	if err != nil {
		return err
	}
	if !created {
		return fmt.Errorf("an ADMIN account already exists; refusing to bootstrap another")
	}

	logger.Info("admin account created", "id", admin.ID, "email", admin.Email)
	return nil
}
