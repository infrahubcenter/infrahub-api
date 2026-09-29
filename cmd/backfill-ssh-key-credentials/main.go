// Command backfill-ssh-key-credentials is a one-off migration helper for
// the named SSH key credential rework (migration 051): it copies every VM's
// old-style, one-per-VM credentials(SSH_PRIVATE_KEY) row into a new named
// ssh_key_credentials row (named after the VM) and attaches it via
// vms.ssh_key_credential_id. Idempotent -- ListLegacySSHCredentialsForBackfill
// only returns VMs that don't already have a credential attached, so
// re-running after a partial failure just picks up where it left off.
//
// The old credentials table itself is left untouched; nothing here deletes
// from it. Run this once, after applying migration 051 and before removing
// the legacy CredentialService's storage path from any remaining callers.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"vmcontrolcenter/backend/internal/config"
	"vmcontrolcenter/backend/internal/database"
	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
	"vmcontrolcenter/backend/internal/services"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(context.Background(), logger); err != nil {
		logger.Error("backfill-ssh-key-credentials failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

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

	encryption, err := services.NewEncryptionService(cfg.SSHCredentialEncryptionKey)
	if err != nil {
		return fmt.Errorf("SSH_CREDENTIAL_ENCRYPTION_KEY: %w", err)
	}
	sshKeyCredentials := services.NewSSHKeyCredentialService(store, encryption)

	adminIDs, err := store.ListAdminUserIDs(ctx)
	if err != nil {
		return fmt.Errorf("list admin users: %w", err)
	}
	if len(adminIDs) == 0 {
		return fmt.Errorf("no ADMIN user exists to attribute backfilled credentials to; run bootstrap-admin first")
	}
	createdBy := adminIDs[0]

	pending, err := store.ListLegacySSHCredentialsForBackfill(ctx)
	if err != nil {
		return fmt.Errorf("list legacy ssh credentials: %w", err)
	}
	if len(pending) == 0 {
		logger.Info("nothing to backfill; every VM with a legacy credential already has a named credential attached")
		return nil
	}

	migrated, failed := 0, 0
	for _, row := range pending {
		plaintext, err := encryption.Decrypt(string(row.EncryptedData))
		if err != nil {
			logger.Error("skipping VM: failed to decrypt legacy credential", "vm_id", row.VmID, "resource_name", row.ResourceName, "error", err)
			failed++
			continue
		}

		name := row.ResourceName
		var cred services.SSHKeyCredentialSummary
		for attempt := 0; attempt < 5; attempt++ {
			cred, err = sshKeyCredentials.Create(ctx, row.WorkspaceID, name, plaintext, createdBy)
			if err == nil {
				break
			}
			if errors.Is(err, services.ErrDuplicateName) {
				// Another credential (unrelated to this VM) already owns
				// this name in the workspace -- disambiguate and retry
				// rather than fail the whole run over a naming collision.
				name = fmt.Sprintf("%s (%d)", row.ResourceName, attempt+2)
				continue
			}
			break
		}
		if err != nil {
			logger.Error("skipping VM: failed to create named credential", "vm_id", row.VmID, "resource_name", row.ResourceName, "error", err)
			failed++
			continue
		}

		credID := cred.ID
		if err := store.SetVMSSHKeyCredentialID(ctx, generated.SetVMSSHKeyCredentialIDParams{
			ID: row.VmID, SshKeyCredentialID: pgutil.NullUUID(&credID),
		}); err != nil {
			logger.Error("created credential but failed to attach it to the VM", "vm_id", row.VmID, "credential_id", cred.ID, "error", err)
			failed++
			continue
		}

		logger.Info("backfilled ssh key credential", "vm_id", row.VmID, "resource_name", row.ResourceName, "credential_id", cred.ID, "credential_name", cred.Name)
		migrated++
	}

	logger.Info("backfill complete", "migrated", migrated, "failed", failed)
	if failed > 0 {
		return fmt.Errorf("%d VM(s) failed to backfill; re-run after investigating (see error logs above)", failed)
	}
	return nil
}
