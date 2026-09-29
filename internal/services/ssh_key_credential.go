// Package services: ssh_key_credential.go implements named, reusable SSH
// key credentials -- the replacement for the old 1:1
// credentials(resource_id, 'SSH_PRIVATE_KEY') model (credential.go). An
// admin creates one named credential per key ("prod-fleet-key"), and any
// VM in the same workspace can be pointed at it via
// vms.ssh_key_credential_id -- see migrations/051_ssh_key_credentials.sql.
package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// SSHKeyCredentialSummary is the safe, list/detail-view shape of a named
// SSH key credential -- never the key material.
type SSHKeyCredentialSummary struct {
	ID          uuid.UUID
	WorkspaceID uuid.UUID
	Name        string
	Fingerprint string
	CreatedBy   *uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
	InUseCount  int64
}

func summaryFromRow(row generated.SshKeyCredential, inUseCount int64) SSHKeyCredentialSummary {
	var createdBy *uuid.UUID
	if row.CreatedBy.Valid {
		id := pgutil.UUID(row.CreatedBy)
		createdBy = &id
	}
	return SSHKeyCredentialSummary{
		ID: row.ID, WorkspaceID: row.WorkspaceID, Name: row.Name, Fingerprint: row.Fingerprint,
		CreatedBy: createdBy, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time, InUseCount: inUseCount,
	}
}

type SSHKeyCredentialService struct {
	store      *repository.Store
	encryption *EncryptionService
}

func NewSSHKeyCredentialService(store *repository.Store, encryption *EncryptionService) *SSHKeyCredentialService {
	return &SSHKeyCredentialService{store: store, encryption: encryption}
}

// Create validates workspaceID exists, validates+parses privateKeyPEM
// (rejecting passphrase-protected keys exactly like the legacy
// CredentialService.StoreSSHPrivateKey path), derives the fingerprint from
// the key's own public half -- never a client-supplied one -- encrypts,
// and inserts. A name collision within the workspace surfaces as
// ErrDuplicateName.
func (s *SSHKeyCredentialService) Create(ctx context.Context, workspaceID uuid.UUID, name string, privateKeyPEM []byte, createdBy uuid.UUID) (SSHKeyCredentialSummary, error) {
	trimmedName, err := validateName("SSH key credential name", name)
	if err != nil {
		return SSHKeyCredentialSummary{}, err
	}
	if _, err := s.store.GetWorkspaceByID(ctx, workspaceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SSHKeyCredentialSummary{}, fmt.Errorf("%w: workspace", ErrNotFound)
		}
		return SSHKeyCredentialSummary{}, fmt.Errorf("load workspace: %w", err)
	}

	signer, err := ParseSSHPrivateKey(privateKeyPEM)
	if err != nil {
		return SSHKeyCredentialSummary{}, err
	}
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())

	encrypted, err := s.encryption.Encrypt(privateKeyPEM)
	if err != nil {
		return SSHKeyCredentialSummary{}, fmt.Errorf("encrypt private key: %w", err)
	}

	row, err := s.store.CreateSSHKeyCredential(ctx, generated.CreateSSHKeyCredentialParams{
		WorkspaceID: workspaceID, Name: trimmedName, EncryptedPrivateKey: []byte(encrypted),
		Fingerprint: fingerprint, CreatedBy: pgutil.NullUUID(&createdBy),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return SSHKeyCredentialSummary{}, fmt.Errorf("%w: a credential named %q already exists in this workspace", ErrDuplicateName, trimmedName)
		}
		return SSHKeyCredentialSummary{}, fmt.Errorf("create ssh key credential: %w", err)
	}
	return summaryFromRow(row, 0), nil
}

// Get loads one credential by ID.
func (s *SSHKeyCredentialService) Get(ctx context.Context, id uuid.UUID) (SSHKeyCredentialSummary, error) {
	row, err := s.store.GetSSHKeyCredentialByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SSHKeyCredentialSummary{}, ErrNotFound
		}
		return SSHKeyCredentialSummary{}, fmt.Errorf("load ssh key credential: %w", err)
	}
	count, err := s.store.CountVMsBySSHKeyCredential(ctx, pgutil.NullUUID(&id))
	if err != nil {
		return SSHKeyCredentialSummary{}, fmt.Errorf("count vms using ssh key credential: %w", err)
	}
	return summaryFromRow(row, count), nil
}

// List returns every credential in workspaceID, each annotated with how
// many VMs currently reference it.
func (s *SSHKeyCredentialService) List(ctx context.Context, workspaceID uuid.UUID) ([]SSHKeyCredentialSummary, error) {
	rows, err := s.store.ListSSHKeyCredentialsByWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("list ssh key credentials: %w", err)
	}
	out := make([]SSHKeyCredentialSummary, 0, len(rows))
	for _, row := range rows {
		out = append(out, summaryFromRow(generated.SshKeyCredential{
			ID: row.ID, WorkspaceID: row.WorkspaceID, Name: row.Name, EncryptedPrivateKey: row.EncryptedPrivateKey,
			Fingerprint: row.Fingerprint, CreatedBy: row.CreatedBy, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		}, row.InUseCount))
	}
	return out, nil
}

// GetSigner decrypts and parses the stored key into an ssh.Signer for
// immediate use -- the ONLY method that ever touches plaintext key
// material, mirroring CredentialService.GetSSHSigner's exact discipline.
func (s *SSHKeyCredentialService) GetSigner(ctx context.Context, id uuid.UUID) (ssh.Signer, error) {
	row, err := s.store.GetSSHKeyCredentialByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCredentialNotConfigured
		}
		return nil, fmt.Errorf("load ssh key credential: %w", err)
	}
	plaintext, err := s.encryption.Decrypt(string(row.EncryptedPrivateKey))
	if err != nil {
		// Never include the error's underlying detail beyond "decrypt
		// failed" -- it could theoretically echo ciphertext fragments.
		return nil, fmt.Errorf("decrypt stored credential: authentication failed")
	}
	signer, err := ssh.ParsePrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: stored key no longer parses", ErrInvalidSSHKey)
	}
	return signer, nil
}

// Rename validates the new name and updates it; a collision with another
// credential in the same workspace surfaces as ErrDuplicateName.
func (s *SSHKeyCredentialService) Rename(ctx context.Context, id uuid.UUID, newName string) (SSHKeyCredentialSummary, error) {
	trimmedName, err := validateName("SSH key credential name", newName)
	if err != nil {
		return SSHKeyCredentialSummary{}, err
	}
	row, err := s.store.RenameSSHKeyCredential(ctx, generated.RenameSSHKeyCredentialParams{ID: id, Name: trimmedName})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SSHKeyCredentialSummary{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return SSHKeyCredentialSummary{}, fmt.Errorf("%w: a credential named %q already exists in this workspace", ErrDuplicateName, trimmedName)
		}
		return SSHKeyCredentialSummary{}, fmt.Errorf("rename ssh key credential: %w", err)
	}
	count, err := s.store.CountVMsBySSHKeyCredential(ctx, pgutil.NullUUID(&id))
	if err != nil {
		return SSHKeyCredentialSummary{}, fmt.Errorf("count vms using ssh key credential: %w", err)
	}
	return summaryFromRow(row, count), nil
}

// Delete blocks deletion while any VM still references id -- cascading to
// keyless would silently strip SSH access from a VM the admin didn't
// touch, a worse failure mode for a security credential than a blocked
// delete. Mirrors WorkspaceService.Delete's exact block-on-dependents
// precedent.
func (s *SSHKeyCredentialService) Delete(ctx context.Context, id uuid.UUID) error {
	if _, err := s.store.GetSSHKeyCredentialByID(ctx, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("load ssh key credential: %w", err)
	}
	count, err := s.store.CountVMsBySSHKeyCredential(ctx, pgutil.NullUUID(&id))
	if err != nil {
		return fmt.Errorf("count vms using ssh key credential: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("%w: this SSH key is attached to %d VM(s) -- detach it from every VM first", ErrHasDependencies, count)
	}
	if err := s.store.DeleteSSHKeyCredential(ctx, id); err != nil {
		return fmt.Errorf("delete ssh key credential: %w", err)
	}
	return nil
}
