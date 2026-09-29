package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/repository"
)

// ErrPassphraseProtectedKey is returned when the supplied private key is
// encrypted. See CredentialService's doc comment for why this step
// doesn't support it.
var ErrPassphraseProtectedKey = errors.New("passphrase-protected SSH keys are not currently supported")

// ErrInvalidSSHKey is returned when the supplied data doesn't parse as any
// private key format the SSH library understands.
var ErrInvalidSSHKey = errors.New("invalid SSH private key")

// ErrCredentialNotConfigured is returned when an operation needs a
// credential that hasn't been configured yet.
var ErrCredentialNotConfigured = errors.New("SSH credential not configured")

// CredentialService encrypts SSH private keys before they ever reach
// PostgreSQL and decrypts them only in memory, only when a caller needs to
// establish a connection (SSHService). It never returns raw key bytes or
// logs decrypted material -- see docs/ssh-architecture.md.
//
// Passphrase-protected keys: not supported in this step (Step 5 spec §10
// allows deferring this with a clear error rather than silently failing).
// The credential model already anticipates it -- credentials.credential_type
// has room for a future SSH_PRIVATE_KEY_PASSPHRASE row stored and encrypted
// exactly like SSH_PRIVATE_KEY is now -- but wiring a passphrase through
// the connection flow is left to a later step. StoreSSHPrivateKey detects
// an encrypted key via ssh.ParsePrivateKey's *ssh.PassphraseMissingError
// and returns ErrPassphraseProtectedKey rather than silently accepting a
// key it can't actually use to connect.
type CredentialService struct {
	store      *repository.Store
	encryption *EncryptionService
}

// NewCredentialService creates a CredentialService.
func NewCredentialService(store *repository.Store, encryption *EncryptionService) *CredentialService {
	return &CredentialService{store: store, encryption: encryption}
}

// ParseSSHPrivateKey validates pemBytes as an unencrypted SSH private key,
// returning ErrPassphraseProtectedKey or ErrInvalidSSHKey (never a raw
// x/crypto/ssh parser error) on failure. Shared by every place in this
// codebase that accepts a raw private key from a caller: StoreSSHPrivateKey
// below, SSHKeyCredentialService.Create, and VM Console's ephemeral-key
// path (vm_console.go).
func ParseSSHPrivateKey(pemBytes []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		var passphraseErr *ssh.PassphraseMissingError
		if errors.As(err, &passphraseErr) {
			return nil, ErrPassphraseProtectedKey
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidSSHKey, err)
	}
	return signer, nil
}

// StoreSSHPrivateKey validates, encrypts, and (re)stores the SSH private
// key for resourceID, replacing any existing one. Replacement is atomic:
// the old row is deleted and the new one inserted in the same transaction,
// so a failure never leaves two credentials -- or a half-written one --
// behind.
func (s *CredentialService) StoreSSHPrivateKey(ctx context.Context, resourceID uuid.UUID, privateKeyPEM []byte) error {
	if _, err := ParseSSHPrivateKey(privateKeyPEM); err != nil {
		return err
	}

	encrypted, err := s.encryption.Encrypt(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	return s.store.WithTx(ctx, func(q *generated.Queries) error {
		existing, err := q.GetCredentialByResourceAndType(ctx, generated.GetCredentialByResourceAndTypeParams{
			ResourceID: resourceID, CredentialType: "SSH_PRIVATE_KEY",
		})
		if err == nil {
			if err := q.DeleteCredential(ctx, existing.ID); err != nil {
				return fmt.Errorf("remove previous credential: %w", err)
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("check existing credential: %w", err)
		}

		if _, err := q.CreateCredential(ctx, generated.CreateCredentialParams{
			ResourceID:     resourceID,
			CredentialType: "SSH_PRIVATE_KEY",
			EncryptedData:  []byte(encrypted),
		}); err != nil {
			return fmt.Errorf("store credential: %w", err)
		}
		return nil
	})
}

// GetSSHSigner decrypts the stored private key and parses it into an
// ssh.Signer for immediate use in an ssh.ClientConfig. It is the only
// method that touches plaintext key material, and it never leaves this
// service: callers get a signer they can use to authenticate, not the key
// bytes themselves.
func (s *CredentialService) GetSSHSigner(ctx context.Context, resourceID uuid.UUID) (ssh.Signer, error) {
	cred, err := s.store.GetCredentialByResourceAndType(ctx, generated.GetCredentialByResourceAndTypeParams{
		ResourceID: resourceID, CredentialType: "SSH_PRIVATE_KEY",
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCredentialNotConfigured
		}
		return nil, fmt.Errorf("load credential: %w", err)
	}

	plaintext, err := s.encryption.Decrypt(string(cred.EncryptedData))
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

// HasSSHCredential reports whether resourceID has a configured SSH
// private key, without touching its contents.
func (s *CredentialService) HasSSHCredential(ctx context.Context, resourceID uuid.UUID) (bool, error) {
	return s.store.HasSSHCredentialConfigured(ctx, resourceID)
}

// DeleteCredential removes the SSH private key for resourceID. Idempotent.
func (s *CredentialService) DeleteCredential(ctx context.Context, resourceID uuid.UUID) error {
	cred, err := s.store.GetCredentialByResourceAndType(ctx, generated.GetCredentialByResourceAndTypeParams{
		ResourceID: resourceID, CredentialType: "SSH_PRIVATE_KEY",
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("load credential: %w", err)
	}
	if err := s.store.DeleteCredential(ctx, cred.ID); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	return nil
}
