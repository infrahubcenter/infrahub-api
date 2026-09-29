package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// StandaloneDatabaseCredentialService stores/retrieves standalone
// database monitoring credentials (spec §8/§14): a dedicated
// `standalone_database_credentials` table, reusing the exact same
// AES-256-GCM EncryptionService (Step 5, unchanged) for the encrypted
// blob -- never stores plaintext, never returned by any API.
type StandaloneDatabaseCredentialService struct {
	store      *repository.Store
	encryption *EncryptionService
}

// NewStandaloneDatabaseCredentialService creates a
// StandaloneDatabaseCredentialService.
func NewStandaloneDatabaseCredentialService(store *repository.Store, encryption *EncryptionService) *StandaloneDatabaseCredentialService {
	return &StandaloneDatabaseCredentialService{store: store, encryption: encryption}
}

// SetCredential encrypts and stores/replaces the monitoring username +
// password for a standalone database.
func (s *StandaloneDatabaseCredentialService) SetCredential(ctx context.Context, databaseID uuid.UUID, username, password string) error {
	encrypted, err := s.encryption.Encrypt([]byte(password))
	if err != nil {
		return fmt.Errorf("encrypt database credential: %w", err)
	}
	_, err = s.store.UpsertStandaloneDatabaseCredential(ctx, generated.UpsertStandaloneDatabaseCredentialParams{
		DatabaseID: databaseID, Username: pgutil.Text(username), EncryptedPassword: []byte(encrypted),
	})
	if err != nil {
		return fmt.Errorf("store database credential: %w", err)
	}
	return nil
}

// GetCredential decrypts and returns the stored username/password --
// never exposed through any API response, only used internally to build
// a direct connection.
func (s *StandaloneDatabaseCredentialService) GetCredential(ctx context.Context, databaseID uuid.UUID) (username, password string, err error) {
	row, err := s.store.GetStandaloneDatabaseCredential(ctx, databaseID)
	if err != nil {
		return "", "", err
	}
	plaintext, err := s.encryption.Decrypt(string(row.EncryptedPassword))
	if err != nil {
		return "", "", fmt.Errorf("decrypt database credential: %w", err)
	}
	return pgutil.TextOrEmpty(row.Username), string(plaintext), nil
}

// HasCredential reports whether a monitoring credential is configured,
// without decrypting it -- used by the UI's "Username: monitoring /
// Password: ••••••••" display, which must never receive the actual secret.
func (s *StandaloneDatabaseCredentialService) HasCredential(ctx context.Context, databaseID uuid.UUID) (username string, configured bool) {
	row, err := s.store.GetStandaloneDatabaseCredential(ctx, databaseID)
	if err != nil {
		return "", false
	}
	return pgutil.TextOrEmpty(row.Username), true
}
