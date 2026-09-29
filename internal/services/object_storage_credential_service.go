package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/repository"
)

// StandaloneObjectStorageCredentialService stores/retrieves standalone
// object storage monitoring credentials: a dedicated
// `standalone_object_storage_credentials` table, reusing the exact same
// AES-256-GCM EncryptionService (Step 5, unchanged, keyed by
// SSH_CREDENTIAL_ENCRYPTION_KEY) for the encrypted blob -- never stores
// plaintext, never returned by any API. Mirrors
// StandaloneDatabaseCredentialService exactly, minus the username field:
// access_key_id is not a secret and stays plaintext on object_storages
// itself (migration 005).
type StandaloneObjectStorageCredentialService struct {
	store      *repository.Store
	encryption *EncryptionService
}

// NewStandaloneObjectStorageCredentialService creates a
// StandaloneObjectStorageCredentialService.
func NewStandaloneObjectStorageCredentialService(store *repository.Store, encryption *EncryptionService) *StandaloneObjectStorageCredentialService {
	return &StandaloneObjectStorageCredentialService{store: store, encryption: encryption}
}

// SetSecretKey encrypts and stores/replaces the monitoring secret access
// key for a standalone object storage.
func (s *StandaloneObjectStorageCredentialService) SetSecretKey(ctx context.Context, objectStorageID uuid.UUID, secretAccessKey string) error {
	encrypted, err := s.encryption.Encrypt([]byte(secretAccessKey))
	if err != nil {
		return fmt.Errorf("encrypt object storage credential: %w", err)
	}
	_, err = s.store.UpsertStandaloneObjectStorageCredential(ctx, generated.UpsertStandaloneObjectStorageCredentialParams{
		ObjectStorageID: objectStorageID, EncryptedSecretKey: []byte(encrypted),
	})
	if err != nil {
		return fmt.Errorf("store object storage credential: %w", err)
	}
	return nil
}

// GetSecretKey decrypts and returns the stored secret access key -- never
// exposed through any API response, only used internally to build a
// direct S3 connection.
func (s *StandaloneObjectStorageCredentialService) GetSecretKey(ctx context.Context, objectStorageID uuid.UUID) (string, error) {
	row, err := s.store.GetStandaloneObjectStorageCredential(ctx, objectStorageID)
	if err != nil {
		return "", err
	}
	plaintext, err := s.encryption.Decrypt(string(row.EncryptedSecretKey))
	if err != nil {
		return "", fmt.Errorf("decrypt object storage credential: %w", err)
	}
	return string(plaintext), nil
}

// HasSecretKey reports whether a monitoring secret access key is
// configured, without decrypting it -- used by the UI's
// "Secret Key: ••••••••" display, which must never receive the actual
// secret.
func (s *StandaloneObjectStorageCredentialService) HasSecretKey(ctx context.Context, objectStorageID uuid.UUID) (bool, error) {
	_, err := s.store.GetStandaloneObjectStorageCredential(ctx, objectStorageID)
	if err != nil {
		return false, nil
	}
	return true, nil
}
