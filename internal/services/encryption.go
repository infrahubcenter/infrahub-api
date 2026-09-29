package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const aes256KeyLen = 32 // AES-256

// EncryptionService implements application-level AES-256-GCM encryption
// for values that must never be stored in plaintext (SSH private keys --
// see CredentialService). The key never touches PostgreSQL: it comes from
// SSH_CREDENTIAL_ENCRYPTION_KEY (see internal/config), an environment
// variable never committed to git.
//
// Storage format: base64( nonce || ciphertext‖tag ). GCM's nonce is
// public by design -- it does not need to be secret, only unique per
// encryption under the same key, which crypto/rand guarantees with
// overwhelming probability. Encrypt prepends a freshly random nonce to
// every ciphertext, so no reused-nonce state has to be tracked; Decrypt
// reads it back off the front of the blob.
type EncryptionService struct {
	gcm cipher.AEAD
}

// NewEncryptionService builds an EncryptionService from a base64-encoded
// 32-byte key (e.g. the output of `openssl rand -base64 32`).
func NewEncryptionService(base64Key string) (*EncryptionService, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}
	if len(key) != aes256KeyLen {
		return nil, fmt.Errorf("encryption key must decode to %d bytes, got %d", aes256KeyLen, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &EncryptionService{gcm: gcm}, nil
}

// Encrypt returns a base64 string encoding nonce‖ciphertext‖tag. Safe to
// store directly in credentials.encrypted_data.
func (s *EncryptionService) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	sealed := s.gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt. Returns an error (never a partial/garbage
// plaintext) if the ciphertext was tampered with or the key is wrong --
// GCM authenticates on every call.
func (s *EncryptionService) Decrypt(encoded string) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	nonceSize := s.gcm.NonceSize()
	if len(sealed) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]

	plaintext, err := s.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: authentication failed")
	}
	return plaintext, nil
}

// GenerateEncryptionKey returns a fresh base64-encoded 32-byte key, for
// `go run ./cmd/gen-encryption-key` to print during local setup.
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, aes256KeyLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
