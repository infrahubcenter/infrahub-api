// Package services: vm_agent_token.go issues and verifies the bearer
// tokens InfraHub's push-based VM Agent (see /vm-agent at the repo root)
// authenticates its outbound WebSocket connection with. Mirrors
// docker_agent_token.go exactly, keyed by vm_resource_id.
package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/repository"
)

// ErrInvalidVMAgentToken means the bearer token an agent presented on
// connect doesn't match any VM's current token.
var ErrInvalidVMAgentToken = errors.New("invalid or unknown agent token")

const vmAgentTokenPrefix = "infrahub_vmagent_"

// VMAgentTokenService issues/verifies VM Agent bearer tokens. Only a
// SHA-256 hash is ever stored -- the plaintext token is returned exactly
// once, at generation time.
type VMAgentTokenService struct {
	store *repository.Store
}

// NewVMAgentTokenService creates a VMAgentTokenService.
func NewVMAgentTokenService(store *repository.Store) *VMAgentTokenService {
	return &VMAgentTokenService{store: store}
}

func hashVMAgentToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// GenerateToken creates (or replaces) vmResourceID's agent token,
// returning the plaintext exactly this once.
func (s *VMAgentTokenService) GenerateToken(ctx context.Context, vmResourceID uuid.UUID) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := vmAgentTokenPrefix + hex.EncodeToString(raw)
	if _, err := s.store.UpsertVMAgentToken(ctx, generated.UpsertVMAgentTokenParams{
		VmResourceID: vmResourceID, TokenHash: hashVMAgentToken(token),
	}); err != nil {
		return "", fmt.Errorf("store agent token: %w", err)
	}
	return token, nil
}

// VMResourceIDForToken resolves a presented bearer token to the VM
// resource it authenticates -- the agent WebSocket endpoint's own auth
// check.
func (s *VMAgentTokenService) VMResourceIDForToken(ctx context.Context, token string) (uuid.UUID, error) {
	vmResourceID, err := s.store.GetVMResourceIDByVMAgentTokenHash(ctx, hashVMAgentToken(token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrInvalidVMAgentToken
		}
		return uuid.Nil, err
	}
	return vmResourceID, nil
}

// HasToken reports whether a VM has ever had an agent token issued.
func (s *VMAgentTokenService) HasToken(ctx context.Context, vmResourceID uuid.UUID) (bool, error) {
	return s.store.HasVMAgentToken(ctx, vmResourceID)
}

// MarkConnected records that vmResourceID's agent just connected --
// updates the token's own last_connected_at. The vms row's own
// vm_agent_last_heartbeat_at is updated separately, on every metrics_push
// (see VMAgentService.HandleMetricsPush), a stronger liveness signal than
// connect-time alone for a push-based agent.
func (s *VMAgentTokenService) MarkConnected(ctx context.Context, vmResourceID uuid.UUID) error {
	return s.store.UpdateVMAgentTokenLastConnected(ctx, vmResourceID)
}
