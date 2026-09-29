// Package services: docker_agent_token.go issues and verifies the bearer
// tokens InfraHub's per-VM Docker agent (see /docker-agent at the repo
// root) authenticates its outbound WebSocket connection with. Mirrors
// k8s_credential.go exactly, keyed by vm_resource_id instead of
// k8s_cluster_id.
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

// ErrInvalidDockerAgentToken means the bearer token an agent presented on
// connect doesn't match any VM's current token -- either it was never
// issued, or it was superseded by a later GenerateToken call.
var ErrInvalidDockerAgentToken = errors.New("invalid or unknown agent token")

const dockerAgentTokenPrefix = "infrahub_docker_"

// DockerAgentTokenService issues/verifies agent bearer tokens. Only a
// SHA-256 hash is ever stored -- the plaintext token is returned exactly
// once, at generation time, exactly like every other "show once"
// credential in this app.
type DockerAgentTokenService struct {
	store *repository.Store
}

// NewDockerAgentTokenService creates a DockerAgentTokenService.
func NewDockerAgentTokenService(store *repository.Store) *DockerAgentTokenService {
	return &DockerAgentTokenService{store: store}
}

func hashDockerAgentToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// GenerateToken creates (or replaces) vmResourceID's agent token,
// returning the plaintext exactly this once. Replacing a token
// immediately invalidates whatever the agent was previously using -- it
// must be reconfigured with the new token to reconnect.
func (s *DockerAgentTokenService) GenerateToken(ctx context.Context, vmResourceID uuid.UUID) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := dockerAgentTokenPrefix + hex.EncodeToString(raw)
	if _, err := s.store.UpsertDockerAgentToken(ctx, generated.UpsertDockerAgentTokenParams{
		VmResourceID: vmResourceID, TokenHash: hashDockerAgentToken(token),
	}); err != nil {
		return "", fmt.Errorf("store agent token: %w", err)
	}
	return token, nil
}

// VMResourceIDForToken resolves a presented bearer token to the VM
// resource it authenticates -- the agent WebSocket endpoint's own auth
// check.
func (s *DockerAgentTokenService) VMResourceIDForToken(ctx context.Context, token string) (uuid.UUID, error) {
	vmResourceID, err := s.store.GetVMResourceIDByDockerAgentTokenHash(ctx, hashDockerAgentToken(token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrInvalidDockerAgentToken
		}
		return uuid.Nil, err
	}
	return vmResourceID, nil
}

// HasToken reports whether a VM has ever had an agent token issued.
func (s *DockerAgentTokenService) HasToken(ctx context.Context, vmResourceID uuid.UUID) (bool, error) {
	return s.store.HasDockerAgentToken(ctx, vmResourceID)
}

// MarkConnected records that vmResourceID's agent just connected --
// updates both the token's own last_connected_at (parity with the K8s
// agent token table) and the vms row's docker_agent_last_heartbeat_at
// (surfaced directly on the VM's own Monitoring tab).
func (s *DockerAgentTokenService) MarkConnected(ctx context.Context, vmResourceID uuid.UUID) error {
	if err := s.store.UpdateDockerAgentTokenLastConnected(ctx, vmResourceID); err != nil {
		return err
	}
	_, err := s.store.UpdateVMDockerAgentHeartbeat(ctx, vmResourceID)
	return err
}
