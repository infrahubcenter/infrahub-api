// Package services: docker_host_token.go issues and verifies the bearer
// tokens a standalone Docker Host's agent authenticates its outbound
// WebSocket connection with -- mirrors k8s_credential.go
// (K8sAgentTokenService) exactly, keyed by docker_hosts.id instead of
// k8s_clusters.id. Unlike a VM's docker agent (docker_agent_token.go,
// keyed directly by resources.id since a VM's own resource_id already
// exists), a Docker Host has its own detail table with its own PK, same
// shape as K8sAgentTokenService/k8s_clusters.
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

// ErrInvalidDockerHostAgentToken means the bearer token an agent presented
// on connect doesn't match any Docker Host's current token -- either it
// was never issued, or it was superseded by a later GenerateToken call.
var ErrInvalidDockerHostAgentToken = errors.New("invalid or unknown agent token")

const dockerHostAgentTokenPrefix = "infrahub_dockerhost_"

// DockerHostAgentTokenService issues/verifies agent bearer tokens for
// standalone Docker Hosts. Only a SHA-256 hash is ever stored -- the
// plaintext token is returned exactly once, at generation time.
type DockerHostAgentTokenService struct {
	store *repository.Store
}

// NewDockerHostAgentTokenService creates a DockerHostAgentTokenService.
func NewDockerHostAgentTokenService(store *repository.Store) *DockerHostAgentTokenService {
	return &DockerHostAgentTokenService{store: store}
}

func hashDockerHostAgentToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// GenerateToken creates (or replaces) hostID's agent token, returning the
// plaintext exactly this once. Replacing a token immediately invalidates
// whatever the agent was previously using -- it must be reconfigured with
// the new token to reconnect.
func (s *DockerHostAgentTokenService) GenerateToken(ctx context.Context, hostID uuid.UUID) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := dockerHostAgentTokenPrefix + hex.EncodeToString(raw)
	if _, err := s.store.UpsertDockerHostAgentToken(ctx, generated.UpsertDockerHostAgentTokenParams{
		DockerHostID: hostID, TokenHash: hashDockerHostAgentToken(token),
	}); err != nil {
		return "", fmt.Errorf("store agent token: %w", err)
	}
	return token, nil
}

// ResourceIDForToken resolves a presented bearer token to the resource id
// (docker_hosts.resource_id) it authenticates -- deliberately the same
// return shape as DockerAgentTokenService.VMResourceIDForToken, so
// DockerAgentHandler.Connect can register with the hub identically
// regardless of which token service actually matched.
func (s *DockerHostAgentTokenService) ResourceIDForToken(ctx context.Context, token string) (uuid.UUID, error) {
	host, err := s.store.GetDockerHostByAgentTokenHash(ctx, hashDockerHostAgentToken(token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrInvalidDockerHostAgentToken
		}
		return uuid.Nil, err
	}
	return host.ResourceID, nil
}

// HasToken reports whether a host has ever had an agent token issued.
func (s *DockerHostAgentTokenService) HasToken(ctx context.Context, hostID uuid.UUID) (bool, error) {
	return s.store.HasDockerHostAgentToken(ctx, hostID)
}

// MarkConnected records that the agent for the host owning resourceID
// just connected -- purely informational, never used for authorization.
// Keyed by resource id (not docker_hosts.id) to match
// DockerAgentTokenService.MarkConnected's exact signature.
func (s *DockerHostAgentTokenService) MarkConnected(ctx context.Context, resourceID uuid.UUID) error {
	return s.store.UpdateDockerHostAgentTokenLastConnectedByResourceID(ctx, resourceID)
}
