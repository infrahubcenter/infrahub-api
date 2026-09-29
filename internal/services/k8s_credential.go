// Package services: k8s_credential.go issues and verifies the bearer
// tokens InfraHub's in-cluster K8s agent (see /k8s-agent at the repo
// root) authenticates its outbound WebSocket connection with. This
// replaces the earlier kubeconfig-upload model outright (migration 035):
// InfraHub's backend never holds cluster-admin credentials and never
// needs inbound network access to a cluster's API server -- the agent
// runs inside the cluster using its own in-cluster ServiceAccount, and
// dials OUT.
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

// ErrInvalidK8sAgentToken means the bearer token an agent presented on
// connect doesn't match any cluster's current token -- either it was
// never issued, or it was superseded by a later GenerateToken call.
var ErrInvalidK8sAgentToken = errors.New("invalid or unknown agent token")

const k8sAgentTokenPrefix = "infrahub_k8s_"

// K8sAgentTokenService issues/verifies agent bearer tokens. Only a
// SHA-256 hash is ever stored -- the plaintext token is returned exactly
// once, at generation time, exactly like every other "show once"
// credential in this app.
type K8sAgentTokenService struct {
	store *repository.Store
}

// NewK8sAgentTokenService creates a K8sAgentTokenService.
func NewK8sAgentTokenService(store *repository.Store) *K8sAgentTokenService {
	return &K8sAgentTokenService{store: store}
}

func hashK8sAgentToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// GenerateToken creates (or replaces) clusterID's agent token, returning
// the plaintext exactly this once. Replacing a token immediately
// invalidates whatever the agent was previously using -- it must be
// reconfigured with the new token to reconnect.
func (s *K8sAgentTokenService) GenerateToken(ctx context.Context, clusterID uuid.UUID) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := k8sAgentTokenPrefix + hex.EncodeToString(raw)
	if _, err := s.store.UpsertK8sClusterAgentToken(ctx, generated.UpsertK8sClusterAgentTokenParams{
		K8sClusterID: clusterID, TokenHash: hashK8sAgentToken(token),
	}); err != nil {
		return "", fmt.Errorf("store agent token: %w", err)
	}
	return token, nil
}

// ClusterIDForToken resolves a presented bearer token to the cluster it
// authenticates -- the agent WebSocket endpoint's own auth check.
func (s *K8sAgentTokenService) ClusterIDForToken(ctx context.Context, token string) (uuid.UUID, error) {
	cluster, err := s.store.GetK8sClusterByAgentTokenHash(ctx, hashK8sAgentToken(token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrInvalidK8sAgentToken
		}
		return uuid.Nil, err
	}
	return cluster.ID, nil
}

// HasToken reports whether a cluster has ever had an agent token issued.
func (s *K8sAgentTokenService) HasToken(ctx context.Context, clusterID uuid.UUID) (bool, error) {
	return s.store.HasK8sClusterAgentToken(ctx, clusterID)
}

// MarkConnected records that clusterID's agent just connected -- purely
// informational (surfaced as "last connected" in the cluster list), never
// used for authorization.
func (s *K8sAgentTokenService) MarkConnected(ctx context.Context, clusterID uuid.UUID) error {
	return s.store.UpdateK8sClusterAgentTokenLastConnected(ctx, clusterID)
}
