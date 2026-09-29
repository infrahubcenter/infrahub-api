-- Agent-token authentication for the in-cluster K8s agent (replaces
-- kubeconfig upload -- see migration 035). Only a SHA-256 hash of the
-- token is ever stored; the plaintext token is shown to the admin exactly
-- once, at generation time, and never persisted.

-- name: UpsertK8sClusterAgentToken :one
-- Configuring or regenerating a cluster's agent token replaces any
-- previous one outright -- a cluster has exactly one live token at a
-- time, and the old one stops authenticating immediately.
INSERT INTO k8s_cluster_agent_tokens (k8s_cluster_id, token_hash)
VALUES ($1, $2)
ON CONFLICT (k8s_cluster_id) DO UPDATE SET
    token_hash = EXCLUDED.token_hash, last_connected_at = NULL
RETURNING *;

-- name: GetK8sClusterByAgentTokenHash :one
-- The agent WebSocket endpoint's own authentication lookup -- resolves a
-- presented token's hash straight to the cluster it authenticates,
-- without a separate "load token, then load cluster" round trip.
SELECT kc.* FROM k8s_clusters kc
JOIN k8s_cluster_agent_tokens t ON t.k8s_cluster_id = kc.id
WHERE t.token_hash = $1 AND kc.deleted_at IS NULL;

-- name: UpdateK8sClusterAgentTokenLastConnected :exec
UPDATE k8s_cluster_agent_tokens SET last_connected_at = now() WHERE k8s_cluster_id = $1;

-- name: HasK8sClusterAgentToken :one
SELECT EXISTS(SELECT 1 FROM k8s_cluster_agent_tokens WHERE k8s_cluster_id = $1);
