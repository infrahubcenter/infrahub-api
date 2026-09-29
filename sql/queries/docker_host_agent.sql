-- Agent-token authentication for a standalone Docker Host (mirrors
-- sql/queries/k8s_agent.sql exactly). Only a SHA-256 hash of the token is
-- ever stored; the plaintext token is shown to the admin exactly once, at
-- generation time, and never persisted.

-- name: UpsertDockerHostAgentToken :one
-- Configuring or regenerating a host's agent token replaces any previous
-- one outright -- a host has exactly one live token at a time, and the
-- old one stops authenticating immediately.
INSERT INTO docker_host_agent_tokens (docker_host_id, token_hash)
VALUES ($1, $2)
ON CONFLICT (docker_host_id) DO UPDATE SET
    token_hash = EXCLUDED.token_hash, last_connected_at = NULL
RETURNING *;

-- name: GetDockerHostByAgentTokenHash :one
-- The agent WebSocket endpoint's own authentication lookup -- resolves a
-- presented token's hash straight to the host it authenticates, without a
-- separate "load token, then load host" round trip.
SELECT dh.* FROM docker_hosts dh
JOIN docker_host_agent_tokens t ON t.docker_host_id = dh.id
WHERE t.token_hash = $1 AND dh.deleted_at IS NULL;

-- name: UpdateDockerHostAgentTokenLastConnectedByResourceID :exec
-- Keyed by resources.id (not docker_hosts.id) so DockerHostAgentTokenService.
-- MarkConnected can share the exact same signature shape as
-- DockerAgentTokenService.MarkConnected(vmResourceID) -- DockerAgentHandler.
-- Connect calls whichever token service actually matched identically.
UPDATE docker_host_agent_tokens t
SET last_connected_at = now()
FROM docker_hosts h
WHERE t.docker_host_id = h.id AND h.resource_id = $1;

-- name: HasDockerHostAgentToken :one
SELECT EXISTS(SELECT 1 FROM docker_host_agent_tokens WHERE docker_host_id = $1);
