-- Agent-token authentication for InfraHub's per-VM Docker agent (see
-- /docker-agent at the repo root and migration 041_docker_agent.sql).
-- Only a SHA-256 hash of the token is ever stored; the plaintext token is
-- shown to the admin exactly once, at generation time, and never
-- persisted. Mirrors sql/queries/k8s_agent.sql exactly.

-- name: UpsertDockerAgentToken :one
-- Configuring or regenerating a VM's agent token replaces any previous
-- one outright -- a VM has exactly one live token at a time, and the old
-- one stops authenticating immediately.
INSERT INTO docker_agent_tokens (vm_resource_id, token_hash)
VALUES ($1, $2)
ON CONFLICT (vm_resource_id) DO UPDATE SET
    token_hash = EXCLUDED.token_hash, last_connected_at = NULL
RETURNING *;

-- name: GetVMResourceIDByDockerAgentTokenHash :one
-- The agent WebSocket endpoint's own authentication lookup -- resolves a
-- presented token's hash straight to the VM resource it authenticates,
-- without a separate "load token, then load VM" round trip.
SELECT t.vm_resource_id FROM docker_agent_tokens t
JOIN resources r ON r.id = t.vm_resource_id
WHERE t.token_hash = $1 AND r.deleted_at IS NULL;

-- name: UpdateDockerAgentTokenLastConnected :exec
UPDATE docker_agent_tokens SET last_connected_at = now() WHERE vm_resource_id = $1;

-- name: HasDockerAgentToken :one
SELECT EXISTS(SELECT 1 FROM docker_agent_tokens WHERE vm_resource_id = $1);

-- name: GetDockerAgentTokenByVMResourceID :one
SELECT * FROM docker_agent_tokens WHERE vm_resource_id = $1;

-- name: SetVMDockerAgentInstalled :one
-- Recorded once the SSH-based installer finishes successfully -- version
-- is whatever the freshly-installed binary reports on its first
-- engine_version round trip, not just "some version was pushed".
UPDATE vms SET docker_agent_installed = true, docker_agent_version = $2
WHERE resource_id = $1
RETURNING *;

-- name: UpdateVMDockerAgentHeartbeat :one
-- Called whenever the agent's WebSocket connects (mirrors
-- UpdateK8sClusterAgentTokenLastConnected's role, but on the vms row
-- itself since "last heartbeat" is surfaced right on the VM's own
-- Monitoring tab, not a separate cluster-list page).
UPDATE vms SET docker_agent_last_heartbeat_at = now()
WHERE resource_id = $1
RETURNING *;
