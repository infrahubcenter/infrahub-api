-- Agent-token authentication and metric storage for InfraHub's push-based
-- VM Agent (see /vm-agent at the repo root and migration
-- 052_vm_agent.sql). Only a SHA-256 hash of the token is ever stored;
-- mirrors sql/queries/docker_agent.sql exactly for the token half.

-- name: UpsertVMAgentToken :one
INSERT INTO vm_agent_tokens (vm_resource_id, token_hash)
VALUES ($1, $2)
ON CONFLICT (vm_resource_id) DO UPDATE SET
    token_hash = EXCLUDED.token_hash, last_connected_at = NULL
RETURNING *;

-- name: GetVMResourceIDByVMAgentTokenHash :one
SELECT t.vm_resource_id FROM vm_agent_tokens t
JOIN resources r ON r.id = t.vm_resource_id
WHERE t.token_hash = $1 AND r.deleted_at IS NULL;

-- name: UpdateVMAgentTokenLastConnected :exec
UPDATE vm_agent_tokens SET last_connected_at = now() WHERE vm_resource_id = $1;

-- name: HasVMAgentToken :one
SELECT EXISTS(SELECT 1 FROM vm_agent_tokens WHERE vm_resource_id = $1);

-- name: SetVMAgentInstalled :one
-- Recorded once the SSH-based installer finishes successfully -- version
-- is whatever the freshly-installed binary reports on its first
-- metrics_push, not just "some version was pushed" (mirrors
-- SetVMDockerAgentInstalled).
UPDATE vms SET vm_agent_installed = true, vm_agent_version = $2
WHERE resource_id = $1
RETURNING *;

-- name: UpdateVMAgentHeartbeat :one
-- Called on every metrics_push, not just on connect -- "last heartbeat"
-- for this push-based agent means "last time it actually sent data", a
-- stronger liveness signal than the Docker agent's connect-time-only
-- heartbeat (that one is pull-based, so a live connection already implies
-- liveness; a stalled push-side goroutine here would otherwise still show
-- as falsely alive from connect time alone).
--
-- Also sets vm_agent_installed = true unconditionally: SetVMAgentInstalled
-- (vm_agent_install.go) only runs at the end of the SSH-based automated
-- installer, so an agent brought up any other way (the manual/"Show
-- Manual Command" reveal, or an agent-only "Connect VM" VM, which has
-- no SSH path to run that installer over at all) would otherwise show
-- "Not Installed" forever no matter how many real samples it pushes.
-- A successful metrics_push is the strongest possible proof this agent
-- is actually installed and running -- stronger than any installer
-- having merely been *attempted* -- so it's the right place to flip
-- this, regardless of how the agent got there.
--
-- Host identity (os/os_version/kernel_version/hostname, migrations/
-- 060_vm_agent_host_identity.sql) uses COALESCE against the existing
-- value rather than unconditionally overwriting with NULL -- an older
-- agent binary that hasn't been upgraded yet simply doesn't send these
-- fields, and keeping a real (if stale) previous value beats erasing it.
UPDATE vms SET
    vm_agent_last_heartbeat_at = now(), vm_agent_installed = true,
    vm_agent_os = COALESCE(sqlc.narg('vm_agent_os'), vm_agent_os),
    vm_agent_os_version = COALESCE(sqlc.narg('vm_agent_os_version'), vm_agent_os_version),
    vm_agent_kernel_version = COALESCE(sqlc.narg('vm_agent_kernel_version'), vm_agent_kernel_version),
    vm_agent_hostname = COALESCE(sqlc.narg('vm_agent_hostname'), vm_agent_hostname)
WHERE resource_id = $1
RETURNING *;

-- name: InsertVMAgentMetricSnapshot :one
INSERT INTO vm_agent_metric_snapshots (
    vm_id, cpu_percent, cpu_cores, memory_used_bytes, memory_total_bytes,
    swap_used_bytes, swap_total_bytes, load_1m, load_5m, load_15m, uptime_seconds,
    storage_used_bytes, storage_total_bytes, network_rx_rate_bytes, network_tx_rate_bytes,
    process_count
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
) RETURNING *;

-- name: GetLatestVMAgentMetricSnapshot :one
SELECT * FROM vm_agent_metric_snapshots
WHERE vm_id = $1
ORDER BY captured_at DESC
LIMIT 1;

-- name: ListVMAgentMetricSnapshotsSince :many
SELECT * FROM vm_agent_metric_snapshots
WHERE vm_id = $1 AND captured_at >= $2
ORDER BY captured_at ASC;
