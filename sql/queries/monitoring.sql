-- name: InsertMonitoringSnapshot :one
INSERT INTO monitoring_snapshots (
    resource_id, status,
    cpu_usage_percent, cpu_user_percent, cpu_system_percent, cpu_iowait_percent, cpu_idle_percent, cpu_cores,
    cpu_raw_jiffies,
    memory_used_bytes, memory_total_bytes, swap_used_bytes, swap_total_bytes,
    storage_used_bytes, storage_total_bytes,
    network_rx_bytes, network_tx_bytes, network_rx_rate_bytes, network_tx_rate_bytes,
    load_1m, load_5m, load_15m, uptime_seconds,
    process_count, process_running_count, process_sleeping_count, process_zombie_count
) VALUES (
    $1, $2,
    $3, $4, $5, $6, $7, $8,
    $9,
    $10, $11, $12, $13,
    $14, $15,
    $16, $17, $18, $19,
    $20, $21, $22, $23,
    $24, $25, $26, $27
)
RETURNING *;

-- name: GetLatestMonitoringSnapshot :one
SELECT * FROM monitoring_snapshots
WHERE resource_id = $1
ORDER BY captured_at DESC
LIMIT 1;

-- name: ListRecentMonitoringSnapshots :many
-- Newest first. Used both to find the immediately-previous sample for
-- CPU/network delta math and as the small rolling window
-- cpuDimensionStatus (monitoring_health.go) uses to avoid flapping health
-- on a single CPU spike (Step 6 spec §23).
SELECT * FROM monitoring_snapshots
WHERE resource_id = $1
ORDER BY captured_at DESC
LIMIT $2;

-- name: ListMonitoringSnapshotsByResourceRange :many
SELECT * FROM monitoring_snapshots
WHERE resource_id = $1 AND captured_at >= $2 AND captured_at <= $3
ORDER BY captured_at DESC
LIMIT $4;

-- name: DeleteOldMonitoringSnapshots :exec
DELETE FROM monitoring_snapshots WHERE captured_at < $1;

-- name: ListLatestMonitoringStatusByResourceIDs :many
-- Batched counterpart to GetLatestMonitoringSnapshot -- one row per
-- resource_id, its most recent snapshot's status/captured_at -- feeding
-- services.DeriveDisplayHealth per VM for Step 19's dashboard (Overview's
-- health-bucket tally and Resources' per-row health field) without an
-- N+1 GetLatestMonitoringSnapshot call per VM.
SELECT DISTINCT ON (resource_id) resource_id, status, captured_at
FROM monitoring_snapshots
WHERE resource_id = ANY(sqlc.arg('resource_ids')::uuid[])
ORDER BY resource_id, captured_at DESC;

-- name: InsertVMFilesystemSnapshot :one
INSERT INTO vm_filesystems (
    vm_id, mount_point, filesystem, total_bytes, used_bytes, available_bytes, usage_percent
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ListVMFilesystemsByVM :many
SELECT * FROM vm_filesystems
WHERE vm_id = $1
ORDER BY captured_at DESC, mount_point;

-- name: ListLatestVMFilesystems :many
-- The most recent snapshot row for every mount point currently known on
-- this VM (Step 6 spec #18/#28: filesystem detail is per-mount, not a
-- single aggregate, and belongs in this table rather than
-- monitoring_snapshots).
SELECT DISTINCT ON (mount_point) *
FROM vm_filesystems
WHERE vm_id = $1
ORDER BY mount_point, captured_at DESC;

-- name: DeleteOldVMFilesystems :exec
DELETE FROM vm_filesystems WHERE captured_at < $1;

-- name: InsertVMNetworkSnapshot :one
INSERT INTO vm_network_snapshots (
    vm_id, interface_name, rx_bytes, tx_bytes, rx_packets, tx_packets,
    rx_errors, tx_errors, rx_dropped, tx_dropped, rx_rate_bytes, tx_rate_bytes
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetPreviousVMNetworkSnapshot :one
-- The immediately-prior sample for one interface, read before inserting a
-- new one so the rate can be computed as a delta (Step 6 spec #25) --
-- never from a single cumulative-counter read.
SELECT * FROM vm_network_snapshots
WHERE vm_id = $1 AND interface_name = $2
ORDER BY captured_at DESC
LIMIT 1;

-- name: ListLatestVMNetworkSnapshots :many
SELECT DISTINCT ON (interface_name) *
FROM vm_network_snapshots
WHERE vm_id = $1
ORDER BY interface_name, captured_at DESC;

-- name: ListVMNetworkHistory :many
SELECT * FROM vm_network_snapshots
WHERE vm_id = $1 AND interface_name = $2 AND captured_at >= $3 AND captured_at <= $4
ORDER BY captured_at DESC
LIMIT $5;

-- name: DeleteOldVMNetworkSnapshots :exec
DELETE FROM vm_network_snapshots WHERE captured_at < $1;

-- name: CreateMonitoringRun :one
INSERT INTO vm_monitoring_runs (vm_id, status) VALUES ($1, 'RUNNING') RETURNING *;

-- name: CompleteMonitoringRun :one
UPDATE vm_monitoring_runs
SET status = $2, error_summary = $3, completed_at = now()
WHERE id = $1
RETURNING *;

-- name: ListMonitoringRunsByVM :many
SELECT * FROM vm_monitoring_runs
WHERE vm_id = $1
ORDER BY started_at DESC
LIMIT $2;

-- name: DeleteOldVMMonitoringRuns :exec
DELETE FROM vm_monitoring_runs WHERE started_at < $1;

-- name: ListMonitoringEnabledVMs :many
-- The scheduler's work list for one cycle: active, monitoring-enabled VMs
-- that actually have an SSH credential configured (Step 6 spec §7 step 3
-- -- there is no point queuing a job that can only fail at the very first
-- step). Deactivated resources (status = DISABLED) and monitoring_enabled
-- = false are both excluded (Step 6 spec §4/§57).
SELECT r.id AS resource_id, v.id AS vm_id, r.name, v.address, v.ssh_port
FROM resources r
JOIN vms v ON v.resource_id = r.id
WHERE r.resource_type = 'VM'
  AND r.deleted_at IS NULL
  AND r.status != 'DISABLED'
  AND r.monitoring_enabled = true
  AND v.ssh_key_credential_id IS NOT NULL
ORDER BY r.name;
