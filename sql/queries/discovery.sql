-- name: CreateDiscoveryRun :one
INSERT INTO vm_discovery_runs (vm_id, status)
VALUES ($1, 'RUNNING')
RETURNING *;

-- name: CompleteDiscoveryRun :one
UPDATE vm_discovery_runs
SET status = $2, completed_at = now(), error_summary = $3
WHERE id = $1
RETURNING *;

-- name: ListDiscoveryRunsByVM :many
SELECT * FROM vm_discovery_runs
WHERE vm_id = $1
ORDER BY started_at DESC
LIMIT $2;

-- name: GetLatestDiscoveryRun :one
SELECT * FROM vm_discovery_runs
WHERE vm_id = $1
ORDER BY started_at DESC
LIMIT 1;
