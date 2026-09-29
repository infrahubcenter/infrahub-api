-- name: CreateOperation :one
INSERT INTO operations (resource_id, operation_type, requested_by, command_preview)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetOperationByID :one
SELECT * FROM operations WHERE id = $1;

-- name: ListOperationsByResource :many
SELECT * FROM operations WHERE resource_id = $1 ORDER BY created_at DESC;

-- name: UpdateOperationStatus :one
-- started_at is set on CONNECTING (first real contact with the VM);
-- completed_at covers every terminal status this step's state machine can
-- land on, including PARTIAL and INTERRUPTED (a backend-crash outcome,
-- never one the execution code itself sets deliberately).
UPDATE operations
SET status = $2,
    started_at = CASE WHEN $2 = 'CONNECTING' AND started_at IS NULL THEN now() ELSE started_at END,
    completed_at = CASE WHEN $2 IN ('SUCCESS', 'FAILED', 'PARTIAL', 'CANCELLED', 'INTERRUPTED') THEN now() ELSE completed_at END,
    exit_code = $3,
    summary = $4
WHERE id = $1
RETURNING *;

-- name: SetOperationCommandHash :one
UPDATE operations SET command_hash = $2 WHERE id = $1 RETURNING *;

-- name: AppendOperationLog :one
INSERT INTO operation_logs (operation_id, sequence_number, stream, message)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListOperationLogs :many
SELECT * FROM operation_logs
WHERE operation_id = $1
ORDER BY sequence_number;

-- name: ListOperationLogsAfter :many
-- Cursor-based tail for the live WebSocket log stream: only rows the
-- viewer hasn't already been sent (spec: no re-polling the whole history
-- every tick).
SELECT * FROM operation_logs
WHERE operation_id = $1 AND sequence_number > $2
ORDER BY sequence_number;

-- name: CountOperationLogBytes :one
SELECT coalesce(sum(length(message)), 0)::bigint AS total_bytes
FROM operation_logs WHERE operation_id = $1;
