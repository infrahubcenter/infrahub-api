-- Step 14: controlled database operations + admin remediation. Mirrors
-- reboot.sql's claim/lock/status/log pattern closely (migration 024).

-- name: GetActiveDatabaseOperationForDatabaseLocked :one
-- Operation-queue exclusivity (spec: "Prevent two conflicting operations
-- from running simultaneously against the same database"): row-locks any
-- operation for this database that has actually been confirmed to run
-- (PENDING/RUNNING). Deliberately excludes WAITING_CONFIRMATION -- an
-- unconfirmed draft plan is not yet "active" in any sense that should
-- block a *different* plan from being reviewed and confirmed; multiple
-- proposals may coexist, but at most one may ever be confirmed/running at
-- a time. Must only ever be called inside a transaction (Store.WithTx).
SELECT * FROM database_operations
WHERE database_id = $1
    AND status IN ('PENDING', 'RUNNING')
    AND (sqlc.narg('exclude_operation_id')::uuid IS NULL OR id != sqlc.narg('exclude_operation_id')::uuid)
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- name: CreateDatabaseOperation :one
INSERT INTO database_operations (
    database_id, operation_type, requested_by, reason, parameters, command_preview, recommendation_id, status
)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'WAITING_CONFIRMATION')
RETURNING *;

-- name: GetDatabaseOperationByID :one
SELECT * FROM database_operations WHERE id = $1;

-- name: ConfirmDatabaseOperation :one
UPDATE database_operations
SET status = 'PENDING', confirmed_at = now()
WHERE id = $1 AND status = 'WAITING_CONFIRMATION'
RETURNING *;

-- name: UpdateDatabaseOperationStatus :one
-- started_at is set on the first transition into RUNNING; completed_at on
-- every terminal status. Each is set only once (guarded by IS NULL).
UPDATE database_operations
SET status = $2,
    started_at    = CASE WHEN $2 = 'RUNNING' AND started_at IS NULL THEN now() ELSE started_at END,
    completed_at  = CASE WHEN $2 IN ('SUCCESS', 'FAILED', 'CANCELLED', 'TIMEOUT') THEN now() ELSE completed_at END,
    error_summary = $3
WHERE id = $1
RETURNING *;

-- name: SetDatabaseOperationTimeoutAt :one
UPDATE database_operations SET timeout_at = $2 WHERE id = $1 RETURNING *;

-- name: CompleteDatabaseOperation :one
UPDATE database_operations
SET status = $2,
    completed_at   = now(),
    result_summary = $3,
    result_detail  = $4,
    error_summary  = $5,
    health_before  = $6,
    health_after   = $7
WHERE id = $1
RETURNING *;

-- name: ListNonTerminalDatabaseOperations :many
-- Startup crash-recovery sweep, mirroring ListNonTerminalRebootOperations.
SELECT * FROM database_operations
WHERE status IN ('PENDING', 'WAITING_CONFIRMATION', 'RUNNING');

-- name: GetDatabaseOperationDetail :one
SELECT
    do_.*, d.type AS database_type, d.host AS database_host, res.name AS database_name, res.id AS database_resource_id,
    u.name AS requested_by_name, u.email AS requested_by_email
FROM database_operations do_
JOIN databases d ON d.id = do_.database_id
JOIN resources res ON res.id = d.resource_id
LEFT JOIN users u ON u.id = do_.requested_by
WHERE do_.id = $1;

-- name: ListDatabaseOperationsGlobal :many
-- res.deleted_at IS NULL (Step 23): otherwise a deleted database's old
-- operation history keeps showing up here with a resource name that no
-- longer resolves anywhere else in the app -- every other resource-scoped
-- list already excludes deleted_at rows, this JOIN was simply missed.
SELECT
    do_.*, d.type AS database_type, res.name AS database_name, res.id AS database_resource_id,
    u.name AS requested_by_name, u.email AS requested_by_email
FROM database_operations do_
JOIN databases d ON d.id = do_.database_id AND d.deleted_at IS NULL
JOIN resources res ON res.id = d.resource_id AND res.deleted_at IS NULL
LEFT JOIN users u ON u.id = do_.requested_by
WHERE (sqlc.narg('resource_ids')::uuid[] IS NULL OR res.id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY do_.created_at DESC
LIMIT $1 OFFSET $2;

-- name: ListDatabaseOperationsByDatabase :many
SELECT
    do_.*, u.name AS requested_by_name, u.email AS requested_by_email
FROM database_operations do_
LEFT JOIN users u ON u.id = do_.requested_by
WHERE do_.database_id = $1
ORDER BY do_.created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountDatabaseOperationsByDatabase :one
SELECT count(*) FROM database_operations WHERE database_id = $1;

-- name: DeleteDatabaseOperation :execrows
-- Hard delete, scoped by (id, database_id) together so an operation ID
-- can never be used to delete a row belonging to a different database
-- (mirrors authorizeAdminOperation's IDOR discipline at the SQL layer
-- too, not just the handler). The service layer only ever calls this
-- once the operation is confirmed terminal (SUCCESS/FAILED/CANCELLED/
-- TIMEOUT) -- never while it could still be claimed by the worker.
DELETE FROM database_operations WHERE id = $1 AND database_id = $2;

-- === Live output transcript (database_operation_logs) ===

-- name: AppendDatabaseOperationLog :one
INSERT INTO database_operation_logs (database_operation_id, sequence_number, stream, message)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListDatabaseOperationLogs :many
SELECT * FROM database_operation_logs WHERE database_operation_id = $1 ORDER BY sequence_number;

-- name: ListDatabaseOperationLogsAfter :many
SELECT * FROM database_operation_logs
WHERE database_operation_id = $1 AND sequence_number > $2
ORDER BY sequence_number;
