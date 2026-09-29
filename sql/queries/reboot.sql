-- Step 11: controlled VM reboot + post-reboot verification. Mirrors
-- update_execution.sql's shape closely (the same claim/lock/step/result
-- pattern), against the new reboot_operations/reboot_operation_logs/
-- reboot_verification_results tables (migration 020).

-- name: GetActiveRebootForResourceLocked :one
-- The reboot side of cross-operation exclusivity (spec #10): row-locks
-- any non-terminal reboot for this VM. Must only ever be called inside a
-- transaction (Store.WithTx), paired with GetActiveOperationForResourceLocked
-- (the update side) so a VM can never have an update AND a reboot running
-- at once, in either order.
SELECT * FROM reboot_operations
WHERE vm_id = $1
    AND status IN ('PENDING', 'PRECHECK', 'REBOOTING', 'WAITING_FOR_VM', 'RECONNECTING', 'VERIFYING')
    AND (sqlc.narg('exclude_reboot_operation_id')::uuid IS NULL OR id != sqlc.narg('exclude_reboot_operation_id')::uuid)
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- name: CreateRebootOperation :one
INSERT INTO reboot_operations (vm_id, created_by, reason, status)
VALUES ($1, $2, $3, 'PENDING')
RETURNING *;

-- name: GetRebootOperationByID :one
SELECT * FROM reboot_operations WHERE id = $1;

-- name: UpdateRebootOperationStatus :one
-- started_at is set on PRECHECK (first real activity); reboot_sent_at on
-- REBOOTING; disconnected_at on WAITING_FOR_VM (entering the wait/retry
-- window); reconnected_at on VERIFYING -- that transition only ever
-- happens once a reconnect attempt has actually succeeded (RECONNECTING
-- itself just marks "attempts are now in progress," spanning possibly
-- many tries, so it is not when the timestamp belongs); completed_at on
-- every terminal status. Each is set only once (guarded by IS NULL) even
-- if a status is somehow revisited.
UPDATE reboot_operations
SET status = $2,
    started_at      = CASE WHEN $2 = 'PRECHECK' AND started_at IS NULL THEN now() ELSE started_at END,
    reboot_sent_at  = CASE WHEN $2 = 'REBOOTING' AND reboot_sent_at IS NULL THEN now() ELSE reboot_sent_at END,
    disconnected_at = CASE WHEN $2 = 'WAITING_FOR_VM' AND disconnected_at IS NULL THEN now() ELSE disconnected_at END,
    reconnected_at  = CASE WHEN $2 = 'VERIFYING' AND reconnected_at IS NULL THEN now() ELSE reconnected_at END,
    completed_at    = CASE WHEN $2 IN ('SUCCESS', 'PARTIAL', 'FAILED', 'TIMEOUT', 'UNKNOWN', 'CANCELLED', 'INTERRUPTED') THEN now() ELSE completed_at END,
    error_summary   = $3
WHERE id = $1
RETURNING *;

-- name: SetRebootTimeoutAt :one
UPDATE reboot_operations SET timeout_at = $2 WHERE id = $1 RETURNING *;

-- name: ListNonTerminalRebootOperations :many
-- Startup crash-recovery sweep, mirroring ListNonTerminalOperations.
SELECT * FROM reboot_operations
WHERE status IN ('PENDING', 'PRECHECK', 'REBOOTING', 'WAITING_FOR_VM', 'RECONNECTING', 'VERIFYING');

-- name: GetRebootOperationDetail :one
SELECT
    ro.*, r.name AS vm_name, r.id AS vm_resource_id, u.name AS created_by_name, u.email AS created_by_email
FROM reboot_operations ro
JOIN vms v ON v.id = ro.vm_id
JOIN resources r ON r.id = v.resource_id
LEFT JOIN users u ON u.id = ro.created_by
WHERE ro.id = $1;

-- name: ListRebootOperationsGlobal :many
-- r.deleted_at IS NULL (Step 23): otherwise a deleted VM's old reboot
-- history keeps showing up here with a resource name that no longer
-- resolves anywhere else in the app -- every other resource-scoped list
-- already excludes deleted_at rows, this JOIN was simply missed.
SELECT
    ro.*, r.name AS vm_name, r.id AS vm_resource_id, u.name AS created_by_name, u.email AS created_by_email
FROM reboot_operations ro
JOIN vms v ON v.id = ro.vm_id
JOIN resources r ON r.id = v.resource_id AND r.deleted_at IS NULL
LEFT JOIN users u ON u.id = ro.created_by
WHERE (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY ro.created_at DESC
LIMIT $1 OFFSET $2;

-- name: ListRebootOperationsByVM :many
SELECT
    ro.*, r.name AS vm_name, u.name AS created_by_name, u.email AS created_by_email
FROM reboot_operations ro
JOIN vms v ON v.id = ro.vm_id
JOIN resources r ON r.id = v.resource_id
LEFT JOIN users u ON u.id = ro.created_by
WHERE ro.vm_id = $1
ORDER BY ro.created_at DESC;

-- === Live output transcript (reboot_operation_logs) ===

-- name: AppendRebootOperationLog :one
INSERT INTO reboot_operation_logs (reboot_operation_id, sequence_number, stream, message)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListRebootOperationLogs :many
SELECT * FROM reboot_operation_logs WHERE reboot_operation_id = $1 ORDER BY sequence_number;

-- name: ListRebootOperationLogsAfter :many
SELECT * FROM reboot_operation_logs
WHERE reboot_operation_id = $1 AND sequence_number > $2
ORDER BY sequence_number;

-- === Before/after verification (reboot_verification_results) ===

-- name: UpsertRebootVerificationResult :one
INSERT INTO reboot_verification_results (reboot_operation_id, check_type, expected_value, actual_value, status, error_summary)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (reboot_operation_id, check_type) DO UPDATE SET
    expected_value = EXCLUDED.expected_value,
    actual_value   = EXCLUDED.actual_value,
    status         = EXCLUDED.status,
    error_summary  = EXCLUDED.error_summary,
    checked_at     = now()
RETURNING *;

-- name: ListRebootVerificationResults :many
SELECT * FROM reboot_verification_results WHERE reboot_operation_id = $1 ORDER BY check_type;

-- === VM operational state ===

-- name: SetVMOperationalState :one
UPDATE vms SET operational_state = $2 WHERE id = $1 RETURNING *;
