-- Step 10: the execution engine. Continues reusing operations/operation_logs
-- (migration 010, extended by 018/019) rather than a parallel table --
-- these queries only add what Step 9's operations.sql/update_center.sql
-- didn't already cover: a transactional per-VM claim, step/result
-- bookkeeping, crash-recovery sweep, and history listings.

-- name: GetActiveOperationForResourceLocked :one
-- The database-level concurrency lock (spec: "use a database-level
-- protection/locking strategy where practical, not just a UI button").
-- Row-locks any non-terminal operation for this VM so two concurrent
-- execute requests can't both pass the "nothing else is running" check --
-- must only ever be called inside a transaction (Store.WithTx), and the
-- caller must actually consume the lock by creating/rejecting before the
-- transaction commits.
SELECT * FROM operations
WHERE resource_id = $1 AND operation_type IN ('OS_UPDATE', 'PACKAGE_UPDATE')
    AND status IN ('PENDING', 'CONNECTING', 'RUNNING', 'VERIFYING')
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- name: CreateUpdateOperation :one
-- Always created with status='PENDING' inside the same transaction as the
-- GetActiveOperationForResourceLocked check above, so the "one active
-- operation per VM" guarantee is atomic, not a check-then-act race.
INSERT INTO operations (resource_id, operation_type, requested_by, command_preview, update_plan_id, status)
VALUES ($1, $2, $3, $4, $5, 'PENDING')
RETURNING *;

-- name: ListNonTerminalOperations :many
-- Startup crash-recovery sweep (spec: "detect any operation left in
-- CONNECTING/RUNNING/VERIFYING from an unclean prior shutdown and mark it
-- INTERRUPTED -- never automatically resume"). PENDING is included too: a
-- row created but never dispatched to a worker before a crash is exactly
-- as stuck as one that was mid-execution.
SELECT * FROM operations
WHERE operation_type IN ('OS_UPDATE', 'PACKAGE_UPDATE')
    AND status IN ('PENDING', 'CONNECTING', 'RUNNING', 'VERIFYING');

-- name: ListUpdateOperationsGlobal :many
-- Admin's global history list; resource_ids narg gives member-scoping the
-- same NULL-means-unrestricted shape as ListVMUpdateSummaries/
-- ListRecommendationsFiltered.
-- r.deleted_at IS NULL (Step 23): otherwise a deleted VM's old update
-- operations keep showing up here with a resource name that no longer
-- resolves anywhere else in the app -- every other resource-scoped list
-- already excludes deleted_at rows, this JOIN was simply missed.
SELECT o.*, r.name AS vm_name, r.id AS vm_resource_id, u.name AS created_by_name, u.email AS created_by_email
FROM operations o
JOIN resources r ON r.id = o.resource_id AND r.deleted_at IS NULL
LEFT JOIN users u ON u.id = o.requested_by
WHERE o.operation_type IN ('OS_UPDATE', 'PACKAGE_UPDATE')
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR o.resource_id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY o.created_at DESC
LIMIT $1 OFFSET $2;

-- name: ListUpdateOperationsByResource :many
SELECT o.*, r.name AS vm_name, u.name AS created_by_name, u.email AS created_by_email
FROM operations o
JOIN resources r ON r.id = o.resource_id
LEFT JOIN users u ON u.id = o.requested_by
WHERE o.resource_id = $1 AND o.operation_type IN ('OS_UPDATE', 'PACKAGE_UPDATE')
ORDER BY o.created_at DESC;

-- name: GetUpdateOperationDetail :one
SELECT o.*, r.name AS vm_name, r.id AS vm_resource_id, u.name AS created_by_name, u.email AS created_by_email
FROM operations o
JOIN resources r ON r.id = o.resource_id
LEFT JOIN users u ON u.id = o.requested_by
WHERE o.id = $1;

-- === Per-step progress (update_operation_steps) ===

-- name: CreateOperationStep :one
INSERT INTO update_operation_steps (operation_id, step_number, step_type, status)
VALUES ($1, $2, $3, 'PENDING')
RETURNING *;

-- name: StartOperationStep :one
UPDATE update_operation_steps SET status = 'RUNNING', started_at = now()
WHERE operation_id = $1 AND step_number = $2
RETURNING *;

-- name: FinishOperationStep :one
UPDATE update_operation_steps
SET status = $3, completed_at = now(), exit_code = $4, output_summary = $5, error_summary = $6
WHERE operation_id = $1 AND step_number = $2
RETURNING *;

-- name: ListOperationSteps :many
SELECT * FROM update_operation_steps WHERE operation_id = $1 ORDER BY step_number;

-- === Per-package verification results (update_operation_results) ===

-- name: CreateOperationResult :exec
-- Idempotent: verifyPackages() runs both from the automatic VERIFY step
-- and from the admin-triggered manual re-check, and must not accumulate a
-- duplicate row on the second call.
INSERT INTO update_operation_results (operation_id, package_name, before_version, target_version)
VALUES ($1, $2, $3, $4)
ON CONFLICT (operation_id, package_name) DO NOTHING;

-- name: SetOperationResultStatus :one
UPDATE update_operation_results SET after_version = $3, status = $4
WHERE operation_id = $1 AND package_name = $2
RETURNING *;

-- name: ListOperationResults :many
SELECT * FROM update_operation_results WHERE operation_id = $1 ORDER BY package_name;

-- === Privilege mode (display cache on vms) ===

-- name: SetVMPrivilegeMode :one
UPDATE vms SET privilege_mode = $2 WHERE id = $1 RETURNING *;
