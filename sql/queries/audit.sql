-- name: CreateAuditLog :one
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ListAuditLogsByUser :many
SELECT * FROM audit_logs
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: ListAuditLogsByResource :many
SELECT * FROM audit_logs
WHERE resource_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- Step 21: the /audit-logs page's list+filter+search+pagination query.
-- Every filter is an optional sqlc.narg -- a NULL arg is a no-op, so this
-- one query serves the unfiltered list and every filtered variant alike
-- (same pattern as ListUpdateOperationsGlobal's resource_ids narg). Search
-- matches action, resource_type, or the actor's name/email; it never
-- searches metadata (which could contain resource names best matched via
-- their own filter, and keeps this a plain indexable ILIKE rather than a
-- jsonb scan).
-- name: ListAuditLogsFiltered :many
SELECT a.*, u.name AS actor_name, u.email AS actor_email
FROM audit_logs a
LEFT JOIN users u ON u.id = a.user_id
WHERE (sqlc.narg('user_id')::uuid IS NULL OR a.user_id = sqlc.narg('user_id')::uuid)
  AND (sqlc.narg('action')::text IS NULL OR a.action = sqlc.narg('action')::text)
  AND (sqlc.narg('resource_type')::text IS NULL OR a.resource_type = sqlc.narg('resource_type')::text)
  AND (sqlc.narg('from')::timestamptz IS NULL OR a.created_at >= sqlc.narg('from')::timestamptz)
  AND (sqlc.narg('to')::timestamptz IS NULL OR a.created_at <= sqlc.narg('to')::timestamptz)
  AND (
    sqlc.narg('search')::text IS NULL
    OR a.action ILIKE '%' || sqlc.narg('search')::text || '%'
    OR a.resource_type ILIKE '%' || sqlc.narg('search')::text || '%'
    OR u.name ILIKE '%' || sqlc.narg('search')::text || '%'
    OR u.email ILIKE '%' || sqlc.narg('search')::text || '%'
  )
ORDER BY a.created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountAuditLogsFiltered :one
SELECT count(*)
FROM audit_logs a
LEFT JOIN users u ON u.id = a.user_id
WHERE (sqlc.narg('user_id')::uuid IS NULL OR a.user_id = sqlc.narg('user_id')::uuid)
  AND (sqlc.narg('action')::text IS NULL OR a.action = sqlc.narg('action')::text)
  AND (sqlc.narg('resource_type')::text IS NULL OR a.resource_type = sqlc.narg('resource_type')::text)
  AND (sqlc.narg('from')::timestamptz IS NULL OR a.created_at >= sqlc.narg('from')::timestamptz)
  AND (sqlc.narg('to')::timestamptz IS NULL OR a.created_at <= sqlc.narg('to')::timestamptz)
  AND (
    sqlc.narg('search')::text IS NULL
    OR a.action ILIKE '%' || sqlc.narg('search')::text || '%'
    OR a.resource_type ILIKE '%' || sqlc.narg('search')::text || '%'
    OR u.name ILIKE '%' || sqlc.narg('search')::text || '%'
    OR u.email ILIKE '%' || sqlc.narg('search')::text || '%'
  );

-- name: CountAuditLogsToday :one
SELECT count(*) FROM audit_logs WHERE created_at >= date_trunc('day', now());

-- Step 21 overview cards: one row per distinct action with its total count
-- across all time -- cheap (bounded by the number of distinct action
-- names, a few dozen, never by row count) and bucketed into the page's
-- category cards in Go (auditCategoryFor), so the category list only ever
-- needs to live in one place.
-- name: GetAuditLogActionCounts :many
SELECT action, count(*) AS total FROM audit_logs GROUP BY action;
