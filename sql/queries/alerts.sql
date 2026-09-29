-- Step 16: alert lifecycle + timeline.

-- name: CreateAlert :one
INSERT INTO alerts (
    alert_rule_id, resource_id, container_id, workspace_id, alert_type, severity,
    metric, current_value, threshold, title, description
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: GetAlertByID :one
SELECT * FROM alerts WHERE id = $1;

-- name: GetActiveAlertForRule :one
SELECT * FROM alerts WHERE alert_rule_id = $1 AND status IN ('ACTIVE', 'ACKNOWLEDGED');

-- name: UpdateAlertSample :one
-- Refreshes an already-active alert's last-known value each evaluation
-- cycle -- never creates a duplicate row (spec §11's deduplication).
UPDATE alerts SET current_value = $2, last_seen_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateAlertSeverity :one
UPDATE alerts SET severity = $2, last_seen_at = now() WHERE id = $1 RETURNING *;

-- name: AcknowledgeAlert :one
UPDATE alerts
SET status = 'ACKNOWLEDGED', acknowledged_by = $2, acknowledged_at = now()
WHERE id = $1 AND status = 'ACTIVE'
RETURNING *;

-- name: ResolveAlert :one
UPDATE alerts
SET status = 'RESOLVED', resolved_at = now()
WHERE id = $1 AND status IN ('ACTIVE', 'ACKNOWLEDGED')
RETURNING *;

-- name: SuppressAlert :one
UPDATE alerts
SET status = 'SUPPRESSED', suppressed_at = now(), suppressed_reason = $2
WHERE id = $1 AND status IN ('ACTIVE', 'ACKNOWLEDGED')
RETURNING *;

-- name: SetAlertLastNotifiedAt :exec
UPDATE alerts SET last_notified_at = $2 WHERE id = $1;

-- name: ListNonTerminalAlertsForRule :many
-- Used when a rule is suppressed/deleted -- every currently-open alert
-- for it must transition too, never left orphaned in ACTIVE.
SELECT * FROM alerts WHERE alert_rule_id = $1 AND status IN ('ACTIVE', 'ACKNOWLEDGED');

-- name: GetAlertDetail :one
SELECT
    a.*, res.name AS resource_name, res.resource_type, w.name AS workspace_name,
    dc.name AS container_name, ar.metric AS rule_metric, ar.condition AS rule_condition,
    ar.duration_seconds AS rule_duration_seconds, u.name AS acknowledged_by_name, u.email AS acknowledged_by_email
FROM alerts a
JOIN resources res ON res.id = a.resource_id
LEFT JOIN workspaces w ON w.id = a.workspace_id
LEFT JOIN docker_containers dc ON dc.id = a.container_id
JOIN alert_rules ar ON ar.id = a.alert_rule_id
LEFT JOIN users u ON u.id = a.acknowledged_by
WHERE a.id = $1;

-- name: ListAlertsFiltered :many
-- res.deleted_at IS NULL (Step 23): otherwise a deleted resource's old
-- alerts keep showing up here pointing at a resource name that no longer
-- resolves anywhere else in the app.
SELECT
    a.*, res.name AS resource_name, res.resource_type, w.name AS workspace_name, dc.name AS container_name
FROM alerts a
JOIN resources res ON res.id = a.resource_id AND res.deleted_at IS NULL
LEFT JOIN workspaces w ON w.id = a.workspace_id
LEFT JOIN docker_containers dc ON dc.id = a.container_id
WHERE (sqlc.narg('resource_ids')::uuid[] IS NULL OR a.resource_id = ANY(sqlc.narg('resource_ids')::uuid[]))
    AND (sqlc.narg('status')::text IS NULL OR a.status = sqlc.narg('status'))
    AND (sqlc.narg('severity')::text IS NULL OR a.severity = sqlc.narg('severity'))
    AND (sqlc.narg('workspace_id')::uuid IS NULL OR a.workspace_id = sqlc.narg('workspace_id'))
    AND (sqlc.narg('resource_id')::uuid IS NULL OR a.resource_id = sqlc.narg('resource_id'))
    AND (sqlc.narg('search')::text IS NULL OR a.title ILIKE '%' || sqlc.narg('search') || '%' OR res.name ILIKE '%' || sqlc.narg('search') || '%')
ORDER BY
    CASE a.severity WHEN 'CRITICAL' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END,
    a.created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountAlertsFiltered :one
SELECT count(*)
FROM alerts a
JOIN resources res ON res.id = a.resource_id AND res.deleted_at IS NULL
WHERE (sqlc.narg('resource_ids')::uuid[] IS NULL OR a.resource_id = ANY(sqlc.narg('resource_ids')::uuid[]))
    AND (sqlc.narg('status')::text IS NULL OR a.status = sqlc.narg('status'))
    AND (sqlc.narg('severity')::text IS NULL OR a.severity = sqlc.narg('severity'))
    AND (sqlc.narg('workspace_id')::uuid IS NULL OR a.workspace_id = sqlc.narg('workspace_id'))
    AND (sqlc.narg('resource_id')::uuid IS NULL OR a.resource_id = sqlc.narg('resource_id'))
    AND (sqlc.narg('search')::text IS NULL OR a.title ILIKE '%' || sqlc.narg('search') || '%');

-- name: SummarizeAlertsByStatus :many
-- Dashboard summary (spec §19): counts grouped by status/severity,
-- already scoped to the caller's authorized resources.
SELECT status, severity, count(*) AS total
FROM alerts a
WHERE (sqlc.narg('resource_ids')::uuid[] IS NULL OR a.resource_id = ANY(sqlc.narg('resource_ids')::uuid[]))
GROUP BY status, severity;

-- name: CountResolvedToday :one
SELECT count(*)
FROM alerts a
WHERE (sqlc.narg('resource_ids')::uuid[] IS NULL OR a.resource_id = ANY(sqlc.narg('resource_ids')::uuid[]))
    AND status = 'RESOLVED' AND resolved_at >= date_trunc('day', now());

-- name: WorstActiveAlertSeverityByResource :many
-- Step 19 Phase 2: one row per resource with at least one currently-open
-- (ACTIVE/ACKNOWLEDGED) alert -- its worst severity among CRITICAL >
-- WARNING > INFO -- feeding MonitoringDashboardHandler's merged DTO's
-- ActiveAlertSeverity field and the Resources endpoint's alert_severity
-- filter, batched across every resource in the caller's authorized set
-- rather than one query per resource. Same nil-vs-set "resource_ids"
-- convention as every other cross-resource summary query in this project
-- (nil = unrestricted, an Admin's own caller-side guard).
SELECT resource_id,
    (array_agg(severity ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END))[1]::text AS worst_severity
FROM alerts
WHERE status IN ('ACTIVE', 'ACKNOWLEDGED')
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR resource_id = ANY(sqlc.narg('resource_ids')::uuid[]))
GROUP BY resource_id;

-- === alert_events (timeline) ===

-- name: AppendAlertEvent :one
INSERT INTO alert_events (alert_id, event_type, status, value, threshold, message, actor_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ListAlertEvents :many
SELECT * FROM alert_events WHERE alert_id = $1 ORDER BY created_at;

-- name: DeleteAlertsOlderThan :execrows
DELETE FROM alerts WHERE status IN ('RESOLVED', 'SUPPRESSED') AND updated_at < $1;
