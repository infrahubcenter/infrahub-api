-- name: CreateRecommendation :one
INSERT INTO recommendations (resource_id, type, severity, title, description, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListRecommendationsByResource :many
SELECT * FROM recommendations
WHERE resource_id = $1 AND (sqlc.arg('status')::text = '' OR status = sqlc.arg('status'))
ORDER BY detected_at DESC;

-- name: UpdateRecommendationStatus :one
UPDATE recommendations
SET status = $2
WHERE id = $1
RETURNING *;

-- name: ResolveRecommendation :one
UPDATE recommendations
SET status = 'RESOLVED', resolved_at = now()
WHERE id = $1
RETURNING *;

-- name: UpsertRecommendationBySource :one
-- source_type/source_id (Step 7 migration 016) link a recommendation back
-- to whatever row produced it -- for package updates, package_updates.id.
-- Re-running a scan updates the existing recommendation in place instead
-- of inserting a new one every cycle (spec §19); a previously RESOLVED
-- recommendation whose underlying issue reappeared comes back as NEW
-- rather than staying silently resolved.
INSERT INTO recommendations (resource_id, type, severity, title, description, metadata, source_type, source_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (source_type, source_id) WHERE source_id IS NOT NULL
DO UPDATE SET
    severity    = EXCLUDED.severity,
    title       = EXCLUDED.title,
    description = EXCLUDED.description,
    metadata    = EXCLUDED.metadata,
    status      = CASE WHEN recommendations.status = 'RESOLVED' THEN 'NEW' ELSE recommendations.status END,
    resolved_at = CASE WHEN recommendations.status = 'RESOLVED' THEN NULL ELSE recommendations.resolved_at END
RETURNING *;

-- name: ResolveRecommendationBySource :exec
UPDATE recommendations
SET status = 'RESOLVED', resolved_at = now()
WHERE source_type = $1 AND source_id = $2 AND status != 'RESOLVED';

-- name: SetRecommendationStatusBySource :exec
-- For ACKNOWLEDGED/DISMISSED (Step 7 spec §20) -- unlike
-- ResolveRecommendationBySource, this never touches resolved_at and
-- accepts any target status, so acknowledging/dismissing a package
-- update via /packages/:packageId/acknowledge|dismiss keeps the linked
-- recommendation showing the same status on the /recommendations
-- dashboard.
UPDATE recommendations
SET status = $3
WHERE source_type = $1 AND source_id = $2;

-- name: ListRecommendationsFiltered :many
-- Powers the cross-resource /recommendations dashboard (spec §38),
-- across every resource_type (VM and, since Step 14, DATABASE) --
-- resource_type is returned so the frontend can route "Review" to the
-- right detail page (/vms/:id vs /databases/:id) rather than assuming VM.
-- ADMIN passes resource_ids = NULL (no restriction, sees everything);
-- MEMBER passes every resource ID they're authorized on across every
-- resource type, merged, so the query itself enforces the restriction
-- rather than trusting the caller to filter client-side (spec §39: never
-- show a member the global count).
-- severity (Step 19 Phase 4) follows the identical optional-narg pattern
-- as type/status above -- mirrors alerts/page.tsx's existing ?severity=
-- convention so the new dashboard's Recommendations widget can deep-link
-- straight to /recommendations?severity=X.
-- res.deleted_at IS NULL (Step 23): an Admin's unrestricted resource_ids
-- (NULL) previously meant "every recommendation ever generated," which
-- kept showing recommendations for VMs/databases the caller had already
-- deleted -- every other resource-scoped list in this app already
-- excludes deleted_at rows, this one was simply missed.
SELECT r.*, res.name AS resource_name, res.workspace_id, res.resource_type
FROM recommendations r
JOIN resources res ON res.id = r.resource_id AND res.deleted_at IS NULL
WHERE (sqlc.narg('type')::text IS NULL OR r.type = sqlc.narg('type'))
    AND (sqlc.narg('status')::text IS NULL OR r.status = sqlc.narg('status'))
    AND (sqlc.narg('severity')::text IS NULL OR r.severity = sqlc.narg('severity'))
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.resource_id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY r.detected_at DESC
LIMIT $1 OFFSET $2;

-- name: CountRecommendationsFiltered :one
SELECT count(*)
FROM recommendations r
JOIN resources res ON res.id = r.resource_id AND res.deleted_at IS NULL
WHERE (sqlc.narg('type')::text IS NULL OR r.type = sqlc.narg('type'))
    AND (sqlc.narg('status')::text IS NULL OR r.status = sqlc.narg('status'))
    AND (sqlc.narg('severity')::text IS NULL OR r.severity = sqlc.narg('severity'))
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.resource_id = ANY(sqlc.narg('resource_ids')::uuid[]));

-- name: GetRecommendationSummaryCounts :one
-- Step 19 Phase 2: powers MonitoringDashboardHandler.Overview's
-- Recommendations bucket -- total plus a status partition and an
-- open-by-severity breakdown (open = NEW or ACKNOWLEDGED, mirroring
-- alert_rules' own "still needs attention" notion of open), scoped by the
-- caller's authorized resource_ids exactly like every other cross-resource
-- summary query in this project (nil = unrestricted, an Admin's own
-- caller-side guard; narrowed further by a workspace filter via a
-- smaller resource_ids set when Overview's ?workspace_id= param is
-- present).
SELECT
    count(*) AS total,
    count(*) FILTER (WHERE r.status = 'NEW') AS new,
    count(*) FILTER (WHERE r.status = 'ACKNOWLEDGED') AS acknowledged,
    count(*) FILTER (WHERE r.status = 'DISMISSED') AS dismissed,
    count(*) FILTER (WHERE r.status = 'RESOLVED') AS resolved,
    count(*) FILTER (WHERE r.status IN ('NEW', 'ACKNOWLEDGED') AND r.severity = 'CRITICAL') AS open_critical,
    count(*) FILTER (WHERE r.status IN ('NEW', 'ACKNOWLEDGED') AND r.severity = 'HIGH')     AS open_high,
    count(*) FILTER (WHERE r.status IN ('NEW', 'ACKNOWLEDGED') AND r.severity = 'MEDIUM')   AS open_medium,
    count(*) FILTER (WHERE r.status IN ('NEW', 'ACKNOWLEDGED') AND r.severity = 'LOW')      AS open_low
FROM recommendations r
JOIN resources res ON res.id = r.resource_id AND res.deleted_at IS NULL
WHERE (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.resource_id = ANY(sqlc.narg('resource_ids')::uuid[]));
