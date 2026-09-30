-- name: CreateObjectStorage :one
INSERT INTO object_storages (resource_id, provider, endpoint, region, bucket, base_path, access_key_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetObjectStorageByID :one
SELECT * FROM object_storages WHERE id = $1;

-- name: GetObjectStorageByResourceID :one
SELECT * FROM object_storages WHERE resource_id = $1;

-- name: UpdateObjectStorageDiscovery :one
UPDATE object_storages
SET last_discovered_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateObjectStorageLastSeen :exec
UPDATE object_storages SET last_seen_at = now() WHERE id = $1;

-- === Step 17: standalone object storage monitoring ===

-- name: ListObjectStoragesForMonitoring :many
-- Return all object storages with monitoring enabled, ready for a
-- collection cycle (mirrors ListDatabasesForMonitoring).
SELECT * FROM object_storages
WHERE monitoring_enabled = true AND deleted_at IS NULL
ORDER BY resource_id, id;

-- name: UpdateObjectStorageConfig :one
-- Admin create/edit of a standalone object storage's connection details --
-- partial update via COALESCE, mirrors UpdateDatabaseConfig exactly.
UPDATE object_storages
SET name            = COALESCE(sqlc.narg('name'), name),
    provider        = COALESCE(sqlc.narg('provider'), provider),
    endpoint        = COALESCE(sqlc.narg('endpoint'), endpoint),
    region          = COALESCE(sqlc.narg('region'), region),
    bucket          = COALESCE(sqlc.narg('bucket'), bucket),
    base_path       = COALESCE(sqlc.narg('base_path'), base_path),
    tls_enabled     = COALESCE(sqlc.narg('tls_enabled'), tls_enabled),
    tls_skip_verify = COALESCE(sqlc.narg('tls_skip_verify'), tls_skip_verify),
    access_key_id   = COALESCE(sqlc.narg('access_key_id'), access_key_id)
WHERE id = sqlc.arg('id') AND deleted_at IS NULL
RETURNING *;

-- name: SetObjectStorageMonitoringEnabled :one
UPDATE object_storages SET monitoring_enabled = $2 WHERE id = $1 RETURNING *;

-- name: UpdateObjectStorageConnectionStatus :one
-- Updates connection_status/health_status/last_metrics_at together after
-- any probe (manual test-connection or a fast-metrics collection cycle) --
-- extended in Phase 2 to also set health_status so a single UPDATE covers
-- all three post-collection fields, rather than a second sibling query.
UPDATE object_storages
SET connection_status = $2, health_status = $3, last_metrics_at = now()
WHERE id = $1
RETURNING id, connection_status, health_status, last_metrics_at;

-- === Authorization: mirrors databases.sql's DATABASE-scoped queries
-- exactly, filtered to resource_type = 'OBJECT_STORAGE' instead ===

-- name: GetObjectStorageResourceByID :one
SELECT * FROM resources
WHERE id = $1 AND resource_type = 'OBJECT_STORAGE' AND deleted_at IS NULL;

-- name: ListDirectObjectStoragePermissionsForUser :many
SELECT rp.resource_id, p.name AS permission_name
FROM resource_permissions rp
JOIN permissions p ON p.id = rp.permission_id
JOIN resources r ON r.id = rp.resource_id
WHERE rp.user_id = $1 AND r.resource_type = 'OBJECT_STORAGE' AND r.status != 'DISABLED' AND r.deleted_at IS NULL;

-- name: ListObjectStorageResourceIDsForUserWorkspaces :many
SELECT r.id AS resource_id, r.workspace_id
FROM resources r
JOIN workspaces w ON w.id = r.workspace_id
JOIN workspace_members wm ON wm.workspace_id = r.workspace_id
WHERE wm.user_id = $1 AND w.is_active = true
    AND r.resource_type = 'OBJECT_STORAGE' AND r.status != 'DISABLED' AND r.deleted_at IS NULL;

-- name: SoftDeleteObjectStorageResource :exec
-- Removes the monitoring configuration only -- never touches the real S3
-- bucket. monitoring_enabled is also cleared so no scheduler ever picks
-- this instance up again. Mirrors SoftDeleteDatabaseResource exactly.
-- Also soft-deletes the owning resources row in the same statement:
-- previously only this table was marked, leaving an active resources row
-- behind that still counted toward its workspace ("workspace is not
-- empty") and resource totals after every delete.
WITH deleted AS (
    UPDATE object_storages SET deleted_at = now(), monitoring_enabled = false WHERE object_storages.id = $1
    RETURNING object_storages.resource_id
)
UPDATE resources SET deleted_at = now(), updated_at = now()
WHERE id IN (SELECT resource_id FROM deleted) AND deleted_at IS NULL;

-- name: GetObjectStorageWithResourceByID :one
-- IDOR-safe-adjacent detail lookup: joins the owning resource/workspace so
-- the handler never needs a second round trip, and so a soft-deleted
-- object storage can never be fetched by ID -- mirrors
-- GetDatabaseWithResourceByID exactly.
SELECT
    o.*, r.id AS resource_id_check, r.name AS resource_name, r.workspace_id,
    w.name AS workspace_name
FROM object_storages o
JOIN resources r ON r.id = o.resource_id
JOIN workspaces w ON w.id = r.workspace_id
WHERE o.id = $1 AND o.deleted_at IS NULL;

-- name: ListObjectStoragesForDashboard :many
-- Cross-resource summary view for GET /api/object-storage, mirrors
-- ListStandaloneDatabasesForDashboard exactly, including its workspace_id/
-- workspace_name projection (also backs GET /api/my-access's
-- object_storage section via scopedObjectStorageAccess).
SELECT
    o.id, o.resource_id, o.provider, o.endpoint, o.region, o.bucket, o.base_path,
    o.monitoring_enabled, o.connection_status, o.health_status,
    r.name AS resource_name, r.workspace_id, w.name AS workspace_name
FROM object_storages o
LEFT JOIN resources r ON r.id = o.resource_id
LEFT JOIN workspaces w ON w.id = r.workspace_id
WHERE o.deleted_at IS NULL
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY w.name, r.name;

-- name: GetObjectStorageSummaryCounts :one
-- Powers GET /api/object-storage/summary -- total plus a mutually-
-- exclusive healthy/warning/critical/unavailable partition over the
-- caller's authorized (resource_ids non-nil) or, for an Admin, every
-- (resource_ids nil) non-deleted object storage, same nil-vs-empty-vs-set
-- "resource_ids" convention as ListObjectStoragesForDashboard/every other
-- cross-resource summary query in this project.
--
-- "unavailable" vs "critical": health_status alone can't distinguish them
-- since ComputeObjectStorageHealth (object_storage_adapter.go) already
-- collapses every classified connection failure into CRITICAL. This query
-- re-splits CRITICAL rows using connection_status: UNAVAILABLE/TIMEOUT/
-- NOT_FOUND mean the bucket itself could not be reached or resolved at all
-- (network-level or nonexistent-target failure) and are reported as
-- "unavailable"; AUTH_FAILED/ACCESS_DENIED/TLS_ERROR mean the endpoint DID
-- respond but rejected the request (a reachable-but-misconfigured/
-- forbidden bucket) and stay "critical". A storage that has never been
-- monitored (health_status/connection_status still 'UNKNOWN') counts only
-- toward total, never toward any of the four buckets -- "never checked" is
-- not the same claim as "healthy" or "down".
SELECT
    count(*) AS total,
    count(*) FILTER (WHERE o.health_status = 'HEALTHY') AS healthy,
    count(*) FILTER (WHERE o.health_status = 'WARNING') AS warning,
    count(*) FILTER (
        WHERE o.health_status = 'CRITICAL' AND o.connection_status NOT IN ('UNAVAILABLE', 'TIMEOUT', 'NOT_FOUND')
    ) AS critical,
    count(*) FILTER (
        WHERE o.health_status = 'CRITICAL' AND o.connection_status IN ('UNAVAILABLE', 'TIMEOUT', 'NOT_FOUND')
    ) AS unavailable
FROM object_storages o
LEFT JOIN resources r ON r.id = o.resource_id
WHERE o.deleted_at IS NULL
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.id = ANY(sqlc.narg('resource_ids')::uuid[]));

-- === Step 17 Phase 2: fast metrics (HeadBucket-only reachability/latency/
-- error-count probe) -- mirrors databases.sql's standalone_database_metrics
-- query set exactly, scoped to object_storage_metrics's smaller fast-cycle
-- column set (object_count/total_size_bytes/request_count/error_4xx/5xx
-- stay NULL until a later phase's deep/bucket-scan cycle populates them). ===

-- name: CreateObjectStorageMetric :one
INSERT INTO object_storage_metrics (
    object_storage_id, captured_at, reachable, latency_ms, error_count,
    object_count, total_size_bytes, request_count, error_4xx_count, error_5xx_count,
    health_status, metrics_status, metric_details
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetLatestObjectStorageMetric :one
SELECT * FROM object_storage_metrics
WHERE object_storage_id = $1
ORDER BY captured_at DESC LIMIT 1;

-- name: ListObjectStorageMetricsSince :many
-- Newest-first, capped by $4 -- a bounded range can still hold far more
-- fast-cycle samples than are worth returning in one response; the
-- handler reverses this into chronological order for its history chart,
-- same "DESC + LIMIT, caller reverses" shape as ListMonitoringSnapshotsByResourceRange.
SELECT * FROM object_storage_metrics
WHERE object_storage_id = $1 AND captured_at >= $2 AND captured_at <= $3
ORDER BY captured_at DESC
LIMIT $4;

-- name: DeleteObjectStorageMetricsBefore :execrows
DELETE FROM object_storage_metrics WHERE captured_at < $1;

-- name: RecordObjectStorageMonitoringSuccess :exec
INSERT INTO object_storage_monitoring_health (object_storage_id, tier, last_success_at, last_duration_ms, metrics_collected)
VALUES ($1, $2, now(), $3, 1)
ON CONFLICT (object_storage_id, tier) DO UPDATE SET
    last_success_at = now(), last_duration_ms = EXCLUDED.last_duration_ms,
    metrics_collected = object_storage_monitoring_health.metrics_collected + 1;

-- name: RecordObjectStorageMonitoringFailure :exec
INSERT INTO object_storage_monitoring_health (object_storage_id, tier, last_failure_at, last_error)
VALUES ($1, $2, now(), $3)
ON CONFLICT (object_storage_id, tier) DO UPDATE SET
    last_failure_at = now(), last_error = EXCLUDED.last_error;

-- name: ListObjectStorageMonitoringHealth :many
SELECT * FROM object_storage_monitoring_health WHERE object_storage_id = $1;

-- name: GetStandaloneObjectStorageCredential :one
SELECT id, object_storage_id, encrypted_secret_key
FROM standalone_object_storage_credentials
WHERE object_storage_id = $1;

-- name: UpsertStandaloneObjectStorageCredential :one
INSERT INTO standalone_object_storage_credentials (object_storage_id, encrypted_secret_key)
VALUES ($1, $2)
ON CONFLICT (object_storage_id) DO UPDATE SET
    encrypted_secret_key = EXCLUDED.encrypted_secret_key,
    updated_at = now()
RETURNING *;

-- === Step 17 Phase 3: deep metrics (bucket security facts, growth,
-- CloudWatch/bounded-listing bucket metrics) ===

-- name: UpdateObjectStorageSecurityFacts :one
-- Syncs the deep cycle's latest versioning/encryption/public-access/
-- object-lock snapshot onto object_storages itself, so the fast dashboard/
-- detail GET (and GET .../security) never needs to join
-- object_storage_deep_metrics. Every value is one of that column's
-- ENABLED/DISABLED/UNKNOWN or PUBLIC/PRIVATE/UNKNOWN CHECK values -- never
-- inferred, always exactly what the deep collector observed.
UPDATE object_storages
SET versioning_status = $2, encryption_status = $3, public_access = $4, object_lock_status = $5
WHERE id = $1
RETURNING *;

-- name: CreateObjectStorageDeepMetric :one
-- Deep-cycle snapshot: versioning/encryption/public-access/object-lock plus
-- growth-rate/error-rate, kept on its own table (mirrors
-- standalone_database_deep_metrics) separate from the bucket-metrics
-- (object_count/total_size_bytes/request_count/error_4xx/5xx) row this same
-- cycle also writes via CreateObjectStorageMetric -- that table already
-- carries columns shared with the fast cycle (migration 026), this one is
-- the deep cycle's own dedicated facts+growth table.
INSERT INTO object_storage_deep_metrics (
    object_storage_id, versioning_status, encryption_status, public_access, object_lock_status,
    growth_bytes_per_day, growth_percent, error_rate_percent, partial, metrics_status, details
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: GetLatestObjectStorageDeepMetric :one
SELECT * FROM object_storage_deep_metrics
WHERE object_storage_id = $1
ORDER BY captured_at DESC LIMIT 1;

-- name: GetObjectStorageSizeHistorySince :many
-- Growth-rate input samples: only object_storage_metrics rows where
-- total_size_bytes was actually collected (written by the DEEP cycle's
-- bucket-metrics probe -- CloudWatch or the bounded ListObjectsV2 fallback
-- -- never the fast HeadBucket-only cycle, which never touches this
-- column) count as a real size sample. Mirrors
-- GetStandaloneDatabaseSizeHistorySince's "chronological, real samples
-- only" shape, fed into the same reused ComputeGrowthRate function.
SELECT * FROM object_storage_metrics
WHERE object_storage_id = $1 AND captured_at >= $2 AND total_size_bytes IS NOT NULL
ORDER BY captured_at ASC;
