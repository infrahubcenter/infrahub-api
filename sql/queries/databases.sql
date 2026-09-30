-- name: CreateDatabaseResource :one
INSERT INTO databases (resource_id, engine, host, port, database_name, username, ssl_enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetDatabaseByID :one
SELECT * FROM databases WHERE id = $1;

-- name: GetDatabaseByResourceID :one
SELECT * FROM databases WHERE resource_id = $1;

-- name: UpdateDatabaseDiscovery :one
UPDATE databases
SET version = $2,
    last_discovered_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateDatabaseLastSeen :exec
UPDATE databases SET last_seen_at = now() WHERE id = $1;

-- === Step 13: Standalone database monitoring ===

-- name: ListDatabasesForMonitoring :many
-- Return all databases with monitoring enabled, ready for collection cycle
SELECT id, resource_id, type, engine, host, port, database_name, monitoring_enabled,
       connection_status, tls_enabled, tls_skip_verify, provider, region, cluster_identifier
FROM databases
WHERE monitoring_enabled = true AND deleted_at IS NULL
ORDER BY resource_id, id;

-- name: GetDatabaseForMonitoring :one
SELECT id, resource_id, type, engine, host, port, database_name, monitoring_enabled,
       connection_status, tls_enabled, tls_skip_verify, provider, region, cluster_identifier
FROM databases WHERE id = $1 AND deleted_at IS NULL;

-- name: UpdateDatabaseConnectionStatus :one
UPDATE databases
SET connection_status = $2, last_metrics_at = now()
WHERE id = $1
RETURNING id, connection_status, last_metrics_at;

-- name: SetDatabaseMonitoringEnabled :one
UPDATE databases SET monitoring_enabled = $2 WHERE id = $1 RETURNING *;

-- name: SetDatabaseMonitoringConfig :one
UPDATE databases
SET type = COALESCE($2, type),
    provider = COALESCE($3, provider),
    region = COALESCE($4, region),
    tls_enabled = COALESCE($5, tls_enabled),
    tls_skip_verify = COALESCE($6, tls_skip_verify),
    monitoring_enabled = COALESCE($7, monitoring_enabled)
WHERE id = $1
RETURNING *;

-- name: GetLatestStandaloneDatabaseMetric :one
SELECT * FROM standalone_database_metrics
WHERE database_id = $1
ORDER BY captured_at DESC LIMIT 1;

-- name: ListLatestStandaloneDatabaseMetrics :many
SELECT DISTINCT ON (database_id) *
FROM standalone_database_metrics
ORDER BY database_id, captured_at DESC;

-- name: InsertStandaloneDatabaseMetric :exec
INSERT INTO standalone_database_metrics (
    database_id, captured_at, connections, active_connections, max_connections,
    memory_usage_bytes, database_size_bytes, operations_per_second, transactions_per_second,
    errors, uptime_seconds, health_status, metrics_status, metric_details
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);

-- name: ListStandaloneDatabaseMetricsSince :many
SELECT * FROM standalone_database_metrics
WHERE database_id = $1 AND captured_at >= $2
ORDER BY captured_at DESC;

-- name: GetStandaloneDatabaseCredential :one
SELECT id, database_id, username, encrypted_password
FROM standalone_database_credentials
WHERE database_id = $1;

-- name: UpsertStandaloneDatabaseCredential :one
INSERT INTO standalone_database_credentials (database_id, username, encrypted_password)
VALUES ($1, $2, $3)
ON CONFLICT (database_id) DO UPDATE SET
    username = EXCLUDED.username,
    encrypted_password = EXCLUDED.encrypted_password,
    updated_at = now()
RETURNING *;

-- name: RecordStandaloneDatabaseMonitoringSuccess :exec
INSERT INTO standalone_database_monitoring_health (database_id, tier, last_success_at, last_duration_ms, metrics_collected)
VALUES ($1, $2, now(), $3, 1)
ON CONFLICT (database_id, tier) DO UPDATE SET
    last_success_at = now(), last_duration_ms = EXCLUDED.last_duration_ms,
    metrics_collected = standalone_database_monitoring_health.metrics_collected + 1;

-- name: RecordStandaloneDatabaseMonitoringFailure :exec
INSERT INTO standalone_database_monitoring_health (database_id, tier, last_failure_at, last_error)
VALUES ($1, $2, now(), $3)
ON CONFLICT (database_id, tier) DO UPDATE SET
    last_failure_at = now(), last_error = EXCLUDED.last_error;

-- name: ListStandaloneDatabaseMonitoringHealth :many
SELECT * FROM standalone_database_monitoring_health WHERE database_id = $1;

-- name: DeleteStandaloneDatabaseMetricsBefore :execrows
DELETE FROM standalone_database_metrics WHERE captured_at < $1;

-- name: CreateStandaloneDatabaseDeepMetric :one
INSERT INTO standalone_database_deep_metrics (
    database_id, cache_hit_ratio, deadlocks, temp_files, temp_bytes,
    wal_bytes, checkpoints_timed, checkpoints_req, commits_per_sec, rollbacks_per_sec,
    locks_waiting, locks_blocked, replication_status, replication_lag_seconds, replica_count,
    latency_p50_ms, latency_p95_ms, latency_p99_ms, growth_bytes_per_day, metrics_status, details
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
RETURNING *;

-- name: GetLatestStandaloneDatabaseDeepMetric :one
SELECT * FROM standalone_database_deep_metrics
WHERE database_id = $1
ORDER BY captured_at DESC LIMIT 1;

-- name: ListStandaloneDatabaseDeepMetricsSince :many
SELECT * FROM standalone_database_deep_metrics
WHERE database_id = $1 AND captured_at >= $2
ORDER BY captured_at;

-- name: GetStandaloneDatabaseSizeHistorySince :many
-- Reuses standalone_database_metrics.database_size_bytes (its own
-- source of truth for size) rather than a duplicate column here.
SELECT captured_at, database_size_bytes FROM standalone_database_metrics
WHERE database_id = $1 AND captured_at >= $2 AND database_size_bytes IS NOT NULL
ORDER BY captured_at;

-- name: UpsertStandaloneDatabaseQueryMetric :one
INSERT INTO standalone_database_query_metrics (
    database_id, query_fingerprint, captured_at, calls, total_time_ms, avg_time_ms,
    rows, blocks_read, blocks_hit, database_name, database_user, normalized_text
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: ListLatestStandaloneDatabaseQueryMetrics :many
SELECT DISTINCT ON (query_fingerprint) *
FROM standalone_database_query_metrics
WHERE database_id = $1
ORDER BY query_fingerprint, captured_at DESC;

-- name: GetLatestStandaloneDatabaseQueryMetric :one
SELECT * FROM standalone_database_query_metrics
WHERE database_id = $1 AND query_fingerprint = $2
ORDER BY captured_at DESC LIMIT 1;

-- name: GetFirstStandaloneDatabaseQueryMetric :one
SELECT * FROM standalone_database_query_metrics
WHERE database_id = $1 AND query_fingerprint = $2
ORDER BY captured_at ASC LIMIT 1;

-- name: ListStandaloneDatabaseQueryMetricsSince :many
SELECT * FROM standalone_database_query_metrics
WHERE database_id = $1 AND captured_at >= $2
ORDER BY captured_at;

-- name: DeleteStandaloneDatabaseDeepMetricsBefore :execrows
DELETE FROM standalone_database_deep_metrics WHERE captured_at < $1;

-- name: DeleteStandaloneDatabaseQueryMetricsBefore :execrows
DELETE FROM standalone_database_query_metrics WHERE captured_at < $1;

-- === Authorization (spec §50-57): mirrors resources.sql's VM-scoped
-- queries exactly, filtered to resource_type = 'DATABASE' instead ===

-- name: GetDatabaseResourceByID :one
SELECT * FROM resources
WHERE id = $1 AND resource_type = 'DATABASE' AND deleted_at IS NULL;

-- name: ListDirectDatabasePermissionsForUser :many
SELECT rp.resource_id, p.name AS permission_name
FROM resource_permissions rp
JOIN permissions p ON p.id = rp.permission_id
JOIN resources r ON r.id = rp.resource_id
WHERE rp.user_id = $1 AND r.resource_type = 'DATABASE' AND r.status != 'DISABLED' AND r.deleted_at IS NULL;

-- name: ListDatabaseResourceIDsForUserWorkspaces :many
SELECT r.id AS resource_id, r.workspace_id
FROM resources r
JOIN workspaces w ON w.id = r.workspace_id
JOIN workspace_members wm ON wm.workspace_id = r.workspace_id
WHERE wm.user_id = $1 AND w.is_active = true
    AND r.resource_type = 'DATABASE' AND r.status != 'DISABLED' AND r.deleted_at IS NULL;

-- name: SoftDeleteDatabaseResource :exec
-- Removes the monitoring configuration only (spec §82) -- never drops
-- the real external database. monitoring_enabled is also cleared so no
-- scheduler ever picks this instance up again.
-- Also soft-deletes the owning resources row in the same statement:
-- previously only this table was marked, leaving an active resources row
-- behind that still counted toward its workspace ("workspace is not
-- empty") and resource totals after every delete.
WITH deleted AS (
    UPDATE databases SET deleted_at = now(), monitoring_enabled = false WHERE databases.id = $1
    RETURNING databases.resource_id
)
UPDATE resources SET deleted_at = now(), updated_at = now()
WHERE id IN (SELECT resource_id FROM deleted) AND deleted_at IS NULL;

-- name: UpdateDatabaseConfig :one
-- Admin create/edit of a standalone database's connection details (spec
-- §6) -- separate from SetDatabaseMonitoringConfig, which only ever
-- toggles provider/region/tls/monitoring_enabled without touching
-- host/port/name/type.
UPDATE databases
SET type = COALESCE($2, type),
    host = COALESCE($3, host),
    port = COALESCE($4, port),
    database_name = COALESCE($5, database_name),
    provider = COALESCE($6, provider),
    region = COALESCE($7, region),
    cluster_identifier = COALESCE($8, cluster_identifier),
    endpoint = COALESCE($9, endpoint),
    tls_enabled = COALESCE($10, tls_enabled),
    tls_skip_verify = COALESCE($11, tls_skip_verify)
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: GetDatabaseWithResourceByID :one
-- IDOR-safe-adjacent detail lookup: joins the owning resource/workspace so
-- the handler never needs a second round trip, and so a soft-deleted
-- database can never be fetched by ID (spec §57's "do not trust database
-- ID from frontend" -- authorization on the resource_id is still checked
-- separately by the caller).
SELECT
    d.*, r.id AS resource_id_check, r.name AS resource_name, r.workspace_id,
    w.name AS workspace_name
FROM databases d
JOIN resources r ON r.id = d.resource_id
JOIN workspaces w ON w.id = r.workspace_id
WHERE d.id = $1 AND d.deleted_at IS NULL;

-- name: CountActiveDatabaseRecommendationsByCategory :one
-- Powers /api/databases/performance's category counts -- "active" means
-- status != 'RESOLVED', scoped exactly like every other cross-resource
-- summary query in this project (NULL resource_ids = unrestricted/admin,
-- an explicit slice = Member's authorized databases, an empty-but-non-nil
-- slice = none).
SELECT
    count(DISTINCT source_id) FILTER (WHERE source_type IN ('database_slow_query', 'database_high_query_latency')) AS slow_databases,
    count(DISTINCT source_id) FILTER (WHERE source_type = 'database_replication_lag') AS replication_issues,
    count(DISTINCT source_id) FILTER (WHERE source_type = 'database_connection_pressure') AS connection_pressure,
    count(DISTINCT source_id) FILTER (WHERE source_type = 'database_lock_contention') AS lock_contention
FROM recommendations
WHERE status != 'RESOLVED'
    AND source_type IN ('database_slow_query', 'database_high_query_latency', 'database_replication_lag', 'database_connection_pressure', 'database_lock_contention')
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR resource_id = ANY(sqlc.narg('resource_ids')::uuid[]));

-- name: ListStandaloneDatabasesForDashboard :many
-- Cross-resource summary view for /api/databases/summary endpoint. Also
-- backs GET /api/databases and GET /api/my-access's databases section
-- (DatabaseHandler.List/scopedDatabaseAccess) -- workspace_id/workspace_name
-- are purely additive projections of columns that have existed on
-- `resources` since Step 1, added here rather than a new query so both call
-- sites benefit for free. LEFT JOIN workspaces mirrors resources.sql's
-- ListAllDirectResourceGrants exactly.
SELECT
    d.id, d.resource_id, d.type, d.host, d.port, d.database_name,
    d.monitoring_enabled, d.connection_status, d.provider, d.region,
    r.name AS resource_name, r.workspace_id, w.name AS workspace_name,
    COALESCE(lm.health_status, 'UNKNOWN') AS latest_health,
    lm.captured_at AS latest_metric_at
FROM databases d
LEFT JOIN resources r ON r.id = d.resource_id
LEFT JOIN workspaces w ON w.id = r.workspace_id
LEFT JOIN LATERAL (
    SELECT health_status, captured_at FROM standalone_database_metrics
    WHERE database_id = d.id ORDER BY captured_at DESC LIMIT 1
) lm ON true
WHERE d.deleted_at IS NULL
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY w.name, r.name, d.type;
