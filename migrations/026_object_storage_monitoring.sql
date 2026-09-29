-- +goose Up

-- Step 17: Object Storage (AWS S3 / DigitalOcean Spaces / MinIO / generic
-- S3-compatible) monitoring infrastructure. Mirrors migration 023's
-- structure exactly: the `object_storages` table (created in migration 005)
-- is a simple resource-backed configuration table, enhanced here with
-- dedicated monitoring/credential/metrics tables. Object storage is a
-- first-class resource under a Project (optionally a Group), reached
-- directly via the AWS SDK v2 S3 client -- never a VM child, never SSH.
--
-- This migration only lays the schema down (Phase 1: schema + adapter +
-- CRUD + test-connection). Nothing writes to object_storage_metrics/
-- object_storage_deep_metrics/object_storage_monitoring_health yet --
-- those tables exist now so a later phase (fast/deep metrics schedulers)
-- needs no additional migration.

-- Monitoring credential for standalone object storage (like
-- standalone_database_credentials, but for the object_storages table).
-- No username column -- access_key_id is not a secret and stays plaintext
-- on object_storages (already added in migration 005); only the secret
-- access key is encrypted here.
CREATE TABLE standalone_object_storage_credentials (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    object_storage_id     uuid NOT NULL UNIQUE REFERENCES object_storages(id) ON DELETE CASCADE,
    encrypted_secret_key  bytea,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER standalone_object_storage_credentials_set_updated_at
    BEFORE UPDATE ON standalone_object_storage_credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Enhance object_storages with monitoring state (nullable/UNKNOWN-capable
-- so existing rows continue working without requiring re-entry). Every
-- status column defaults to 'UNKNOWN' and stays a first-class value --
-- absent/unknown is never inferred as PUBLIC/DISABLED/etc (spec: never a
-- fabricated value).
ALTER TABLE object_storages
    ADD COLUMN name               text,
    ADD COLUMN monitoring_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN tls_enabled        boolean NOT NULL DEFAULT true,
    ADD COLUMN tls_skip_verify    boolean NOT NULL DEFAULT false,
    -- Distinct 8-value enum from databases' 7-value ConnectionTestStatus
    -- (CONNECTED/AUTH_FAILED/TIMEOUT/REFUSED/TLS_ERROR/UNAVAILABLE/UNKNOWN)
    -- -- object storage's value set genuinely differs (ACCESS_DENIED and
    -- NOT_FOUND are meaningful, distinct S3 outcomes with no database
    -- analogue; REFUSED collapses into UNAVAILABLE here).
    ADD COLUMN connection_status  text NOT NULL DEFAULT 'UNKNOWN' CHECK (connection_status IN (
        'CONNECTED', 'AUTH_FAILED', 'ACCESS_DENIED', 'NOT_FOUND', 'TIMEOUT', 'TLS_ERROR', 'UNAVAILABLE', 'UNKNOWN'
    )),
    ADD COLUMN last_metrics_at    timestamptz,
    ADD COLUMN health_status      text NOT NULL DEFAULT 'UNKNOWN' CHECK (health_status IN ('HEALTHY', 'WARNING', 'CRITICAL', 'UNKNOWN')),
    ADD COLUMN versioning_status  text NOT NULL DEFAULT 'UNKNOWN' CHECK (versioning_status IN ('ENABLED', 'DISABLED', 'UNKNOWN')),
    ADD COLUMN encryption_status  text NOT NULL DEFAULT 'UNKNOWN' CHECK (encryption_status IN ('ENABLED', 'DISABLED', 'UNKNOWN')),
    ADD COLUMN public_access      text NOT NULL DEFAULT 'UNKNOWN' CHECK (public_access IN ('PUBLIC', 'PRIVATE', 'UNKNOWN')),
    ADD COLUMN object_lock_status text NOT NULL DEFAULT 'UNKNOWN' CHECK (object_lock_status IN ('ENABLED', 'DISABLED', 'UNKNOWN')),
    -- Soft-delete only (spec: removing an object storage from Infra Hub
    -- Center means removing the monitoring registration only -- this
    -- project never writes/deletes/uploads to the real bucket, ever).
    ADD COLUMN deleted_at         timestamptz;

CREATE INDEX object_storages_monitoring_enabled_idx ON object_storages(monitoring_enabled) WHERE monitoring_enabled = true;
CREATE INDEX object_storages_resource_monitoring_idx ON object_storages(resource_id, monitoring_enabled);

-- Fast-cycle metrics: reachability/latency/error-count "provider metrics"
-- plus object-count/size/requests/4xx/5xx "bucket metrics" on the same
-- row (kept structurally separate at the Go-struct level even though they
-- share a table, same convention as standalone_database_metrics). Not
-- written to until the fast-metrics scheduler ships (a later phase).
CREATE TABLE object_storage_metrics (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    object_storage_id     uuid NOT NULL REFERENCES object_storages(id) ON DELETE CASCADE,
    captured_at           timestamptz NOT NULL DEFAULT now(),
    -- Provider/reachability metrics.
    reachable             boolean,
    latency_ms            double precision,
    error_count           integer,
    -- Bucket metrics.
    object_count          bigint,
    total_size_bytes      bigint,
    request_count         bigint,
    error_4xx_count       bigint,
    error_5xx_count       bigint,
    health_status         text NOT NULL DEFAULT 'UNKNOWN' CHECK (health_status IN ('HEALTHY', 'WARNING', 'CRITICAL', 'UNKNOWN')),
    metrics_status        text NOT NULL DEFAULT 'COMPLETE' CHECK (metrics_status IN ('COMPLETE', 'PARTIAL', 'FAILED')),
    metric_details        jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX object_storage_metrics_storage_idx ON object_storage_metrics(object_storage_id, captured_at DESC);

-- Deep-cycle metrics: versioning/encryption/public-access/object-lock
-- snapshot plus growth-rate history, mirrors standalone_database_deep_metrics.
-- Not written to until the deep-metrics scheduler ships (a later phase).
CREATE TABLE object_storage_deep_metrics (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    object_storage_id      uuid NOT NULL REFERENCES object_storages(id) ON DELETE CASCADE,
    captured_at            timestamptz NOT NULL DEFAULT now(),
    versioning_status      text CHECK (versioning_status IS NULL OR versioning_status IN ('ENABLED', 'DISABLED', 'UNKNOWN')),
    encryption_status      text CHECK (encryption_status IS NULL OR encryption_status IN ('ENABLED', 'DISABLED', 'UNKNOWN')),
    public_access          text CHECK (public_access IS NULL OR public_access IN ('PUBLIC', 'PRIVATE', 'UNKNOWN')),
    object_lock_status     text CHECK (object_lock_status IS NULL OR object_lock_status IN ('ENABLED', 'DISABLED', 'UNKNOWN')),
    growth_bytes_per_day   double precision,
    growth_percent         double precision,
    partial                boolean NOT NULL DEFAULT false,
    metrics_status         text NOT NULL DEFAULT 'COMPLETE' CHECK (metrics_status IN ('COMPLETE', 'PARTIAL', 'FAILED')),
    details                jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX object_storage_deep_metrics_storage_idx ON object_storage_deep_metrics(object_storage_id, captured_at DESC);

-- Collector health per tier, mirrors standalone_database_monitoring_health
-- exactly. Not written to until the schedulers ship (a later phase).
CREATE TABLE object_storage_monitoring_health (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    object_storage_id   uuid NOT NULL REFERENCES object_storages(id) ON DELETE CASCADE,
    tier                text NOT NULL CHECK (tier IN ('FAST', 'DEEP')),
    last_success_at     timestamptz,
    last_failure_at     timestamptz,
    last_duration_ms    integer,
    last_error          text,
    metrics_collected   bigint NOT NULL DEFAULT 0,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT object_storage_monitoring_health_unique UNIQUE (object_storage_id, tier)
);

CREATE TRIGGER object_storage_monitoring_health_set_updated_at
    BEFORE UPDATE ON object_storage_monitoring_health
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Widen alert_rules.alert_type/.metric (migration 025) to add the five
-- OBJECT_STORAGE_* alert types and their corresponding metric names --
-- not evaluated by the AlertEngine until a later phase adds the
-- alert_metric_lookup.Resolve() case, but the CHECK constraint is widened
-- now so a single migration covers this feature's full schema footprint.
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_alert_type_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_alert_type_check CHECK (alert_type IN (
    'VM_HIGH_CPU', 'VM_HIGH_MEMORY', 'VM_HIGH_STORAGE', 'VM_UNAVAILABLE',
    'DOCKER_CONTAINER_STOPPED', 'DOCKER_CONTAINER_RESTARTING', 'DOCKER_CONTAINER_UNHEALTHY', 'DOCKER_CONTAINER_OOM',
    'DATABASE_UNAVAILABLE', 'DATABASE_HIGH_CONNECTIONS', 'DATABASE_HIGH_LATENCY', 'DATABASE_LOCK_CONTENTION',
    'DATABASE_REPLICATION_LAG', 'DATABASE_HIGH_STORAGE', 'DATABASE_LOW_CACHE_HIT',
    'OBJECT_STORAGE_UNAVAILABLE', 'OBJECT_STORAGE_HIGH_GROWTH', 'OBJECT_STORAGE_PUBLIC_ACCESS',
    'OBJECT_STORAGE_ENCRYPTION_DISABLED', 'OBJECT_STORAGE_HIGH_ERROR_RATE'
));

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'CPU_PERCENT', 'MEMORY_PERCENT', 'STORAGE_PERCENT', 'VM_UNREACHABLE',
    'CONTAINER_STOPPED', 'CONTAINER_RESTARTING', 'CONTAINER_UNHEALTHY', 'CONTAINER_RESTART_COUNT',
    'DB_UNREACHABLE', 'DB_CONNECTION_PERCENT', 'DB_LATENCY_P95_MS', 'DB_LOCKS_BLOCKED',
    'DB_REPLICATION_LAG_SECONDS', 'DB_STORAGE_BYTES', 'DB_CACHE_HIT_PERCENT',
    'OBJECT_STORAGE_UNREACHABLE', 'OBJECT_STORAGE_GROWTH_PERCENT', 'OBJECT_STORAGE_PUBLIC_ACCESS_FLAG',
    'OBJECT_STORAGE_ENCRYPTION_DISABLED_FLAG', 'OBJECT_STORAGE_ERROR_RATE_PERCENT'
));

-- Widen recommendations.type (migration 009, already widened once by
-- migration 024 for the DATABASE_* recommendation types) to add the four
-- OBJECT_STORAGE_* recommendation types -- not generated by any code path
-- until a later phase adds the deep-metrics recommendation sync, same
-- "schema now, behavior later" rationale as the tables above. (Migration
-- 024 already covers every DATABASE_* recommendation type this codebase's
-- database_deep_metrics_service.go/database_metrics_service.go currently
-- write -- verified by inspecting every upsertDatabaseRecommendation call
-- site; no further DATABASE_* gap exists to fix here.)
ALTER TABLE recommendations DROP CONSTRAINT recommendations_type_check;
ALTER TABLE recommendations ADD CONSTRAINT recommendations_type_check CHECK (type IN (
    'OS_UPDATE', 'PACKAGE_UPDATE', 'DOCKER_UPDATE', 'DATABASE_UPDATE',
    'STORAGE_WARNING', 'CPU_WARNING', 'MEMORY_WARNING', 'DISK_WARNING',
    'SECURITY', 'CONFIGURATION', 'REBOOT_REQUIRED',
    'DATABASE_LOCK_CONTENTION', 'DATABASE_LOW_CACHE_HIT', 'DATABASE_HIGH_TEMP_IO',
    'DATABASE_REPLICATION_LAG', 'DATABASE_GROWTH_HIGH', 'DATABASE_SLOW_QUERY',
    'DATABASE_HIGH_QUERY_LATENCY', 'DATABASE_REDIS_EVICTIONS', 'DATABASE_UNAVAILABLE',
    'DATABASE_REDIS_BLOCKED_CLIENTS',
    'OBJECT_STORAGE_PUBLIC_ACCESS', 'OBJECT_STORAGE_ENCRYPTION_DISABLED',
    'OBJECT_STORAGE_HIGH_GROWTH', 'OBJECT_STORAGE_HIGH_ERROR_RATE'
));

-- +goose Down

ALTER TABLE recommendations DROP CONSTRAINT recommendations_type_check;
ALTER TABLE recommendations ADD CONSTRAINT recommendations_type_check CHECK (type IN (
    'OS_UPDATE', 'PACKAGE_UPDATE', 'DOCKER_UPDATE', 'DATABASE_UPDATE',
    'STORAGE_WARNING', 'CPU_WARNING', 'MEMORY_WARNING', 'DISK_WARNING',
    'SECURITY', 'CONFIGURATION', 'REBOOT_REQUIRED',
    'DATABASE_LOCK_CONTENTION', 'DATABASE_LOW_CACHE_HIT', 'DATABASE_HIGH_TEMP_IO',
    'DATABASE_REPLICATION_LAG', 'DATABASE_GROWTH_HIGH', 'DATABASE_SLOW_QUERY',
    'DATABASE_HIGH_QUERY_LATENCY', 'DATABASE_REDIS_EVICTIONS', 'DATABASE_UNAVAILABLE',
    'DATABASE_REDIS_BLOCKED_CLIENTS'
));

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'CPU_PERCENT', 'MEMORY_PERCENT', 'STORAGE_PERCENT', 'VM_UNREACHABLE',
    'CONTAINER_STOPPED', 'CONTAINER_RESTARTING', 'CONTAINER_UNHEALTHY', 'CONTAINER_RESTART_COUNT',
    'DB_UNREACHABLE', 'DB_CONNECTION_PERCENT', 'DB_LATENCY_P95_MS', 'DB_LOCKS_BLOCKED',
    'DB_REPLICATION_LAG_SECONDS', 'DB_STORAGE_BYTES', 'DB_CACHE_HIT_PERCENT'
));

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_alert_type_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_alert_type_check CHECK (alert_type IN (
    'VM_HIGH_CPU', 'VM_HIGH_MEMORY', 'VM_HIGH_STORAGE', 'VM_UNAVAILABLE',
    'DOCKER_CONTAINER_STOPPED', 'DOCKER_CONTAINER_RESTARTING', 'DOCKER_CONTAINER_UNHEALTHY', 'DOCKER_CONTAINER_OOM',
    'DATABASE_UNAVAILABLE', 'DATABASE_HIGH_CONNECTIONS', 'DATABASE_HIGH_LATENCY', 'DATABASE_LOCK_CONTENTION',
    'DATABASE_REPLICATION_LAG', 'DATABASE_HIGH_STORAGE', 'DATABASE_LOW_CACHE_HIT'
));

DROP TABLE object_storage_monitoring_health;
DROP TABLE object_storage_deep_metrics;
DROP TABLE object_storage_metrics;

DROP INDEX object_storages_resource_monitoring_idx;
DROP INDEX object_storages_monitoring_enabled_idx;

ALTER TABLE object_storages
    DROP COLUMN deleted_at,
    DROP COLUMN object_lock_status,
    DROP COLUMN public_access,
    DROP COLUMN encryption_status,
    DROP COLUMN versioning_status,
    DROP COLUMN health_status,
    DROP COLUMN last_metrics_at,
    DROP COLUMN connection_status,
    DROP COLUMN tls_skip_verify,
    DROP COLUMN tls_enabled,
    DROP COLUMN monitoring_enabled,
    DROP COLUMN name;

DROP TABLE standalone_object_storage_credentials;
