-- +goose Up

-- Step 13: Standalone/managed database monitoring infrastructure.
-- The `databases` table (created in migration 005) is intentionally left
-- as a simple resource-backed configuration table. We now enhance it with
-- monitoring support via dedicated tables, mirroring database_instances'
-- architecture but using direct TCP connections instead of SSH tunnels.

-- Step 12's database_instances model remains unchanged and functional for
-- VM-hosted databases discovered via SSH. This migration adds the parallel
-- standalone database system, both working independently but presented in
-- the same dashboards.

-- Monitoring credentials for standalone databases (like
-- database_credentials for database_instances, but for the databases table).
CREATE TABLE standalone_database_credentials (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id       uuid NOT NULL UNIQUE REFERENCES databases(id) ON DELETE CASCADE,
    username          text,
    encrypted_password bytea,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER standalone_database_credentials_set_updated_at
    BEFORE UPDATE ON standalone_database_credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Enhance databases table with monitoring state (nullable fields so existing
-- databases continue working without requiring re-entry).
--
-- `engine`'s original CHECK (migration 005: POSTGRESQL/MYSQL/REDIS only)
-- is widened here to the same 6-value set as the new `type` column --
-- otherwise inserting a MariaDB/MongoDB/Valkey row would violate the old
-- constraint. `type` is the authoritative column going forward; `engine`
-- is kept in sync by the service layer for backward compatibility with
-- any pre-existing reader of that column.
ALTER TABLE databases DROP CONSTRAINT databases_engine_check;
ALTER TABLE databases ADD CONSTRAINT databases_engine_check CHECK (engine IN ('POSTGRESQL', 'MYSQL', 'MARIADB', 'MONGODB', 'REDIS', 'VALKEY'));

ALTER TABLE databases
    ADD COLUMN type text NOT NULL DEFAULT 'POSTGRESQL' CHECK (type IN ('POSTGRESQL', 'MYSQL', 'MARIADB', 'MONGODB', 'REDIS', 'VALKEY')),
    ADD COLUMN provider text CHECK (provider IN ('AWS_RDS', 'DIGITALOCEAN', 'SELF_HOSTED', 'OTHER')),
    ADD COLUMN region text,
    ADD COLUMN cluster_identifier text,
    ADD COLUMN endpoint text,
    ADD COLUMN monitoring_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN connection_status text NOT NULL DEFAULT 'UNKNOWN' CHECK (connection_status IN (
        'CONNECTED', 'AUTH_FAILED', 'TIMEOUT', 'REFUSED', 'TLS_ERROR', 'UNAVAILABLE', 'UNKNOWN'
    )),
    ADD COLUMN last_metrics_at timestamptz,
    ADD COLUMN tls_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN tls_skip_verify boolean NOT NULL DEFAULT false,
    -- Soft-delete (spec §82: removing a database from VM Control Center
    -- means removing the monitoring configuration only, never dropping
    -- the real external database) -- referenced by sql/queries/databases.sql's
    -- monitoring/dashboard queries, which filter on this column.
    ADD COLUMN deleted_at timestamptz;

CREATE INDEX databases_monitoring_enabled_idx ON databases(monitoring_enabled) WHERE monitoring_enabled = true;
CREATE INDEX databases_resource_monitoring_idx ON databases(resource_id, monitoring_enabled);

-- Common metrics for standalone databases (mirrors database_metric_snapshots
-- but for the databases table).
CREATE TABLE standalone_database_metrics (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id             uuid NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    captured_at             timestamptz NOT NULL DEFAULT now(),
    connections             integer,
    active_connections      integer,
    max_connections         integer,
    memory_usage_bytes      bigint,
    database_size_bytes     bigint,
    operations_per_second   double precision,
    transactions_per_second double precision,
    errors                  integer,
    uptime_seconds          bigint,
    health_status           text NOT NULL DEFAULT 'UNKNOWN' CHECK (health_status IN ('HEALTHY', 'WARNING', 'CRITICAL', 'UNKNOWN', 'OFFLINE')),
    metrics_status          text NOT NULL DEFAULT 'COMPLETE' CHECK (metrics_status IN ('COMPLETE', 'PARTIAL', 'FAILED')),
    metric_details          jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX standalone_database_metrics_database_idx ON standalone_database_metrics(database_id, captured_at DESC);

-- Deep metrics for standalone databases (mirrors database_deep_metrics).
CREATE TABLE standalone_database_deep_metrics (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id           uuid NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    captured_at           timestamptz NOT NULL DEFAULT now(),
    cache_hit_ratio       double precision,
    deadlocks             integer,
    temp_files            bigint,
    temp_bytes            bigint,
    wal_bytes             bigint,
    checkpoints_timed     integer,
    checkpoints_req       integer,
    commits_per_sec       double precision,
    rollbacks_per_sec     double precision,
    locks_waiting         integer,
    locks_blocked         integer,
    replication_status    text,
    replication_lag_seconds double precision,
    replica_count         integer,
    latency_p50_ms        double precision,
    latency_p95_ms        double precision,
    latency_p99_ms        double precision,
    growth_bytes_per_day  double precision,
    metrics_status        text NOT NULL DEFAULT 'COMPLETE' CHECK (metrics_status IN ('COMPLETE', 'PARTIAL', 'FAILED')),
    details               jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX standalone_database_deep_metrics_database_idx ON standalone_database_deep_metrics(database_id, captured_at DESC);

-- Query-level metrics for standalone databases (mirrors database_query_metrics).
CREATE TABLE standalone_database_query_metrics (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id           uuid NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    query_fingerprint     text NOT NULL,
    captured_at           timestamptz NOT NULL DEFAULT now(),
    calls                 bigint,
    total_time_ms         double precision,
    avg_time_ms           double precision,
    rows                  bigint,
    blocks_read           bigint,
    blocks_hit            bigint,
    database_name         text,
    database_user         text,
    normalized_text       text,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX standalone_database_query_metrics_database_idx ON standalone_database_query_metrics(database_id, captured_at DESC);
CREATE INDEX standalone_database_query_metrics_fingerprint_idx ON standalone_database_query_metrics(database_id, query_fingerprint, captured_at DESC);

-- Collector health for standalone databases (mirrors database_monitoring_health).
CREATE TABLE standalone_database_monitoring_health (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id         uuid NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    tier                text NOT NULL CHECK (tier IN ('FAST', 'DEEP')),
    last_success_at     timestamptz,
    last_failure_at     timestamptz,
    last_duration_ms    integer,
    last_error          text,
    metrics_collected   bigint NOT NULL DEFAULT 0,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT standalone_database_monitoring_health_unique UNIQUE (database_id, tier)
);

CREATE TRIGGER standalone_database_monitoring_health_set_updated_at
    BEFORE UPDATE ON standalone_database_monitoring_health
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down

DROP TABLE standalone_database_monitoring_health;
DROP TABLE standalone_database_query_metrics;
DROP TABLE standalone_database_deep_metrics;
DROP TABLE standalone_database_metrics;

ALTER TABLE databases
    DROP COLUMN deleted_at,
    DROP COLUMN tls_skip_verify,
    DROP COLUMN tls_enabled,
    DROP COLUMN last_metrics_at,
    DROP COLUMN connection_status,
    DROP COLUMN monitoring_enabled,
    DROP COLUMN cluster_identifier,
    DROP COLUMN region,
    DROP COLUMN provider,
    DROP COLUMN endpoint,
    DROP COLUMN type;

ALTER TABLE databases DROP CONSTRAINT databases_engine_check;
ALTER TABLE databases ADD CONSTRAINT databases_engine_check CHECK (engine IN ('POSTGRESQL', 'MYSQL', 'REDIS'));

DROP TABLE standalone_database_credentials;
