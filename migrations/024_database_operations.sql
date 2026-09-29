-- +goose Up

-- Step 14: controlled database operations + admin remediation, on top of
-- Step 13's standalone database monitoring. Widen recommendations.type
-- first -- Step 13's deep-metrics service already tries to upsert these
-- ten DATABASE_* recommendation types (database_deep_metrics_service.go /
-- database_metrics_service.go), but migration 023 never added them to
-- this CHECK constraint, so every one of those upserts has been silently
-- failing since Step 13 shipped (UpsertRecommendationBySource's error is
-- intentionally swallowed, matching every other best-effort recommendation
-- write in this project -- monitoring must never fail because a
-- recommendation couldn't be written). Fixing this here, not as a
-- standalone migration, because Step 14's "Review a recommendation ->
-- propose an operation" flow is meaningless without it.
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

-- operation_type is deliberately a small, closed set of backend-defined
-- templates (spec: "Never allow arbitrary SQL/Redis/MongoDB/shell
-- commands... All commands/operations must be backend-defined templates").
-- RESTART/REPLICATION_ACTION/CONFIG_CHANGE/UPGRADE are included for
-- forward compatibility (the spec's "prepare a controlled workflow for
-- future... upgrades" and "Admin must explicitly initiate any future
-- supported replication operation") but no adapter currently declares
-- support for them -- see database_operation_adapter.go's capability
-- tables. There is deliberately no architecture in this project (no SSH,
-- no shell) to actually restart a standalone database's process, so
-- RESTART can never be honestly implemented until/unless a provider API
-- integration is added.
CREATE TABLE database_operations (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id        uuid NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    operation_type     text NOT NULL CHECK (operation_type IN (
        'RESTART', 'CANCEL_QUERY', 'TERMINATE_SESSION', 'VACUUM', 'ANALYZE',
        'REDIS_MAINTENANCE', 'REPLICATION_ACTION', 'CONFIG_CHANGE', 'UPGRADE'
    )),
    status             text NOT NULL DEFAULT 'WAITING_CONFIRMATION' CHECK (status IN (
        'PENDING', 'WAITING_CONFIRMATION', 'RUNNING', 'SUCCESS', 'FAILED', 'CANCELLED', 'TIMEOUT'
    )),
    requested_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    reason             text,
    -- Structured, backend-validated parameters only (e.g. {"target_id":
    -- "12345"} for a session to cancel/terminate) -- never a raw
    -- query/command string. See database_operation_adapter.go's
    -- ValidateOperationParams, which is the only code path allowed to
    -- turn this into something executed.
    parameters         jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- The exact backend-generated command/action text shown to the Admin
    -- before confirmation (spec's "Admin should see exactly what the
    -- system intends to execute") -- always derived from operation_type +
    -- parameters, never accepted from the client.
    command_preview    text NOT NULL DEFAULT '',
    recommendation_id  uuid REFERENCES recommendations(id) ON DELETE SET NULL,
    confirmed_at       timestamptz,
    started_at         timestamptz,
    completed_at       timestamptz,
    timeout_at         timestamptz,
    result_summary     text,
    result_detail      jsonb,
    error_summary      text,
    health_before      text,
    health_after       text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX database_operations_database_created_idx ON database_operations(database_id, created_at DESC);
CREATE INDEX database_operations_status_idx ON database_operations(status);

CREATE TRIGGER database_operations_set_updated_at
    BEFORE UPDATE ON database_operations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Live execution transcript, mirroring reboot_operation_logs (migration
-- 020) exactly -- never carries credentials or raw query/command text
-- (spec: "Do not stream credentials or sensitive SQL/query text").
CREATE TABLE database_operation_logs (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    database_operation_id  uuid NOT NULL REFERENCES database_operations(id) ON DELETE CASCADE,
    sequence_number        integer NOT NULL,
    stream                 text NOT NULL CHECK (stream IN ('SYSTEM', 'STDOUT', 'STDERR')),
    message                text NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT database_operation_logs_operation_sequence_unique UNIQUE (database_operation_id, sequence_number)
);

CREATE INDEX database_operation_logs_operation_id_idx ON database_operation_logs(database_operation_id);

-- +goose Down
DROP TABLE database_operation_logs;
DROP TABLE database_operations;

ALTER TABLE recommendations DROP CONSTRAINT recommendations_type_check;
ALTER TABLE recommendations ADD CONSTRAINT recommendations_type_check CHECK (type IN (
    'OS_UPDATE', 'PACKAGE_UPDATE', 'DOCKER_UPDATE', 'DATABASE_UPDATE',
    'STORAGE_WARNING', 'CPU_WARNING', 'MEMORY_WARNING', 'DISK_WARNING',
    'SECURITY', 'CONFIGURATION', 'REBOOT_REQUIRED'
));
