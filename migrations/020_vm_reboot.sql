-- +goose Up

-- Step 11: controlled VM reboot + post-reboot verification. A genuinely
-- new lifecycle, not a fit for the existing operations table (operations.
-- operation_type has no REBOOT value, and its shape -- one command_hash/
-- exit_code/summary per row -- has no room for the reboot-specific
-- lifecycle timestamps this table needs: sent-at, disconnected-at,
-- reconnected-at, timeout-at). Widening operations.operation_type instead
-- was considered and rejected: a reboot's status vocabulary
-- (WAITING_FOR_VM/RECONNECTING has no update-operation equivalent) would
-- have forced operations.status wider still for a concept that doesn't
-- apply to package updates at all.
CREATE TABLE reboot_operations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id           uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    reason          text NOT NULL DEFAULT 'ADMIN_REQUEST' CHECK (reason IN (
        'KERNEL_UPDATE', 'PACKAGE_UPDATE', 'ADMIN_REQUEST', 'OS_UPDATE', 'OTHER'
    )),
    status          text NOT NULL DEFAULT 'PENDING' CHECK (status IN (
        'PENDING', 'PRECHECK', 'REBOOTING', 'WAITING_FOR_VM', 'RECONNECTING',
        'VERIFYING', 'SUCCESS', 'PARTIAL', 'FAILED', 'TIMEOUT', 'UNKNOWN', 'CANCELLED', 'INTERRUPTED'
    )),
    started_at      timestamptz,
    reboot_sent_at  timestamptz,
    disconnected_at timestamptz,
    reconnected_at  timestamptz,
    completed_at    timestamptz,
    timeout_at      timestamptz,
    error_summary   text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX reboot_operations_vm_created_idx ON reboot_operations(vm_id, created_at DESC);
CREATE INDEX reboot_operations_status_idx ON reboot_operations(status);

CREATE TRIGGER reboot_operations_set_updated_at
    BEFORE UPDATE ON reboot_operations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Live output transcript, mirroring operation_logs (migration 010)
-- exactly -- a separate table rather than a reused one only because
-- operation_logs.operation_id has a hard FK into operations, which a
-- reboot_operations row is not.
CREATE TABLE reboot_operation_logs (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    reboot_operation_id uuid NOT NULL REFERENCES reboot_operations(id) ON DELETE CASCADE,
    sequence_number  integer NOT NULL,
    stream           text NOT NULL CHECK (stream IN ('STDOUT', 'STDERR', 'SYSTEM')),
    message          text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT reboot_operation_logs_operation_sequence_unique UNIQUE (reboot_operation_id, sequence_number)
);

CREATE INDEX reboot_operation_logs_operation_id_idx ON reboot_operation_logs(reboot_operation_id);

-- Every before/after comparison point (spec #55-57): one row per signal
-- checked, expected_value being the pre-reboot/target value and
-- actual_value the real post-reboot observation -- never invented,
-- always from a real command's output.
CREATE TABLE reboot_verification_results (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    reboot_operation_id  uuid NOT NULL REFERENCES reboot_operations(id) ON DELETE CASCADE,
    check_type           text NOT NULL CHECK (check_type IN (
        'SSH', 'BOOT_ID', 'UPTIME', 'OS', 'KERNEL', 'STORAGE', 'DOCKER',
        'CONTAINERS', 'PACKAGES', 'REBOOT_REQUIRED'
    )),
    expected_value       text,
    actual_value         text,
    status               text NOT NULL DEFAULT 'UNKNOWN' CHECK (status IN (
        'VERIFIED', 'FAILED', 'UNKNOWN', 'WARNING', 'NOT_APPLICABLE'
    )),
    checked_at           timestamptz NOT NULL DEFAULT now(),
    error_summary        text,
    CONSTRAINT reboot_verification_results_operation_check_unique UNIQUE (reboot_operation_id, check_type)
);

CREATE INDEX reboot_verification_results_operation_id_idx ON reboot_verification_results(reboot_operation_id);

-- Operational state (spec #40/#41): explicitly separate from monitoring's
-- health state (healthy/warning/critical/unknown, computed from metrics)
-- and from connection_status (a raw SSH-attempt outcome) -- this is "what
-- is this VM doing right now, from this application's point of view."
-- Re-detected/overwritten by the reboot and update execution engines at
-- well-defined transition points; never a general-purpose replacement for
-- either existing concept.
ALTER TABLE vms ADD COLUMN operational_state text NOT NULL DEFAULT 'UNKNOWN'
    CHECK (operational_state IN ('ONLINE', 'OFFLINE', 'REBOOTING', 'UPDATING', 'UNKNOWN'));

-- A reboot-required recommendation is its own type, deduplicated the same
-- way every other Step 7-pattern recommendation is: source_type/source_id
-- as the natural idempotency key (source_id here is the vm_id, since
-- there is exactly one live reboot-required condition per VM at a time).
ALTER TABLE recommendations DROP CONSTRAINT recommendations_type_check;
ALTER TABLE recommendations ADD CONSTRAINT recommendations_type_check CHECK (type IN (
    'OS_UPDATE', 'PACKAGE_UPDATE', 'DOCKER_UPDATE', 'DATABASE_UPDATE',
    'STORAGE_WARNING', 'CPU_WARNING', 'MEMORY_WARNING', 'DISK_WARNING',
    'SECURITY', 'CONFIGURATION', 'REBOOT_REQUIRED'
));

-- +goose Down
ALTER TABLE recommendations DROP CONSTRAINT recommendations_type_check;
ALTER TABLE recommendations ADD CONSTRAINT recommendations_type_check CHECK (type IN (
    'OS_UPDATE', 'PACKAGE_UPDATE', 'DOCKER_UPDATE', 'DATABASE_UPDATE',
    'STORAGE_WARNING', 'CPU_WARNING', 'MEMORY_WARNING', 'DISK_WARNING',
    'SECURITY', 'CONFIGURATION'
));

ALTER TABLE vms DROP COLUMN operational_state;

DROP TABLE reboot_verification_results;
DROP TABLE reboot_operation_logs;
DROP TABLE reboot_operations;
