-- +goose Up

-- Step 10: the execution engine. Continues Step 9's decision to reuse the
-- existing operations/operation_logs tables (migration 010) rather than
-- create a parallel "update_operations" table -- this step's own spec
-- repeats the "do not recreate existing architecture" instruction, and
-- operations already has exactly the id/status/started_at/completed_at/
-- exit_code/summary/created_by(requested_by) shape the spec asks for.
-- Extended here with the wider status vocabulary execution needs and a
-- command_hash column for integrity verification (spec: "store a hash of
-- the exact command that was executed, generate once, execute that exact
-- command, never regenerate a different one mid-execution").
ALTER TABLE operations DROP CONSTRAINT operations_status_check;
ALTER TABLE operations ADD CONSTRAINT operations_status_check CHECK (status IN (
    'PENDING', 'APPROVED', 'CONNECTING', 'RUNNING', 'VERIFYING',
    'SUCCESS', 'FAILED', 'PARTIAL', 'CANCELLED', 'INTERRUPTED'
));

-- SHA-256 hex digest of the exact command string that was (or will be)
-- executed. Not a secret -- package names and flags are not sensitive --
-- this exists purely so an auditor can confirm the executed command
-- matches what was approved, without re-deriving it.
ALTER TABLE operations ADD COLUMN command_hash text;

-- update_plans already declared EXECUTING/COMPLETED/FAILED in migration
-- 018 for this step; only PARTIAL (a successful-but-incomplete outcome,
-- distinct from FAILED) was missing.
ALTER TABLE update_plans DROP CONSTRAINT update_plans_status_check;
ALTER TABLE update_plans ADD CONSTRAINT update_plans_status_check CHECK (status IN (
    'DRAFT', 'READY', 'APPROVED', 'EXECUTING', 'COMPLETED', 'FAILED', 'PARTIAL', 'CANCELLED', 'STALE'
));

-- Detected (never admin-typed) sudo capability of the configured SSH user,
-- re-detected fresh at every precheck/revalidation and never trusted
-- stale for an actual execution decision -- this column is a display/
-- last-known-value cache only, mirroring vms.docker_daemon_status/
-- package_manager's existing "current known state" pattern.
ALTER TABLE vms ADD COLUMN privilege_mode text
    CHECK (privilege_mode IS NULL OR privilege_mode IN ('DIRECT_ROOT', 'SUDO_NOPASSWD', 'UNSUPPORTED'));

-- Per-step progress within one operation (spec: "Pre-check, Connect,
-- Refresh package metadata, Execute update, Verify versions, Detect
-- reboot, Refresh VM inventory, Complete" -- shown to the admin as a
-- checklist that only ever reflects backend-confirmed completed steps,
-- never fabricated progress). output_summary/error_summary are bounded,
-- sanitized text -- full raw output lives in operation_logs, never here.
CREATE TABLE update_operation_steps (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id    uuid NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    step_number     integer NOT NULL,
    step_type       text NOT NULL CHECK (step_type IN (
        'PRECHECK', 'CONNECT', 'REFRESH_METADATA', 'UPDATE', 'VERIFY', 'DISCOVERY'
    )),
    status          text NOT NULL DEFAULT 'PENDING' CHECK (status IN (
        'PENDING', 'RUNNING', 'SUCCESS', 'FAILED', 'SKIPPED'
    )),
    started_at      timestamptz,
    completed_at    timestamptz,
    exit_code       integer,
    output_summary  text,
    error_summary   text,
    CONSTRAINT update_operation_steps_operation_step_unique UNIQUE (operation_id, step_number)
);

CREATE INDEX update_operation_steps_operation_id_idx ON update_operation_steps(operation_id);

-- Per-package before/after verification (spec: "never assume success from
-- exit code alone -- verify each selected package's actual installed
-- version"). before_version/target_version are copied from the plan item
-- at execution start; after_version is read from the VM post-update.
CREATE TABLE update_operation_results (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id    uuid NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    package_name    text NOT NULL,
    before_version  text NOT NULL,
    target_version  text NOT NULL,
    after_version   text,
    status          text NOT NULL DEFAULT 'UNKNOWN' CHECK (status IN (
        'VERIFIED', 'FAILED', 'UNKNOWN', 'NOT_APPLICABLE'
    )),
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- One row per package per operation: verifyPackages() is called both
    -- by the automatic post-update VERIFY step and by the admin-triggered
    -- POST .../verify re-check, which must update the existing row rather
    -- than accumulate a duplicate every time it's called.
    CONSTRAINT update_operation_results_operation_package_unique UNIQUE (operation_id, package_name)
);

CREATE INDEX update_operation_results_operation_id_idx ON update_operation_results(operation_id);

-- +goose Down
DROP TABLE update_operation_results;
DROP TABLE update_operation_steps;

ALTER TABLE vms DROP COLUMN privilege_mode;

ALTER TABLE update_plans DROP CONSTRAINT update_plans_status_check;
ALTER TABLE update_plans ADD CONSTRAINT update_plans_status_check CHECK (status IN (
    'DRAFT', 'READY', 'APPROVED', 'EXECUTING', 'COMPLETED', 'FAILED', 'CANCELLED', 'STALE'
));

ALTER TABLE operations DROP COLUMN command_hash;

ALTER TABLE operations DROP CONSTRAINT operations_status_check;
ALTER TABLE operations ADD CONSTRAINT operations_status_check CHECK (status IN (
    'PENDING', 'APPROVED', 'RUNNING', 'SUCCESS', 'FAILED', 'CANCELLED'
));
