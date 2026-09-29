-- +goose Up

-- Step 9: OS/kernel/reboot update detection, and update planning (never
-- execution -- that's Step 10). Reuses Step 7's packages/package_updates/
-- recommendations wholesale (spec #8: "Do NOT create duplicate package
-- update records") and the existing operations/operation_logs tables
-- (migration 010, a Step-2-era placeholder whose operation_type CHECK
-- already includes 'OS_UPDATE'/'PACKAGE_UPDATE' and which already has
-- exactly the started_at/completed_at/exit_code/summary shape spec #39
-- describes as "new" -- extended here with a link to update_plans rather
-- than duplicated as a parallel "update_operations" table, honoring this
-- step's own "do not recreate existing architecture" instruction).

-- os_updates existed as a Step-2 placeholder (migration 008) with a
-- shape that predates Step 7's later dedup/vocabulary conventions
-- (package_updates/recommendations were upgraded in migration 016;
-- os_updates never was, since nothing wrote to it yet -- confirmed unused
-- by any application code). Reshaped in place to spec #7's model rather
-- than left as dead schema: current_version/available_version (renamed
-- from the _os_ prefixed originals), update_type restricted to
-- PATCH/MINOR/MAJOR/RELEASE (dropping the old placeholder's 'SECURITY',
-- which belongs on the linked recommendation, not here), a real
-- UP_TO_DATE/UPDATE_AVAILABLE/UNKNOWN/BLOCKED status (renamed from
-- recommendation_status, whose old NEW/REVIEWED/DISMISSED/RESOLVED
-- vocabulary belonged to a different concept entirely -- acknowledgement
-- state, which lives on the linked recommendation via source_type/
-- source_id, exactly like package_updates already does), and a new
-- release_channel column (spec #6). severity/reboot_required are
-- dropped: severity is derived at recommendation-creation time from real
-- evidence (spec #21), never stored redundantly here, and reboot state
-- is its own concept (see the vms columns below) since it can be true
-- independent of any OS-level release update existing.
ALTER TABLE os_updates DROP CONSTRAINT IF EXISTS os_updates_update_type_check;
ALTER TABLE os_updates DROP CONSTRAINT IF EXISTS os_updates_severity_check;
ALTER TABLE os_updates DROP CONSTRAINT IF EXISTS os_updates_recommendation_status_check;

ALTER TABLE os_updates RENAME COLUMN current_os_version TO current_version;
ALTER TABLE os_updates RENAME COLUMN available_os_version TO available_version;
ALTER TABLE os_updates RENAME COLUMN recommendation_status TO status;

ALTER TABLE os_updates ALTER COLUMN available_version DROP NOT NULL;
ALTER TABLE os_updates ALTER COLUMN update_type DROP NOT NULL;
ALTER TABLE os_updates ALTER COLUMN status SET DEFAULT 'UNKNOWN';
ALTER TABLE os_updates DROP COLUMN severity;
ALTER TABLE os_updates DROP COLUMN reboot_required;
ALTER TABLE os_updates ADD COLUMN release_channel text;

ALTER TABLE os_updates ADD CONSTRAINT os_updates_update_type_check
    CHECK (update_type IS NULL OR update_type IN ('PATCH', 'MINOR', 'MAJOR', 'RELEASE'));
ALTER TABLE os_updates ADD CONSTRAINT os_updates_status_check
    CHECK (status IN ('UP_TO_DATE', 'UPDATE_AVAILABLE', 'UNKNOWN', 'BLOCKED'));
ALTER TABLE os_updates ADD CONSTRAINT os_updates_release_channel_check
    CHECK (release_channel IS NULL OR release_channel IN ('stable', 'LTS', 'non-LTS', 'unknown'));
-- Single latest-known-status row per VM (mirrors vms.docker_daemon_status/
-- package_manager's "current state, re-detected and upserted each scan"
-- shape) rather than a history table -- vm_id was already NOT NULL and
-- indexed; this just makes "one per VM" an actual guarantee so upserts
-- are well-defined.
ALTER TABLE os_updates ADD CONSTRAINT os_updates_vm_unique UNIQUE (vm_id);

-- Kernel/reboot state, like docker_daemon_status, is "the current known
-- state of this VM" rather than history, so it lives directly on vms
-- (re-detected and overwritten each Update Center scan) rather than a
-- separate table. kernel_running reuses the existing vms.kernel_version
-- column (already populated by Step 5 discovery's `uname -r` read) --
-- Update Center's own scan simply re-writes it fresh too, the same
-- column, the same meaning, never a second source of truth for "what
-- kernel is this VM currently running."
ALTER TABLE vms ADD COLUMN kernel_available text;
ALTER TABLE vms ADD COLUMN reboot_status text
    CHECK (reboot_status IS NULL OR reboot_status IN ('NOT_REQUIRED', 'REQUIRED', 'UNKNOWN'));
ALTER TABLE vms ADD COLUMN reboot_reason text;

-- Admin-created, admin-reviewed set of selected package updates for one
-- VM (spec #22-23). Step 9 only ever produces DRAFT/READY/CANCELLED --
-- APPROVED/EXECUTING/COMPLETED/FAILED/STALE are declared here for Step
-- 10's execution flow (and STALE for revalidation, spec #28) but no
-- Step 9 code path ever sets them.
CREATE TABLE update_plans (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id       uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    status      text NOT NULL DEFAULT 'DRAFT' CHECK (status IN (
        'DRAFT', 'READY', 'APPROVED', 'EXECUTING', 'COMPLETED', 'FAILED', 'CANCELLED', 'STALE'
    )),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX update_plans_vm_id_idx ON update_plans(vm_id);

CREATE TRIGGER update_plans_set_updated_at
    BEFORE UPDATE ON update_plans
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A snapshot of the selected update at plan-creation time (spec #24: "This
-- protects the plan from silently changing when package metadata changes
-- later") -- current_version/target_version/security_update/severity are
-- copied from packages/package_updates at creation time, never
-- re-resolved from a live join, so a plan a scan later invalidates can be
-- detected (spec #28, comparing the snapshot to current package_updates)
-- rather than silently drifting.
CREATE TABLE update_plan_items (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    update_plan_id   uuid NOT NULL REFERENCES update_plans(id) ON DELETE CASCADE,
    package_id       uuid NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    package_name     text NOT NULL,
    current_version  text NOT NULL,
    target_version   text NOT NULL,
    update_type      text NOT NULL DEFAULT 'PACKAGE' CHECK (update_type IN ('PACKAGE', 'KERNEL')),
    security_update  boolean NOT NULL DEFAULT false,
    severity         text NOT NULL DEFAULT 'UNKNOWN' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT update_plan_items_plan_package_unique UNIQUE (update_plan_id, package_id)
);

CREATE INDEX update_plan_items_plan_id_idx ON update_plan_items(update_plan_id);

-- Links the pre-existing operations table (migration 010) to the plan
-- that produced it, so Step 10's execution engine knows which plan it's
-- running and this step's "no concurrent update operation" precheck
-- (spec #40) can query operations directly rather than a second table.
-- Nullable: other operation_type values are never plan-linked.
ALTER TABLE operations ADD COLUMN update_plan_id uuid REFERENCES update_plans(id) ON DELETE SET NULL;

CREATE INDEX operations_update_plan_id_idx ON operations(update_plan_id) WHERE update_plan_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS operations_update_plan_id_idx;
ALTER TABLE operations DROP COLUMN update_plan_id;

DROP TABLE update_plan_items;
DROP TABLE update_plans;

ALTER TABLE vms DROP COLUMN reboot_reason;
ALTER TABLE vms DROP COLUMN reboot_status;
ALTER TABLE vms DROP COLUMN kernel_available;

ALTER TABLE os_updates DROP CONSTRAINT os_updates_vm_unique;
ALTER TABLE os_updates DROP CONSTRAINT os_updates_release_channel_check;
ALTER TABLE os_updates DROP CONSTRAINT os_updates_status_check;
ALTER TABLE os_updates DROP CONSTRAINT os_updates_update_type_check;

ALTER TABLE os_updates DROP COLUMN release_channel;
ALTER TABLE os_updates ADD COLUMN reboot_required boolean NOT NULL DEFAULT false;
ALTER TABLE os_updates ADD COLUMN severity text NOT NULL DEFAULT 'LOW';
ALTER TABLE os_updates ALTER COLUMN status DROP DEFAULT;
ALTER TABLE os_updates ALTER COLUMN update_type SET NOT NULL;
ALTER TABLE os_updates ALTER COLUMN available_version SET NOT NULL;

ALTER TABLE os_updates RENAME COLUMN status TO recommendation_status;
ALTER TABLE os_updates RENAME COLUMN available_version TO available_os_version;
ALTER TABLE os_updates RENAME COLUMN current_version TO current_os_version;

ALTER TABLE os_updates ALTER COLUMN recommendation_status SET DEFAULT 'NEW';
ALTER TABLE os_updates ADD CONSTRAINT os_updates_recommendation_status_check
    CHECK (recommendation_status IN ('NEW', 'REVIEWED', 'DISMISSED', 'RESOLVED'));
ALTER TABLE os_updates ADD CONSTRAINT os_updates_severity_check
    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));
ALTER TABLE os_updates ADD CONSTRAINT os_updates_update_type_check
    CHECK (update_type IN ('PATCH', 'MINOR', 'MAJOR', 'SECURITY'));
