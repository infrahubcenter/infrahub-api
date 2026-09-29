-- +goose Up

-- Step 7: Linux package discovery, update detection, and recommendations.
-- packages/package_updates/recommendations already existed as Step 2
-- placeholders with the right shape for most of what this step needs
-- (including packages' (vm_id, name, architecture) uniqueness and
-- recommendations' NEW/ACKNOWLEDGED/DISMISSED/RESOLVED status enum) --
-- this migration only adds what's actually missing, and never touches
-- the older migration files.

-- Detected package manager family, stored on the VM so the packages page
-- can show "Detected: APT" without needing any package rows to exist yet
-- (spec #4). NULL means never successfully detected; a detection failure
-- must never overwrite a previously-good value with NULL (enforced in
-- application code, not the schema).
ALTER TABLE vms ADD COLUMN package_manager text
    CHECK (package_manager IS NULL OR package_manager IN ('APT', 'DNF', 'YUM', 'UNSUPPORTED'));

-- Mirrors vm_discovery_runs/vm_monitoring_runs exactly: "did the scan
-- succeed?" is a separate question from "what did it find?" (the
-- packages/package_updates tables).
CREATE TABLE package_discovery_runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id           uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    package_manager text,
    status          text NOT NULL CHECK (status IN ('RUNNING', 'SUCCESS', 'PARTIAL', 'FAILED')),
    package_count   integer,
    started_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    error_summary   text,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX package_discovery_runs_vm_started_idx ON package_discovery_runs(vm_id, started_at DESC);

-- Soft-delete: a package no longer reported by a scan is marked removed
-- rather than deleted outright, preserving history (spec #47) -- e.g. so
-- "this package was uninstalled on <date>" stays answerable. Listing
-- queries filter removed_at IS NULL by default.
ALTER TABLE packages ADD COLUMN removed_at timestamptz;

CREATE INDEX packages_vm_name_idx ON packages(vm_id, name);
CREATE INDEX packages_vm_last_discovered_idx ON packages(vm_id, last_discovered_at);

-- package_updates gets: (a) a real uniqueness constraint -- there wasn't
-- one before, so every scan would have INSERTed a fresh duplicate row
-- for the same package's update situation instead of refreshing it
-- (spec #19's deduplication requirement); (b) UNKNOWN added to severity,
-- since a package manager reporting "update exists, no severity given"
-- must not be forced into a fabricated LOW/MEDIUM/HIGH/CRITICAL guess
-- (spec #17); (c) recommendation_status's REVIEWED renamed to
-- ACKNOWLEDGED to match recommendations.status's vocabulary exactly
-- (spec #20); (d) security_status alongside the existing
-- is_security_update boolean, since "we don't know" is a real, distinct
-- answer from "confirmed not a security update" (spec #15); (e)
-- architecture/release for RPM's name-version-release.arch scheme
-- (spec #28) and Debian's multi-arch packages.
ALTER TABLE package_updates DROP CONSTRAINT IF EXISTS package_updates_severity_check;
ALTER TABLE package_updates ADD CONSTRAINT package_updates_severity_check
    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'));

ALTER TABLE package_updates DROP CONSTRAINT IF EXISTS package_updates_recommendation_status_check;
UPDATE package_updates SET recommendation_status = 'ACKNOWLEDGED' WHERE recommendation_status = 'REVIEWED';
ALTER TABLE package_updates ADD CONSTRAINT package_updates_recommendation_status_check
    CHECK (recommendation_status IN ('NEW', 'ACKNOWLEDGED', 'DISMISSED', 'RESOLVED'));

ALTER TABLE package_updates
    ADD COLUMN security_status text NOT NULL DEFAULT 'UNKNOWN'
        CHECK (security_status IN ('CONFIRMED', 'NOT_SECURITY', 'UNKNOWN')),
    ADD COLUMN architecture text,
    ADD COLUMN release text;

ALTER TABLE package_updates ADD CONSTRAINT package_updates_vm_package_unique UNIQUE (vm_id, package_id);
CREATE INDEX package_updates_package_id_idx ON package_updates(package_id);

-- recommendations: UNKNOWN added to severity for the same reason as
-- package_updates above (a PACKAGE_UPDATE recommendation with no
-- determinable severity must say so, not guess). source_type/source_id
-- is a generic, nullable link back to whatever row produced this
-- recommendation -- for this step, package_updates.id -- so a repeat
-- scan can find and update the existing recommendation in place instead
-- of inserting a new one every cycle (spec #19), and can resolve it when
-- the underlying package_updates row resolves (spec #48). Generic rather
-- than a package_update_id FK specifically so a later step's
-- OS/Docker/database recommendations can reuse the same column instead
-- of each adding their own.
ALTER TABLE recommendations DROP CONSTRAINT IF EXISTS recommendations_severity_check;
ALTER TABLE recommendations ADD CONSTRAINT recommendations_severity_check
    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'));

ALTER TABLE recommendations ADD COLUMN source_type text;
ALTER TABLE recommendations ADD COLUMN source_id uuid;

CREATE INDEX recommendations_resource_type_status_idx ON recommendations(resource_id, type, status);
CREATE UNIQUE INDEX recommendations_source_unique_idx ON recommendations(source_type, source_id) WHERE source_id IS NOT NULL;

-- +goose Down
DROP INDEX recommendations_source_unique_idx;
DROP INDEX recommendations_resource_type_status_idx;
ALTER TABLE recommendations DROP COLUMN source_id;
ALTER TABLE recommendations DROP COLUMN source_type;
ALTER TABLE recommendations DROP CONSTRAINT IF EXISTS recommendations_severity_check;
ALTER TABLE recommendations ADD CONSTRAINT recommendations_severity_check
    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));

DROP INDEX package_updates_package_id_idx;
ALTER TABLE package_updates DROP CONSTRAINT package_updates_vm_package_unique;
ALTER TABLE package_updates
    DROP COLUMN security_status,
    DROP COLUMN architecture,
    DROP COLUMN release;
ALTER TABLE package_updates DROP CONSTRAINT IF EXISTS package_updates_recommendation_status_check;
UPDATE package_updates SET recommendation_status = 'REVIEWED' WHERE recommendation_status = 'ACKNOWLEDGED';
ALTER TABLE package_updates ADD CONSTRAINT package_updates_recommendation_status_check
    CHECK (recommendation_status IN ('NEW', 'REVIEWED', 'DISMISSED', 'RESOLVED'));
ALTER TABLE package_updates DROP CONSTRAINT IF EXISTS package_updates_severity_check;
ALTER TABLE package_updates ADD CONSTRAINT package_updates_severity_check
    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));

DROP INDEX packages_vm_last_discovered_idx;
DROP INDEX packages_vm_name_idx;
ALTER TABLE packages DROP COLUMN removed_at;

DROP TABLE package_discovery_runs;

ALTER TABLE vms DROP COLUMN package_manager;
