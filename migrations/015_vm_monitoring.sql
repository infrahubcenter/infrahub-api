-- +goose Up

-- Step 6: real VM monitoring. Extends the placeholder monitoring schema
-- from 007_monitoring.sql rather than replacing it -- monitoring_snapshots
-- and vm_filesystems already existed with the right shape for the fields
-- Step 2 anticipated; this migration adds the fields Step 6 actually
-- needs and the two new per-dimension history tables (network, and the
-- monitoring_runs audit trail, mirroring vm_discovery_runs).

-- A VM/resource opts out of monitoring here. Lives on resources (not vms)
-- for the same reason resources.status does: monitoring is meant to be
-- resource-type-agnostic even though only VMs are collected today.
ALTER TABLE resources ADD COLUMN monitoring_enabled boolean NOT NULL DEFAULT true;

-- monitoring_snapshots.status was never populated by any Step before this
-- one (InsertMonitoringSnapshot accepted it as a parameter, but nothing
-- called it) and its original CHECK reused the resource-status enum
-- (UNKNOWN/ONLINE/OFFLINE/WARNING/ERROR/DISABLED), which is the wrong
-- vocabulary for a monitoring *health* value (Step 6 spec #35/#36: health
-- is explicitly distinct from connection/resource status). Repurpose the
-- column rather than adding a redundant one.
ALTER TABLE monitoring_snapshots DROP CONSTRAINT IF EXISTS monitoring_snapshots_status_check;
ALTER TABLE monitoring_snapshots ADD CONSTRAINT monitoring_snapshots_status_check
    CHECK (status IN ('HEALTHY', 'WARNING', 'CRITICAL', 'UNKNOWN', 'OFFLINE'));

-- Both pre-existing percent columns were `numeric(5,2)` (pgtype.Numeric --
-- an awkward, unused-until-now Go type backed by math/big). Every new
-- percent column in this migration uses `double precision` instead
-- (float8/pgtype.Float8, a plain Go float64); converting these two keeps
-- the whole feature on one consistent, simple numeric type.
ALTER TABLE monitoring_snapshots ALTER COLUMN cpu_usage_percent TYPE double precision;
ALTER TABLE vm_filesystems ALTER COLUMN usage_percent TYPE double precision;

ALTER TABLE monitoring_snapshots
    ADD COLUMN cpu_user_percent    double precision,
    ADD COLUMN cpu_system_percent  double precision,
    ADD COLUMN cpu_iowait_percent  double precision,
    ADD COLUMN cpu_idle_percent    double precision,
    ADD COLUMN cpu_cores           integer,
    -- The full raw /proc/stat counter set from this sample (user, nice,
    -- system, idle, iowait, irq, softirq, steal), JSON-encoded, kept only
    -- to compute the *next* cycle's delta (Step 6 spec #10-12: CPU% is
    -- always a delta between two samples, never derived from one read).
    -- Every one of those 8 counters is needed to compute next cycle's
    -- user/system/iowait/idle percentages, not just total+idle, so this is
    -- one JSON blob rather than 8 more bigint columns. Internal-only --
    -- never returned by the API.
    ADD COLUMN cpu_raw_jiffies      text,
    ADD COLUMN swap_used_bytes     bigint,
    ADD COLUMN swap_total_bytes    bigint,
    ADD COLUMN load_1m             double precision,
    ADD COLUMN load_5m             double precision,
    ADD COLUMN load_15m            double precision,
    ADD COLUMN uptime_seconds      bigint,
    -- Aggregated across all non-loopback interfaces; per-interface rates
    -- live in vm_network_snapshots.
    ADD COLUMN network_rx_rate_bytes bigint,
    ADD COLUMN network_tx_rate_bytes bigint,
    ADD COLUMN process_count          integer,
    ADD COLUMN process_running_count  integer,
    ADD COLUMN process_sleeping_count integer,
    ADD COLUMN process_zombie_count   integer;

-- Explicit DESC index for the "latest snapshot" / "recent history" query
-- shape (Step 6 spec #53); the original 007 index is left in place rather
-- than dropped since removing it isn't necessary for this to be fast.
CREATE INDEX monitoring_snapshots_resource_captured_desc_idx
    ON monitoring_snapshots(resource_id, captured_at DESC);

-- vm_filesystems already has every field Step 6 spec #29 asks for under
-- the name "vm_filesystem_snapshots" -- reused as-is per spec #18/#20
-- ("use the existing vm_filesystems table"). Only the mount-point-scoped
-- index is new.
CREATE INDEX vm_filesystems_vm_mount_captured_idx
    ON vm_filesystems(vm_id, mount_point, captured_at DESC);

CREATE TABLE vm_network_snapshots (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id          uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    interface_name text NOT NULL,
    rx_bytes       bigint NOT NULL,
    tx_bytes       bigint NOT NULL,
    rx_packets     bigint NOT NULL,
    tx_packets     bigint NOT NULL,
    rx_errors      bigint NOT NULL,
    tx_errors      bigint NOT NULL,
    rx_dropped     bigint NOT NULL,
    tx_dropped     bigint NOT NULL,
    -- NULL on an interface's first-ever sample (Step 6 spec #25: rate
    -- requires a delta against a previous sample).
    rx_rate_bytes  bigint,
    tx_rate_bytes  bigint,
    captured_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX vm_network_snapshots_vm_iface_captured_idx
    ON vm_network_snapshots(vm_id, interface_name, captured_at DESC);

-- Mirrors vm_discovery_runs exactly: "did the collection succeed?" is a
-- separate question from "what did it collect?" (the snapshot tables).
CREATE TABLE vm_monitoring_runs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id         uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    status        text NOT NULL CHECK (status IN ('RUNNING', 'SUCCESS', 'PARTIAL', 'FAILED')),
    started_at    timestamptz NOT NULL DEFAULT now(),
    completed_at  timestamptz,
    error_summary text,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX vm_monitoring_runs_vm_started_idx ON vm_monitoring_runs(vm_id, started_at DESC);

-- +goose Down
DROP TABLE vm_monitoring_runs;
DROP TABLE vm_network_snapshots;
DROP INDEX vm_filesystems_vm_mount_captured_idx;
DROP INDEX monitoring_snapshots_resource_captured_desc_idx;
ALTER TABLE monitoring_snapshots
    DROP COLUMN cpu_user_percent,
    DROP COLUMN cpu_system_percent,
    DROP COLUMN cpu_iowait_percent,
    DROP COLUMN cpu_idle_percent,
    DROP COLUMN cpu_cores,
    DROP COLUMN cpu_raw_jiffies,
    DROP COLUMN swap_used_bytes,
    DROP COLUMN swap_total_bytes,
    DROP COLUMN load_1m,
    DROP COLUMN load_5m,
    DROP COLUMN load_15m,
    DROP COLUMN uptime_seconds,
    DROP COLUMN network_rx_rate_bytes,
    DROP COLUMN network_tx_rate_bytes,
    DROP COLUMN process_count,
    DROP COLUMN process_running_count,
    DROP COLUMN process_sleeping_count,
    DROP COLUMN process_zombie_count;
ALTER TABLE monitoring_snapshots DROP CONSTRAINT IF EXISTS monitoring_snapshots_status_check;
ALTER TABLE monitoring_snapshots ADD CONSTRAINT monitoring_snapshots_status_check
    CHECK (status IN ('UNKNOWN', 'ONLINE', 'OFFLINE', 'WARNING', 'ERROR', 'DISABLED'));
ALTER TABLE vm_filesystems ALTER COLUMN usage_percent TYPE numeric(5, 2);
ALTER TABLE monitoring_snapshots ALTER COLUMN cpu_usage_percent TYPE numeric(5, 2);
ALTER TABLE resources DROP COLUMN monitoring_enabled;
