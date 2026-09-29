-- +goose Up
-- InfraHub's new push-based VM Agent (see /vm-agent at the repo root) --
-- structurally mirrors docker_agent_tokens (041_docker_agent.sql) exactly:
-- only the bearer token's hash is ever stored, shown once in plaintext at
-- generation time. Additive, alongside the existing SSH-based monitoring
-- scheduler (services.VMMonitoringService/MonitoringScheduler), never a
-- replacement -- a VM with no agent installed keeps working exactly as
-- before via SSH-polled monitoring_snapshots; a VM with the agent
-- installed additionally gets live, agent-pushed metrics in a fully
-- separate table (vm_agent_metric_snapshots below), never mixed into
-- monitoring_snapshots (whose CPU-delta math assumes every row it reads
-- carries the SSH scheduler's own raw jiffie counters).
CREATE TABLE vm_agent_tokens (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_resource_id     uuid NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
    token_hash         bytea NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_connected_at  timestamptz
);

CREATE UNIQUE INDEX vm_agent_tokens_hash_idx ON vm_agent_tokens(token_hash);

ALTER TABLE vms
    ADD COLUMN vm_agent_installed         boolean NOT NULL DEFAULT false,
    ADD COLUMN vm_agent_version           text,
    ADD COLUMN vm_agent_last_heartbeat_at timestamptz;

-- Agent-pushed metric samples -- field set matches monitoring_snapshots'
-- Step 6 fields (007/015_vm_monitoring.sql) so the two sources read as
-- directly comparable in the UI, but this table is entirely separate: the
-- agent computes CPU%/network-rate deltas itself, from its own in-memory
-- previous-sample state (see vm-agent/metrics.go), so unlike
-- monitoring_snapshots there are no raw jiffie counters to persist here
-- for a next-cycle delta.
CREATE TABLE vm_agent_metric_snapshots (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id                  uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    captured_at            timestamptz NOT NULL DEFAULT now(),
    cpu_percent            double precision,
    cpu_cores              integer,
    memory_used_bytes      bigint,
    memory_total_bytes     bigint,
    swap_used_bytes        bigint,
    swap_total_bytes       bigint,
    load_1m                double precision,
    load_5m                double precision,
    load_15m               double precision,
    uptime_seconds         bigint,
    -- Root filesystem only in v1 -- matches the plan's stated scope; the
    -- SSH-based path's per-mount-point vm_filesystems table is untouched
    -- and unaffected.
    storage_used_bytes     bigint,
    storage_total_bytes    bigint,
    network_rx_rate_bytes  bigint,
    network_tx_rate_bytes  bigint,
    process_count          integer
);

CREATE INDEX vm_agent_metric_snapshots_vm_captured_idx
    ON vm_agent_metric_snapshots(vm_id, captured_at DESC);

-- +goose Down
DROP TABLE vm_agent_metric_snapshots;
ALTER TABLE vms
    DROP COLUMN vm_agent_installed,
    DROP COLUMN vm_agent_version,
    DROP COLUMN vm_agent_last_heartbeat_at;
DROP TABLE vm_agent_tokens;
