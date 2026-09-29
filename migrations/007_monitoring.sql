-- +goose Up

-- Common, resource-agnostic time-series metrics. This table intentionally
-- only holds metrics that apply broadly across resource types; a
-- resource-type-specific metrics table (e.g. database connection counts)
-- can be added later without touching this one.
CREATE TABLE monitoring_snapshots (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id           uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    captured_at           timestamptz NOT NULL DEFAULT now(),
    cpu_usage_percent     numeric(5, 2),
    memory_used_bytes     bigint,
    memory_total_bytes    bigint,
    storage_used_bytes    bigint,
    storage_total_bytes   bigint,
    network_rx_bytes      bigint,
    network_tx_bytes      bigint,
    status                text CHECK (status IN ('UNKNOWN', 'ONLINE', 'OFFLINE', 'WARNING', 'ERROR', 'DISABLED'))
);

CREATE INDEX monitoring_snapshots_resource_captured_idx ON monitoring_snapshots(resource_id, captured_at);

CREATE TABLE vm_filesystems (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id           uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    mount_point     text NOT NULL,
    filesystem      text,
    total_bytes     bigint,
    used_bytes      bigint,
    available_bytes bigint,
    usage_percent   numeric(5, 2),
    captured_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX vm_filesystems_vm_captured_idx ON vm_filesystems(vm_id, captured_at);

-- +goose Down
DROP TABLE vm_filesystems;
DROP TABLE monitoring_snapshots;
