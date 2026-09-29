-- +goose Up

-- Trusted host keys, one current key per VM resource (TOFU: trust is only
-- ever established by an explicit admin action -- see
-- docs/ssh-architecture.md). A changed fingerprint on a later connection
-- must be rejected, not silently replaced, so this table is the source of
-- truth an incoming host key is compared against.
CREATE TABLE ssh_host_keys (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id      uuid NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
    host             text NOT NULL,
    port             integer NOT NULL,
    algorithm        text NOT NULL,
    fingerprint      text NOT NULL,
    public_key       text NOT NULL,
    first_seen_at    timestamptz NOT NULL DEFAULT now(),
    last_verified_at timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER ssh_host_keys_set_updated_at
    BEFORE UPDATE ON ssh_host_keys
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One row per discovery attempt -- append-only history (never overwritten)
-- so a failure is visible even after a later attempt succeeds. Never
-- stores credentials, only outcome/timing/a short safe error summary.
CREATE TABLE vm_discovery_runs (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id          uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    status         text NOT NULL CHECK (status IN ('RUNNING', 'SUCCESS', 'PARTIAL', 'FAILED')),
    started_at     timestamptz NOT NULL DEFAULT now(),
    completed_at   timestamptz,
    error_summary  text,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX vm_discovery_runs_vm_started_idx ON vm_discovery_runs(vm_id, started_at DESC);

-- distribution_id: the machine-readable ID= line from /etc/os-release
-- (e.g. "ubuntu"), kept separate from the free-text os_name/os_version
-- Step 2 already has, so future steps can branch on it reliably instead
-- of parsing os_name again.
--
-- connection_status / last_connection_at / last_connection_error: SSH
-- reachability is a distinct concept from resources.status (Step 5 spec
-- §19 -- "do not confuse connection state with monitoring health"). A VM
-- can be resources.status = UNKNOWN with connection_status = FAILED
-- (e.g. wrong credential on a host that's actually up); see
-- docs/ssh-architecture.md for the full status-mapping table.
ALTER TABLE vms
    ADD COLUMN distribution_id       text,
    ADD COLUMN connection_status     text NOT NULL DEFAULT 'NOT_CONFIGURED'
        CHECK (connection_status IN (
            'NOT_CONFIGURED', 'READY', 'CONNECTING', 'CONNECTED',
            'FAILED', 'HOST_KEY_UNKNOWN', 'HOST_KEY_CHANGED'
        )),
    ADD COLUMN last_connection_at    timestamptz,
    ADD COLUMN last_connection_error text;

-- +goose Down
ALTER TABLE vms
    DROP COLUMN last_connection_error,
    DROP COLUMN last_connection_at,
    DROP COLUMN connection_status,
    DROP COLUMN distribution_id;

DROP TABLE vm_discovery_runs;
DROP TABLE ssh_host_keys;
