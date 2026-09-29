-- +goose Up

-- Step 8: Docker discovery, container/image/network/volume inventory, and
-- container metrics (including live streaming). docker_containers and
-- docker_images already existed as Step 2 placeholders -- extended here,
-- never recreated. docker_networks/docker_container_networks/
-- docker_volumes/docker_discovery_runs/docker_container_metric_snapshots
-- are new.

-- Docker daemon/version status is a single "latest known" record per VM
-- (not time-series -- docker_discovery_runs already tracks run history),
-- so it lives directly on vms, mirroring how package_manager was added
-- in Step 7. docker_installed (Step 5, boolean "docker present at last
-- VM discovery") is intentionally left alone and untouched by this
-- step -- docker_daemon_status is the richer, Docker-specific status
-- this step re-checks independently (spec #3: "Docker availability must
-- be checked again before Docker-specific operations").
ALTER TABLE vms ADD COLUMN docker_daemon_status text
    CHECK (docker_daemon_status IS NULL OR docker_daemon_status IN
        ('NOT_INSTALLED', 'INSTALLED', 'RUNNING', 'UNAVAILABLE', 'PERMISSION_DENIED', 'UNKNOWN'));
ALTER TABLE vms ADD COLUMN docker_engine_version text;
ALTER TABLE vms ADD COLUMN docker_api_version text;
ALTER TABLE vms ADD COLUMN docker_cli_version text;
-- Everything from spec #6 (storage/logging/cgroup driver, cgroup version,
-- Docker-reported kernel/OS/architecture, NCPU, total memory) as a small
-- nested blob rather than 10 more columns -- it's only ever displayed as
-- a group on the Docker overview page, never individually filtered/
-- queried, and jsonb naturally omits whatever a given Docker install
-- doesn't expose rather than needing 10 separate nullable columns.
ALTER TABLE vms ADD COLUMN docker_info jsonb NOT NULL DEFAULT '{}'::jsonb;

-- docker_containers: status keeps its existing meaning (Docker's own
-- State.Status enum) but its CHECK is corrected to Docker's real state
-- vocabulary (spec #11) -- the original list included the non-Docker
-- value 'STOPPED', which Docker itself never reports (a stopped
-- container's real state is 'exited'). A new `state` column holds the
-- human-readable status Docker also reports alongside it (e.g. "Up 2
-- days", "Exited (0) 3 hours ago") -- descriptive only, never used for
-- filtering, which is what `status` is for.
ALTER TABLE docker_containers DROP CONSTRAINT IF EXISTS docker_containers_status_check;
ALTER TABLE docker_containers ADD CONSTRAINT docker_containers_status_check
    CHECK (status IN ('CREATED', 'RUNNING', 'RESTARTING', 'EXITED', 'PAUSED', 'DEAD', 'REMOVING', 'UNKNOWN'));

ALTER TABLE docker_containers
    ADD COLUMN image_id           text,
    ADD COLUMN state              text,
    ADD COLUMN health             text
        CHECK (health IS NULL OR health IN ('HEALTHY', 'UNHEALTHY', 'STARTING', 'NO_HEALTHCHECK', 'UNKNOWN')),
    ADD COLUMN command             text,
    ADD COLUMN started_at_remote   timestamptz,
    ADD COLUMN restart_count       integer,
    ADD COLUMN platform            text,
    -- Safe mount metadata only (source/destination/read_only/type) --
    -- never file contents. Structured JSON, same convention as `ports`.
    ADD COLUMN mounts              jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- Soft-deleted, not hard-deleted, when a scan no longer sees the
    -- container -- preserves metric history (spec #58).
    ADD COLUMN removed_at          timestamptz;

-- docker_images: the original (vm_id, image_id) uniqueness collapsed
-- multiple repository:tag pairs sharing one image ID into a single row,
-- silently overwriting one tag's record with another's (spec #22's
-- explicit warning). Repointed at (vm_id, image_id, repository, tag) so
-- e.g. "myapp:1.2" and "myapp:latest" pointing at the same image ID are
-- both retained as distinct rows.
ALTER TABLE docker_images DROP CONSTRAINT IF EXISTS docker_images_vm_image_unique;
ALTER TABLE docker_images
    ADD COLUMN digest     text,
    ADD COLUMN removed_at timestamptz;
-- NULL tag/repository would defeat the new composite uniqueness (NULLs
-- are never equal to each other in a unique constraint), so untagged
-- images/repositories are normalized to '<none>' -- Docker's own
-- convention for exactly this case -- rather than left NULL.
ALTER TABLE docker_images ALTER COLUMN tag SET DEFAULT '<none>';
UPDATE docker_images SET tag = '<none>' WHERE tag IS NULL;
ALTER TABLE docker_images ALTER COLUMN tag SET NOT NULL;
ALTER TABLE docker_images ADD CONSTRAINT docker_images_vm_image_repo_tag_unique
    UNIQUE (vm_id, image_id, repository, tag);

CREATE TABLE docker_networks (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id              uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    network_id         text NOT NULL,
    name               text NOT NULL,
    driver             text,
    scope              text,
    internal           boolean NOT NULL DEFAULT false,
    attachable         boolean NOT NULL DEFAULT false,
    created_at_remote  timestamptz,
    last_discovered_at timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    removed_at         timestamptz,
    CONSTRAINT docker_networks_vm_network_unique UNIQUE (vm_id, network_id)
);

CREATE INDEX docker_networks_vm_id_idx ON docker_networks(vm_id);

CREATE TRIGGER docker_networks_set_updated_at
    BEFORE UPDATE ON docker_networks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One row per container-network attachment (spec #19). Both FKs cascade:
-- membership is meaningless once either side is gone, and this table is
-- current-state-only (not history), so a hard delete on disappearance is
-- correct here (unlike containers/images/networks/volumes themselves,
-- which soft-delete).
CREATE TABLE docker_container_networks (
    container_id uuid NOT NULL REFERENCES docker_containers(id) ON DELETE CASCADE,
    network_id   uuid NOT NULL REFERENCES docker_networks(id) ON DELETE CASCADE,
    ip_address   text,
    gateway      text,
    mac_address  text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (container_id, network_id)
);

CREATE INDEX docker_container_networks_network_id_idx ON docker_container_networks(network_id);

CREATE TABLE docker_volumes (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id              uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    volume_name        text NOT NULL,
    driver             text,
    mountpoint         text,
    scope              text,
    created_at_remote  timestamptz,
    last_discovered_at timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    removed_at         timestamptz,
    CONSTRAINT docker_volumes_vm_name_unique UNIQUE (vm_id, volume_name)
);

CREATE INDEX docker_volumes_vm_id_idx ON docker_volumes(vm_id);

CREATE TRIGGER docker_volumes_set_updated_at
    BEFORE UPDATE ON docker_volumes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Mirrors vm_discovery_runs/vm_monitoring_runs/package_discovery_runs
-- exactly: "did the scan succeed?" separate from "what did it find?".
CREATE TABLE docker_discovery_runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id           uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    status          text NOT NULL CHECK (status IN ('RUNNING', 'SUCCESS', 'PARTIAL', 'FAILED')),
    container_count integer,
    image_count     integer,
    network_count   integer,
    volume_count    integer,
    started_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    error_summary   text,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX docker_discovery_runs_vm_started_idx ON docker_discovery_runs(vm_id, started_at DESC);

-- Per-container metric samples (spec #35). Raw cumulative counters only
-- (network/block I/O) -- rates are computed at read time from two
-- consecutive rows (spec #38/#39 place rate calculation in "the
-- service/API", not the storage layer). cpu_percent/memory_percent are
-- already percentages, not counters, straight from `docker stats`.
CREATE TABLE docker_container_metric_snapshots (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id        uuid NOT NULL REFERENCES docker_containers(id) ON DELETE CASCADE,
    vm_id               uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    captured_at         timestamptz NOT NULL DEFAULT now(),
    cpu_percent         double precision,
    memory_usage_bytes  bigint,
    memory_limit_bytes  bigint,
    memory_percent      double precision,
    network_rx_bytes    bigint,
    network_tx_bytes    bigint,
    block_read_bytes    bigint,
    block_write_bytes   bigint,
    pids                integer
);

CREATE INDEX docker_container_metric_snapshots_vm_container_captured_idx
    ON docker_container_metric_snapshots(vm_id, container_id, captured_at DESC);
CREATE INDEX docker_container_metric_snapshots_container_captured_idx
    ON docker_container_metric_snapshots(container_id, captured_at DESC);

-- +goose Down
ALTER TABLE vms DROP COLUMN docker_info;
ALTER TABLE vms DROP COLUMN docker_cli_version;
ALTER TABLE vms DROP COLUMN docker_api_version;
ALTER TABLE vms DROP COLUMN docker_engine_version;
ALTER TABLE vms DROP COLUMN docker_daemon_status;

DROP TABLE docker_container_metric_snapshots;
DROP TABLE docker_discovery_runs;
DROP TABLE docker_volumes;
DROP TABLE docker_container_networks;
DROP TABLE docker_networks;

ALTER TABLE docker_images DROP CONSTRAINT docker_images_vm_image_repo_tag_unique;
ALTER TABLE docker_images ALTER COLUMN tag DROP NOT NULL;
ALTER TABLE docker_images ALTER COLUMN tag DROP DEFAULT;
UPDATE docker_images SET tag = NULL WHERE tag = '<none>';
ALTER TABLE docker_images
    DROP COLUMN digest,
    DROP COLUMN removed_at;
ALTER TABLE docker_images ADD CONSTRAINT docker_images_vm_image_unique UNIQUE (vm_id, image_id);

ALTER TABLE docker_containers
    DROP COLUMN image_id,
    DROP COLUMN state,
    DROP COLUMN health,
    DROP COLUMN command,
    DROP COLUMN started_at_remote,
    DROP COLUMN restart_count,
    DROP COLUMN platform,
    DROP COLUMN mounts,
    DROP COLUMN removed_at;
ALTER TABLE docker_containers DROP CONSTRAINT IF EXISTS docker_containers_status_check;
ALTER TABLE docker_containers ADD CONSTRAINT docker_containers_status_check
    CHECK (status IN ('RUNNING', 'STOPPED', 'RESTARTING', 'PAUSED', 'EXITED', 'UNKNOWN'));
