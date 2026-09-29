-- name: UpdateVMDockerStatus :one
-- Like UpdateVMPackageManager (Step 7): only ever called with a real
-- detection result. A transient failure never overwrites a previously-
-- good status/version with NULL/UNKNOWN -- the caller simply skips this
-- call in that case.
UPDATE vms
SET docker_daemon_status = $2, docker_engine_version = $3, docker_api_version = $4,
    docker_cli_version = $5, docker_info = $6
WHERE id = $1
RETURNING *;

-- name: ListDockerScanEnabledVMs :many
-- Discovery scheduler's work list: active VMs with SSH configured (same
-- base eligibility as monitoring/package scanning).
SELECT r.id AS resource_id, v.id AS vm_id, r.name
FROM resources r
JOIN vms v ON v.resource_id = r.id
WHERE r.resource_type = 'VM'
  AND r.deleted_at IS NULL
  AND r.status != 'DISABLED'
  AND v.ssh_key_credential_id IS NOT NULL
ORDER BY r.name;

-- name: ListDockerMetricsEnabledVMs :many
-- Metrics scheduler's work list: only VMs already confirmed to have a
-- running Docker daemon -- no point opening an SSH connection just to
-- learn Docker isn't reachable on every 15s tick.
SELECT r.id AS resource_id, v.id AS vm_id, r.name
FROM resources r
JOIN vms v ON v.resource_id = r.id
WHERE r.resource_type = 'VM'
  AND r.deleted_at IS NULL
  AND r.status != 'DISABLED'
  AND v.docker_daemon_status = 'RUNNING'
  AND v.ssh_key_credential_id IS NOT NULL
ORDER BY r.name;

-- name: CreateDockerDiscoveryRun :one
INSERT INTO docker_discovery_runs (vm_id, status) VALUES ($1, 'RUNNING') RETURNING *;

-- name: CompleteDockerDiscoveryRun :one
UPDATE docker_discovery_runs
SET status = $2, container_count = $3, image_count = $4, network_count = $5, volume_count = $6, error_summary = $7, completed_at = now()
WHERE id = $1
RETURNING *;

-- name: ListDockerDiscoveryRunsByVM :many
SELECT * FROM docker_discovery_runs WHERE vm_id = $1 ORDER BY started_at DESC LIMIT $2;

-- name: GetLatestDockerDiscoveryRun :one
SELECT * FROM docker_discovery_runs WHERE vm_id = $1 ORDER BY started_at DESC LIMIT 1;

-- === Containers ===

-- name: UpsertDockerContainer :one
INSERT INTO docker_containers (
    vm_id, container_id, name, image, image_id, image_tag, status, state, health,
    command, ports, mounts, restart_count, platform, created_at_remote, started_at_remote, last_discovered_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, now()
)
ON CONFLICT (vm_id, container_id) DO UPDATE SET
    name = EXCLUDED.name, image = EXCLUDED.image, image_id = EXCLUDED.image_id,
    image_tag = EXCLUDED.image_tag, status = EXCLUDED.status, state = EXCLUDED.state,
    health = EXCLUDED.health, command = EXCLUDED.command, ports = EXCLUDED.ports,
    mounts = EXCLUDED.mounts, restart_count = EXCLUDED.restart_count, platform = EXCLUDED.platform,
    started_at_remote = EXCLUDED.started_at_remote, last_discovered_at = now(), removed_at = NULL
RETURNING *;

-- name: MarkDockerContainersRemovedSince :exec
UPDATE docker_containers
SET removed_at = now()
WHERE vm_id = $1 AND removed_at IS NULL AND last_discovered_at < $2;

-- name: GetDockerContainerByID :one
SELECT * FROM docker_containers WHERE id = $1 AND vm_id = $2 AND removed_at IS NULL;

-- name: GetDockerContainerWithVMByID :one
-- Resolves a container ID straight to its owning VM's resource
-- (id/name/workspace/status), with no vm_id already known -- needed
-- by the top-level Docker Logs stream
-- (GET /api/docker/containers/:containerId/logs/stream), which is reached
-- from the cross-VM Docker section rather than a specific VM's own page.
SELECT
    dc.id, dc.vm_id, dc.container_id, dc.name, dc.display_name, dc.status,
    r.id AS vm_resource_id, r.name AS vm_name, r.workspace_id, r.status AS vm_status
FROM docker_containers dc
JOIN vms v ON v.id = dc.vm_id
JOIN resources r ON r.id = v.resource_id AND r.deleted_at IS NULL
WHERE dc.id = $1 AND dc.removed_at IS NULL;

-- name: ListDockerContainersByVM :many
SELECT * FROM docker_containers
WHERE vm_id = $1 AND removed_at IS NULL
    AND (sqlc.narg('search')::text IS NULL OR name ILIKE '%' || sqlc.narg('search')::text || '%' OR image ILIKE '%' || sqlc.narg('search')::text || '%')
    AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
    AND (sqlc.narg('health')::text IS NULL OR health = sqlc.narg('health'))
ORDER BY name
LIMIT $2 OFFSET $3;

-- name: CountDockerContainersByVM :one
SELECT count(*) FROM docker_containers
WHERE vm_id = $1 AND removed_at IS NULL
    AND (sqlc.narg('search')::text IS NULL OR name ILIKE '%' || sqlc.narg('search')::text || '%' OR image ILIKE '%' || sqlc.narg('search')::text || '%')
    AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
    AND (sqlc.narg('health')::text IS NULL OR health = sqlc.narg('health'));

-- name: ListRunningDockerContainersByVM :many
-- The metrics collector's per-cycle work list for one VM.
SELECT * FROM docker_containers WHERE vm_id = $1 AND removed_at IS NULL AND status = 'RUNNING';

-- name: GetDockerSummaryByVM :one
SELECT
    count(*) FILTER (WHERE removed_at IS NULL) AS total,
    count(*) FILTER (WHERE removed_at IS NULL AND status = 'RUNNING') AS running,
    count(*) FILTER (WHERE removed_at IS NULL AND status != 'RUNNING') AS stopped,
    count(*) FILTER (WHERE removed_at IS NULL AND health = 'UNHEALTHY') AS unhealthy
FROM docker_containers
WHERE vm_id = $1;

-- name: GetDockerSummaryAcrossVMs :one
-- Cross-VM aggregate for the Monitoring dashboard's Docker overview bucket
-- (Step 19 Phase 3) -- mirrors GetDockerSummaryByVM's per-VM FILTER shape,
-- generalized across every VM the caller is authorized on. Scoped by
-- resources.id (resource_ids narg), joined through vms.resource_id since
-- docker_containers.vm_id/docker_images.vm_id reference vms.id, not
-- resources.id, while authorization scoping is always expressed in terms
-- of resources.id everywhere else in this codebase. Uses separate
-- subqueries per count rather than one multi-table JOIN specifically to
-- avoid join-fan-out double-counting when a VM has both many containers
-- and many images.
WITH scoped_vms AS (
    SELECT v.id, v.docker_installed FROM vms v
    JOIN resources r ON r.id = v.resource_id
    WHERE r.deleted_at IS NULL
      AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR v.resource_id = ANY(sqlc.narg('resource_ids')::uuid[]))
)
SELECT
  (SELECT count(*) FROM scoped_vms WHERE docker_installed) AS docker_hosts,
  (SELECT count(*) FROM docker_containers WHERE vm_id IN (SELECT id FROM scoped_vms) AND removed_at IS NULL) AS containers_total,
  (SELECT count(*) FROM docker_containers WHERE vm_id IN (SELECT id FROM scoped_vms) AND removed_at IS NULL AND status = 'RUNNING') AS containers_running,
  (SELECT count(*) FROM docker_containers WHERE vm_id IN (SELECT id FROM scoped_vms) AND removed_at IS NULL AND status != 'RUNNING') AS containers_stopped,
  (SELECT count(*) FROM docker_containers WHERE vm_id IN (SELECT id FROM scoped_vms) AND removed_at IS NULL AND health = 'UNHEALTHY') AS containers_unhealthy,
  (SELECT count(*) FROM docker_images WHERE vm_id IN (SELECT id FROM scoped_vms) AND removed_at IS NULL) AS images_total;

-- === Images ===

-- name: UpsertDockerImage :one
INSERT INTO docker_images (vm_id, repository, tag, image_id, digest, size_bytes, created_at_remote, last_discovered_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (vm_id, image_id, repository, tag)
DO UPDATE SET digest = EXCLUDED.digest, size_bytes = EXCLUDED.size_bytes,
              created_at_remote = EXCLUDED.created_at_remote, last_discovered_at = now(), removed_at = NULL
RETURNING *;

-- name: MarkDockerImagesRemovedSince :exec
UPDATE docker_images
SET removed_at = now()
WHERE vm_id = $1 AND removed_at IS NULL AND last_discovered_at < $2;

-- name: ListDockerImagesByVM :many
SELECT * FROM docker_images WHERE vm_id = $1 AND removed_at IS NULL ORDER BY repository, tag;

-- name: CountDockerImagesByVM :one
SELECT count(*) FROM docker_images WHERE vm_id = $1 AND removed_at IS NULL;

-- === Networks ===

-- name: UpsertDockerNetwork :one
INSERT INTO docker_networks (vm_id, network_id, name, driver, scope, internal, attachable, created_at_remote, last_discovered_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
ON CONFLICT (vm_id, network_id)
DO UPDATE SET name = EXCLUDED.name, driver = EXCLUDED.driver, scope = EXCLUDED.scope,
              internal = EXCLUDED.internal, attachable = EXCLUDED.attachable,
              last_discovered_at = now(), removed_at = NULL
RETURNING *;

-- name: MarkDockerNetworksRemovedSince :exec
UPDATE docker_networks
SET removed_at = now()
WHERE vm_id = $1 AND removed_at IS NULL AND last_discovered_at < $2;

-- name: ListDockerNetworksByVM :many
SELECT * FROM docker_networks WHERE vm_id = $1 AND removed_at IS NULL ORDER BY name;

-- name: CountDockerNetworksByVM :one
SELECT count(*) FROM docker_networks WHERE vm_id = $1 AND removed_at IS NULL;

-- name: UpsertDockerContainerNetwork :exec
INSERT INTO docker_container_networks (container_id, network_id, ip_address, gateway, mac_address)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (container_id, network_id)
DO UPDATE SET ip_address = EXCLUDED.ip_address, gateway = EXCLUDED.gateway, mac_address = EXCLUDED.mac_address;

-- name: DeleteContainerNetworkMemberships :exec
-- Membership rows are current-state-only (spec #19 -- not a history
-- table), so a scan simply replaces them wholesale for the container
-- rather than tracking removal separately.
DELETE FROM docker_container_networks WHERE container_id = $1;

-- name: ListNetworksForContainer :many
SELECT n.name, n.driver, cn.ip_address, cn.gateway, cn.mac_address
FROM docker_container_networks cn
JOIN docker_networks n ON n.id = cn.network_id
WHERE cn.container_id = $1 AND n.removed_at IS NULL
ORDER BY n.name;

-- === Volumes ===

-- name: UpsertDockerVolume :one
INSERT INTO docker_volumes (vm_id, volume_name, driver, mountpoint, scope, created_at_remote, last_discovered_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
ON CONFLICT (vm_id, volume_name)
DO UPDATE SET driver = EXCLUDED.driver, mountpoint = EXCLUDED.mountpoint, scope = EXCLUDED.scope,
              last_discovered_at = now(), removed_at = NULL
RETURNING *;

-- name: MarkDockerVolumesRemovedSince :exec
UPDATE docker_volumes
SET removed_at = now()
WHERE vm_id = $1 AND removed_at IS NULL AND last_discovered_at < $2;

-- name: ListDockerVolumesByVM :many
SELECT * FROM docker_volumes WHERE vm_id = $1 AND removed_at IS NULL ORDER BY volume_name;

-- name: CountDockerVolumesByVM :one
SELECT count(*) FROM docker_volumes WHERE vm_id = $1 AND removed_at IS NULL;

-- === Container metrics ===

-- name: InsertDockerContainerMetricSnapshot :one
INSERT INTO docker_container_metric_snapshots (
    container_id, vm_id, cpu_percent, memory_usage_bytes, memory_limit_bytes, memory_percent,
    network_rx_bytes, network_tx_bytes, block_read_bytes, block_write_bytes, pids
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: GetLatestDockerContainerMetricSnapshot :one
SELECT * FROM docker_container_metric_snapshots
WHERE container_id = $1
ORDER BY captured_at DESC
LIMIT 1;

-- name: ListDockerContainerMetricHistory :many
SELECT * FROM docker_container_metric_snapshots
WHERE container_id = $1 AND vm_id = $2 AND captured_at >= $3 AND captured_at <= $4
ORDER BY captured_at DESC
LIMIT $5;

-- name: DeleteOldDockerContainerMetricSnapshots :exec
DELETE FROM docker_container_metric_snapshots WHERE captured_at < $1;
