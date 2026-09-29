-- Docker Hosts: a standalone, admin-configured Docker agent target,
-- mirroring sql/queries/k8s.sql's own pattern exactly (see migration
-- 046_docker_hosts.sql). Deliberately no per-resource member-permission
-- queries here, same reasoning as k8s.sql: a Member never gets a host
-- detail page, only the cross-host Monitoring/Logs dashboards gated by
-- docker_access_grants' docker.monitor/docker.logs.

-- name: CreateDockerHost :one
INSERT INTO docker_hosts (resource_id)
VALUES ($1)
RETURNING *;

-- name: GetDockerHostByID :one
SELECT * FROM docker_hosts WHERE id = $1 AND deleted_at IS NULL;

-- name: GetDockerHostResourceByID :one
-- Mirrors GetK8sClusterResourceByID exactly -- resolves resources.id (not
-- docker_hosts.id) to a live, non-deleted DOCKER_HOST resource.
SELECT * FROM resources
WHERE id = $1 AND resource_type = 'DOCKER_HOST' AND deleted_at IS NULL;

-- name: GetDockerHostByResourceID :one
SELECT * FROM docker_hosts WHERE resource_id = $1 AND deleted_at IS NULL;

-- name: GetDockerHostWithResourceByID :one
-- Detail lookup joining the owning resource/workspace -- mirrors
-- GetK8sClusterWithResourceByID exactly.
SELECT
    h.*, r.name AS resource_name, r.workspace_id, w.name AS workspace_name
FROM docker_hosts h
JOIN resources r ON r.id = h.resource_id
JOIN workspaces w ON w.id = r.workspace_id
WHERE h.id = $1 AND h.deleted_at IS NULL;

-- name: ListDockerHostsForAdmin :many
-- The admin host-management page's list -- every non-deleted host, with
-- display names resolved.
SELECT
    h.*, r.name AS resource_name, r.workspace_id, w.name AS workspace_name
FROM docker_hosts h
JOIN resources r ON r.id = h.resource_id
JOIN workspaces w ON w.id = r.workspace_id
WHERE h.deleted_at IS NULL
ORDER BY r.name;

-- name: SetDockerHostMonitoringEnabled :one
UPDATE docker_hosts SET monitoring_enabled = $2 WHERE id = $1 RETURNING *;

-- name: UpdateDockerHostEngineVersion :exec
UPDATE docker_hosts SET engine_version = $2, last_connection_at = now() WHERE id = $1;

-- name: UpdateDockerHostEngineVersionByResourceID :exec
-- Keyed by resources.id, not docker_hosts.id -- lets a periodic,
-- resource-id-scoped touchpoint (DockerHostLogCaptureScheduler's own
-- cycle, which already round-trips to each connected host's agent every
-- interval) refresh engine_version automatically without a separate
-- docker_hosts.id lookup first. Mirrors
-- UpdateDockerHostAgentTokenLastConnectedByResourceID's own reasoning.
UPDATE docker_hosts SET engine_version = $2, last_connection_at = now() WHERE resource_id = $1;

-- name: SoftDeleteDockerHostResource :exec
-- Removes the monitoring registration only -- never touches the real
-- Docker daemon. monitoring_enabled also cleared so no scheduler ever
-- picks this instance up again. Mirrors SoftDeleteK8sClusterResource.
UPDATE docker_hosts SET deleted_at = now(), monitoring_enabled = false WHERE id = $1;

-- name: UpsertDockerHostContainerSighting :one
-- Stamps first_seen_at the first time this container_id is ever reported
-- for this host; every later call only moves last_seen_at, so
-- first_seen_at stays a genuine "when did InfraHub first see this
-- container" fact -- see migration 055's own doc comment.
INSERT INTO docker_host_container_sightings (docker_host_resource_id, container_id)
VALUES ($1, $2)
ON CONFLICT (docker_host_resource_id, container_id)
DO UPDATE SET last_seen_at = now()
RETURNING *;
