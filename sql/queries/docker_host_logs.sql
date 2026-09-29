-- Docker Host log history: mirrors sql/queries/docker_logs.sql exactly,
-- except a Docker Host has no discovery-populated docker_containers row
-- to key off -- docker_host_container_sightings (migration 055/057) is
-- both the discovery record AND the log-capture cursor here, upserted by
-- the capture cycle itself (services.DockerHostLogCaptureService) via the
-- already-existing UpsertDockerHostContainerSighting, since ListContainers
-- (handlers/docker_host.go) only refreshes it when a browser is actually
-- polling that host's container list. See migration 057.

-- name: ListDockerHostsForLogCapture :many
-- Every monitored, non-deleted Docker Host's resource id -- the capture
-- scheduler's own work list, one level up from
-- ListRunningDockerContainersForLogCapture: a Docker Host's container list
-- can only ever be discovered live, from its own connected agent, so this
-- scheduler discovers-and-captures in one pass instead of reading a
-- pre-populated container table.
SELECT resource_id FROM docker_hosts WHERE deleted_at IS NULL AND monitoring_enabled = true;

-- name: InsertDockerHostContainerLogLine :exec
INSERT INTO docker_host_container_log_lines (docker_host_container_sighting_id, logged_at, line)
VALUES ($1, $2, $3);

-- name: UpdateDockerHostContainerLogCursor :exec
UPDATE docker_host_container_sightings SET last_log_captured_at = $2 WHERE id = $1;

-- name: SearchDockerHostContainerLogLines :many
-- Admin/Member authorization (docker.logs) happens in the handler before
-- this ever runs, exactly like SearchDockerLogLines. Resolved by
-- (host resource id, raw container id) rather than a sighting uuid, since
-- that's what the URL/caller actually has.
SELECT l.id, l.logged_at, l.line
FROM docker_host_container_log_lines l
JOIN docker_host_container_sightings s ON s.id = l.docker_host_container_sighting_id
WHERE s.docker_host_resource_id = sqlc.arg('docker_host_resource_id')::uuid
  AND s.container_id = sqlc.arg('container_id')::text
  AND l.logged_at >= sqlc.arg('from_ts')::timestamptz
  AND l.logged_at <= sqlc.arg('to_ts')::timestamptz
  AND (sqlc.narg('query')::text IS NULL OR l.line ILIKE '%' || sqlc.narg('query')::text || '%')
ORDER BY l.logged_at DESC
LIMIT sqlc.arg('page_limit')::int OFFSET sqlc.arg('page_offset')::int;

-- name: CountDockerHostContainerLogLines :one
SELECT count(*)
FROM docker_host_container_log_lines l
JOIN docker_host_container_sightings s ON s.id = l.docker_host_container_sighting_id
WHERE s.docker_host_resource_id = sqlc.arg('docker_host_resource_id')::uuid
  AND s.container_id = sqlc.arg('container_id')::text
  AND l.logged_at >= sqlc.arg('from_ts')::timestamptz
  AND l.logged_at <= sqlc.arg('to_ts')::timestamptz
  AND (sqlc.narg('query')::text IS NULL OR l.line ILIKE '%' || sqlc.narg('query')::text || '%');

-- name: ListDockerHostContainerLogLinesOlderThan :many
-- Read once, right before DeleteOldDockerHostContainerLogLines removes
-- the same rows -- backs the optional log-archive step, see
-- ListDockerLogLinesOlderThan's own doc comment for the full reasoning.
SELECT id, docker_host_container_sighting_id, logged_at, line FROM docker_host_container_log_lines WHERE logged_at < $1;

-- name: DeleteOldDockerHostContainerLogLines :exec
DELETE FROM docker_host_container_log_lines WHERE logged_at < $1;
