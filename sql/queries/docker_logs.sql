-- Log history: a periodic, bounded background capture (docker_log_capture.go)
-- keeps a searchable copy of each running container's logs going back up to
-- the configured retention window, independent of the live-tail WebSocket
-- in docker_logs.go (which never persists anything). See migration 033.

-- name: ListRunningDockerContainersForLogCapture :many
-- The log-capture scheduler's cross-VM work list: every currently-running,
-- non-removed container, on an active (non-disabled, non-deleted) VM.
-- Mirrors GetDockerContainerWithVMByID's join shape.
SELECT
    dc.id, dc.container_id, dc.name, dc.last_log_captured_at,
    r.id AS vm_resource_id
FROM docker_containers dc
JOIN vms v ON v.id = dc.vm_id
JOIN resources r ON r.id = v.resource_id AND r.deleted_at IS NULL AND r.status != 'DISABLED'
WHERE dc.removed_at IS NULL AND dc.status = 'RUNNING';

-- name: InsertDockerLogLine :exec
INSERT INTO docker_container_log_lines (docker_container_id, logged_at, line)
VALUES ($1, $2, $3);

-- name: UpdateDockerContainerLogCursor :exec
UPDATE docker_containers SET last_log_captured_at = $2 WHERE id = $1;

-- name: SearchDockerLogLines :many
-- Admin/Member authorization (docker.logs, same grant the live-tail stream
-- itself requires) happens in the handler before this ever runs -- this
-- query only ever sees a containerID the caller has already been cleared
-- to search. from/to bound the search to (at most) the retention window;
-- the handler clamps them, never trusting client-supplied bounds wider
-- than what's actually retained.
SELECT id, logged_at, line
FROM docker_container_log_lines
WHERE docker_container_id = sqlc.arg('docker_container_id')::uuid
  AND logged_at >= sqlc.arg('from_ts')::timestamptz
  AND logged_at <= sqlc.arg('to_ts')::timestamptz
  AND (sqlc.narg('query')::text IS NULL OR line ILIKE '%' || sqlc.narg('query')::text || '%')
ORDER BY logged_at DESC
LIMIT sqlc.arg('page_limit')::int OFFSET sqlc.arg('page_offset')::int;

-- name: CountDockerLogLines :one
SELECT count(*) FROM docker_container_log_lines
WHERE docker_container_id = sqlc.arg('docker_container_id')::uuid
  AND logged_at >= sqlc.arg('from_ts')::timestamptz
  AND logged_at <= sqlc.arg('to_ts')::timestamptz
  AND (sqlc.narg('query')::text IS NULL OR line ILIKE '%' || sqlc.narg('query')::text || '%');

-- name: ListDockerLogLinesOlderThan :many
-- Read once, right before DeleteOldDockerLogLines removes the same rows
-- -- backs the optional log-archive step (LOG_ARCHIVE_BACKEND=volume|s3,
-- see internal/services/log_archive.go) that writes rows out before they
-- age out of Postgres, so they aren't just lost. docker_container_id
-- travels along so the archive can group/name entries per container.
SELECT id, docker_container_id, logged_at, line FROM docker_container_log_lines WHERE logged_at < $1;

-- name: DeleteOldDockerLogLines :exec
DELETE FROM docker_container_log_lines WHERE logged_at < $1;

-- name: SetDockerContainerDisplayName :one
-- display_name = NULL clears the custom label, reverting display to the
-- container's real name everywhere.
UPDATE docker_containers
SET display_name = sqlc.narg('display_name')::text
WHERE id = $1 AND removed_at IS NULL
RETURNING *;
