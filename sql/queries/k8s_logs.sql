-- Log history: mirrors docker_logs.sql exactly, for standalone Kubernetes
-- pods. See migration 033.

-- name: ListRunningK8sPodsForLogCapture :many
-- The log-capture scheduler's cross-cluster work list: every currently
-- known pod on an active (monitoring-enabled) cluster. Unlike Docker
-- (RUNNING-only), a pod's own phase isn't filtered here -- a
-- Pending/Succeeded/Failed pod can still have useful log history worth
-- capturing, and GetLogs against a pod with no containers started yet
-- simply returns nothing.
SELECT
    kp.id, kp.k8s_cluster_id, kp.namespace, kp.pod_name, kp.last_log_captured_at
FROM k8s_pods kp
JOIN k8s_clusters kc ON kc.id = kp.k8s_cluster_id AND kc.deleted_at IS NULL AND kc.monitoring_enabled
WHERE kp.removed_at IS NULL;

-- name: InsertK8sPodLogLine :exec
INSERT INTO k8s_pod_log_lines (k8s_pod_id, logged_at, line)
VALUES ($1, $2, $3);

-- name: UpdateK8sPodLogCursor :exec
UPDATE k8s_pods SET last_log_captured_at = $2 WHERE id = $1;

-- name: SearchK8sPodLogLines :many
-- Authorization (k8s.logs, the same grant the live-tail stream itself
-- requires) happens in the handler before this ever runs.
SELECT id, logged_at, line
FROM k8s_pod_log_lines
WHERE k8s_pod_id = sqlc.arg('k8s_pod_id')::uuid
  AND logged_at >= sqlc.arg('from_ts')::timestamptz
  AND logged_at <= sqlc.arg('to_ts')::timestamptz
  AND (sqlc.narg('query')::text IS NULL OR line ILIKE '%' || sqlc.narg('query')::text || '%')
ORDER BY logged_at DESC
LIMIT sqlc.arg('page_limit')::int OFFSET sqlc.arg('page_offset')::int;

-- name: CountK8sPodLogLines :one
SELECT count(*) FROM k8s_pod_log_lines
WHERE k8s_pod_id = sqlc.arg('k8s_pod_id')::uuid
  AND logged_at >= sqlc.arg('from_ts')::timestamptz
  AND logged_at <= sqlc.arg('to_ts')::timestamptz
  AND (sqlc.narg('query')::text IS NULL OR line ILIKE '%' || sqlc.narg('query')::text || '%');

-- name: ListK8sPodLogLinesOlderThan :many
-- Read once, right before DeleteOldK8sPodLogLines removes the same rows
-- -- backs the optional log-archive step, see ListDockerLogLinesOlderThan's
-- own doc comment for the full reasoning.
SELECT id, k8s_pod_id, logged_at, line FROM k8s_pod_log_lines WHERE logged_at < $1;

-- name: DeleteOldK8sPodLogLines :exec
DELETE FROM k8s_pod_log_lines WHERE logged_at < $1;

-- name: SetK8sPodDisplayName :one
-- display_name = NULL clears the custom label, reverting display to the
-- pod's real name everywhere.
UPDATE k8s_pods
SET display_name = sqlc.narg('display_name')::text
WHERE id = $1 AND removed_at IS NULL
RETURNING *;
