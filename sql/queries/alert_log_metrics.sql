-- Backing queries for the log-based alert types (Alert Rules widening):
-- DOCKER_CONTAINER_HIGH_ERROR_LOGS / DOCKER_HOST_CONTAINER_HIGH_ERROR_LOGS /
-- K8S_POD_HIGH_ERROR_LOGS. None of the three log-line tables store a
-- severity column (services.ClassifyLogLine classifies at read time,
-- never persisted) -- so the evaluator pulls raw lines since a rule's own
-- duration_seconds window, capped, and classifies/counts ERROR+CRITICAL
-- in Go (see alertLogErrorCount in alert_metric_lookup.go).

-- name: ListDockerContainerLogLinesSince :many
SELECT line FROM docker_container_log_lines
WHERE docker_container_id = $1 AND logged_at >= $2
ORDER BY logged_at DESC
LIMIT $3;

-- name: ListDockerHostContainerLogLinesSince :many
SELECT line FROM docker_host_container_log_lines
WHERE docker_host_container_sighting_id = $1 AND logged_at >= $2
ORDER BY logged_at DESC
LIMIT $3;

-- name: ListK8sPodLogLinesSince :many
SELECT line FROM k8s_pod_log_lines
WHERE k8s_pod_id = $1 AND logged_at >= $2
ORDER BY logged_at DESC
LIMIT $3;
