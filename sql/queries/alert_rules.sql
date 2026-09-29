-- Step 16: alert rule CRUD + the engine's own enabled-rule feed.

-- name: CreateAlertRule :one
INSERT INTO alert_rules (
    resource_id, container_id, k8s_pod_id, docker_host_container_sighting_id, alert_type, metric, condition, threshold, recovery_threshold,
    duration_seconds, severity, notification_policy_id, enabled, created_by
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING *;

-- name: UpdateAlertRule :one
UPDATE alert_rules
SET condition = $2, threshold = $3, recovery_threshold = $4, duration_seconds = $5,
    severity = $6, notification_policy_id = $7, enabled = $8
WHERE id = $1
RETURNING *;

-- name: GetAlertRuleByID :one
SELECT * FROM alert_rules WHERE id = $1;

-- name: DeleteAlertRule :exec
DELETE FROM alert_rules WHERE id = $1;

-- name: ListAlertRulesByResource :many
SELECT * FROM alert_rules WHERE resource_id = $1 ORDER BY created_at DESC;

-- name: ListAlertRulesGlobal :many
-- res.deleted_at IS NULL (Step 23): otherwise a deleted resource's old
-- alert rules keep showing up here pointing at a resource name that no
-- longer resolves anywhere else in the app -- matches
-- ListEnabledAlertRulesForEvaluation's own filter below. kp.pod_name/
-- kp.namespace and dhcs.container_id are display-only extras (Alert Rules
-- widening) so the list page can show exactly which pod/container a
-- K8s/Docker-Host-scoped rule targets, the same way it already shows a
-- VM-scoped rule's container_id.
SELECT ar.*, res.name AS resource_name, res.resource_type, res.workspace_id,
    kp.pod_name AS k8s_pod_name, kp.namespace AS k8s_pod_namespace,
    dhcs.container_id AS docker_host_container_docker_id
FROM alert_rules ar
JOIN resources res ON res.id = ar.resource_id AND res.deleted_at IS NULL
LEFT JOIN k8s_pods kp ON kp.id = ar.k8s_pod_id
LEFT JOIN docker_host_container_sightings dhcs ON dhcs.id = ar.docker_host_container_sighting_id
WHERE (sqlc.narg('resource_ids')::uuid[] IS NULL OR res.id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY ar.created_at DESC;

-- name: SetAlertRuleBreachStartedAt :exec
UPDATE alert_rules SET breach_started_at = $2 WHERE id = $1;

-- name: SuppressAlertRule :one
UPDATE alert_rules
SET suppressed_until = $2, suppressed_reason = $3, suppressed_by = $4
WHERE id = $1
RETURNING *;

-- name: ClearAlertRuleSuppression :one
UPDATE alert_rules SET suppressed_until = NULL, suppressed_reason = NULL, suppressed_by = NULL WHERE id = $1 RETURNING *;

-- The engine's own evaluation feed (spec §36/§51: cached/efficient
-- lookup, not a per-cycle authorization-aware query): every enabled
-- rule, joined with just enough VM/database/object-storage/K8s-pod/
-- Docker-Host-container identity for the metric lookup layer to resolve
-- a value without a second round-trip per rule. K8s cluster/Docker Host
-- "unavailable" metrics need no extra join at all -- res.resource_type +
-- ar.resource_id (already selected) is enough for the lookup layer to
-- call the right agent hub's IsConnected directly.
-- name: ListEnabledAlertRulesForEvaluation :many
SELECT
    ar.*,
    res.resource_type,
    res.name AS resource_name,
    res.workspace_id,
    v.id AS vm_id,
    d.id AS database_id,
    os.id AS object_storage_id,
    dc.status AS container_status,
    dc.health AS container_health,
    dc.restart_count AS container_restart_count,
    kp.phase AS k8s_pod_phase,
    kp.restart_count AS k8s_pod_restart_count,
    kp.cpu_usage_millicores AS k8s_pod_cpu_millicores,
    kp.memory_usage_bytes AS k8s_pod_memory_bytes,
    kp.pod_name AS k8s_pod_name,
    kp.namespace AS k8s_pod_namespace,
    dhcs.container_id AS docker_host_container_docker_id
FROM alert_rules ar
JOIN resources res ON res.id = ar.resource_id AND res.deleted_at IS NULL
LEFT JOIN vms v ON v.resource_id = res.id
LEFT JOIN databases d ON d.resource_id = res.id AND d.deleted_at IS NULL
LEFT JOIN object_storages os ON os.resource_id = res.id AND os.deleted_at IS NULL
LEFT JOIN docker_containers dc ON dc.id = ar.container_id AND dc.removed_at IS NULL
LEFT JOIN k8s_pods kp ON kp.id = ar.k8s_pod_id AND kp.removed_at IS NULL
LEFT JOIN docker_host_container_sightings dhcs ON dhcs.id = ar.docker_host_container_sighting_id
WHERE ar.enabled;
