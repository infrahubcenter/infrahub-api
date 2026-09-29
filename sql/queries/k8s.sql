-- Step 25: Kubernetes clusters -- a standalone, admin-configured
-- infrastructure resource mirroring Database/Object Storage's own
-- pattern (see sql/queries/storage.sql for the template these follow).
-- Deliberately no per-resource member-permission queries here (unlike
-- databases.sql/storage.sql's ListDirect*PermissionsForUser): a Member
-- never gets a cluster detail page at all -- their only access is the
-- cross-cluster Monitoring/Logs dashboards, gated entirely by
-- docker_access_grants' k8s.monitor/k8s.logs (see docker_access.sql),
-- exactly like the Docker section.

-- name: CreateK8sCluster :one
INSERT INTO k8s_clusters (resource_id, namespace_filter)
VALUES ($1, $2)
RETURNING *;

-- name: GetK8sClusterByID :one
SELECT * FROM k8s_clusters WHERE id = $1 AND deleted_at IS NULL;

-- name: GetK8sClusterResourceByID :one
-- Mirrors GetVMResourceByID/GetObjectStorageResourceByID exactly --
-- resolves resources.id (not k8s_clusters.id) to a live, non-deleted
-- K8S_CLUSTER resource for AuthorizationService.CanAccessK8sFeature.
SELECT * FROM resources
WHERE id = $1 AND resource_type = 'K8S_CLUSTER' AND deleted_at IS NULL;

-- name: GetK8sClusterByResourceID :one
SELECT * FROM k8s_clusters WHERE resource_id = $1 AND deleted_at IS NULL;

-- name: GetK8sClusterWithResourceByID :one
-- Detail lookup joining the owning resource/workspace so the admin
-- handler never needs a second round trip -- mirrors
-- GetObjectStorageWithResourceByID exactly.
SELECT
    k.*, r.name AS resource_name, r.workspace_id, w.name AS workspace_name
FROM k8s_clusters k
JOIN resources r ON r.id = k.resource_id
JOIN workspaces w ON w.id = r.workspace_id
WHERE k.id = $1 AND k.deleted_at IS NULL;

-- name: ListK8sClustersForAdmin :many
-- The admin cluster-management page's list -- every non-deleted cluster,
-- with display names resolved.
SELECT
    k.*, r.name AS resource_name, r.workspace_id, w.name AS workspace_name
FROM k8s_clusters k
JOIN resources r ON r.id = k.resource_id
JOIN workspaces w ON w.id = r.workspace_id
WHERE k.deleted_at IS NULL
ORDER BY r.name;

-- name: ListK8sClustersForMonitoring :many
-- Every monitoring-enabled cluster, ready for a discovery/metrics
-- collection cycle -- mirrors ListObjectStoragesForMonitoring.
SELECT * FROM k8s_clusters
WHERE monitoring_enabled = true AND deleted_at IS NULL
ORDER BY resource_id, id;

-- name: UpdateK8sClusterConfig :one
-- Admin edit of a cluster's non-secret config -- partial update via
-- COALESCE, mirrors UpdateObjectStorageConfig.
UPDATE k8s_clusters
SET namespace_filter = COALESCE(sqlc.narg('namespace_filter'), namespace_filter)
WHERE id = sqlc.arg('id') AND deleted_at IS NULL
RETURNING *;

-- name: SetK8sClusterMonitoringEnabled :one
UPDATE k8s_clusters SET monitoring_enabled = $2 WHERE id = $1 RETURNING *;

-- name: UpdateK8sClusterConnectionStatus :one
-- Updates connection_status/api_server_url/kubernetes_version together
-- after a successful connect+discover -- api_server_url/kubernetes_version
-- are left unchanged (COALESCE) on a failed attempt so the last-known-good
-- values persist rather than being blanked out.
UPDATE k8s_clusters
SET connection_status     = $2,
    last_connection_at    = now(),
    last_connection_error = $3,
    api_server_url        = COALESCE(sqlc.narg('api_server_url'), api_server_url),
    kubernetes_version     = COALESCE(sqlc.narg('kubernetes_version'), kubernetes_version)
WHERE id = $1
RETURNING *;

-- name: UpdateK8sClusterDiscovered :exec
UPDATE k8s_clusters SET last_discovered_at = now() WHERE id = $1;

-- name: SoftDeleteK8sClusterResource :exec
-- Removes the monitoring registration only -- never touches the real
-- cluster. monitoring_enabled also cleared so no scheduler ever picks
-- this instance up again. Mirrors SoftDeleteObjectStorageResource.
UPDATE k8s_clusters SET deleted_at = now(), monitoring_enabled = false WHERE id = $1;

-- Credentials: see sql/queries/k8s_agent.sql -- kubeconfig upload was
-- retired in favor of an in-cluster agent authenticating with a bearer
-- token (migration 035).

-- === Pods ===

-- name: UpsertK8sPod :one
INSERT INTO k8s_pods (
    k8s_cluster_id, namespace, pod_name, node_name, phase, ready_containers, total_containers,
    restart_count, cpu_usage_millicores, memory_usage_bytes, started_at, last_discovered_at, removed_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), NULL)
ON CONFLICT (k8s_cluster_id, namespace, pod_name) DO UPDATE SET
    node_name             = EXCLUDED.node_name,
    phase                 = EXCLUDED.phase,
    ready_containers      = EXCLUDED.ready_containers,
    total_containers      = EXCLUDED.total_containers,
    restart_count         = EXCLUDED.restart_count,
    cpu_usage_millicores  = EXCLUDED.cpu_usage_millicores,
    memory_usage_bytes    = EXCLUDED.memory_usage_bytes,
    started_at            = EXCLUDED.started_at,
    last_discovered_at    = now(),
    removed_at            = NULL
RETURNING *;

-- name: MarkK8sPodsRemovedSince :exec
UPDATE k8s_pods
SET removed_at = now()
WHERE k8s_cluster_id = $1 AND removed_at IS NULL AND last_discovered_at < $2;

-- name: GetK8sPodByID :one
SELECT * FROM k8s_pods WHERE id = $1 AND removed_at IS NULL;

-- name: GetK8sPodWithClusterByID :one
-- Resolves a pod ID straight to its owning cluster's resource
-- (id/name/workspace/monitoring-enabled), with no cluster ID already
-- known -- needed by the Logs stream
-- (GET /api/k8s/pods/:podId/logs/stream), reached from the cross-cluster
-- K8s section rather than a specific cluster's own page. Mirrors
-- GetDockerContainerWithVMByID exactly.
SELECT
    kp.id, kp.k8s_cluster_id, kp.namespace, kp.pod_name, kp.display_name,
    k.resource_id AS cluster_resource_id, r.name AS cluster_name, r.workspace_id, k.deleted_at AS cluster_deleted_at
FROM k8s_pods kp
JOIN k8s_clusters k ON k.id = kp.k8s_cluster_id
JOIN resources r ON r.id = k.resource_id AND r.deleted_at IS NULL
WHERE kp.id = $1 AND kp.removed_at IS NULL;

-- name: ListK8sClusterResourceIDsForAccessGrant :many
-- The set of K8S_CLUSTER resource IDs userID can see for `permission`
-- (k8s.monitor or k8s.logs) -- mirrors ListVMResourceIDsForDockerPermission
-- exactly (see docker_access.sql: the union of workspace-wide and direct
-- resource-scoped grants), just scoped to resource_type = 'K8S_CLUSTER'
-- instead of 'VM'.
SELECT r.id
FROM resources r
WHERE r.resource_type = 'K8S_CLUSTER' AND r.deleted_at IS NULL
    AND (
        r.workspace_id IN (
            SELECT dag.workspace_id FROM docker_access_grants dag
            WHERE dag.user_id = $1 AND dag.permission = $2 AND dag.scope_type = 'WORKSPACE'
        )
        OR r.id IN (
            SELECT dag.resource_id FROM docker_access_grants dag
            WHERE dag.user_id = $1 AND dag.permission = $2 AND dag.scope_type = 'RESOURCE'
        )
    );

-- name: ListK8sPodsForClusterResourceIDs :many
-- Cross-cluster pod list for the top-level K8s Monitoring/Logs dashboards
-- -- resource_ids = NULL means unrestricted (Admin); a Member always
-- passes their computed accessible-cluster-resource-ids set. Mirrors
-- ListDockerContainersForResourceIDs exactly.
SELECT
    kp.id, kp.k8s_cluster_id, kp.namespace, kp.pod_name, kp.display_name, kp.node_name, kp.phase,
    kp.ready_containers, kp.total_containers, kp.restart_count,
    kp.cpu_usage_millicores, kp.memory_usage_bytes, kp.started_at, kp.last_discovered_at,
    r.id AS cluster_resource_id, r.name AS cluster_name, r.workspace_id, w.name AS workspace_name
FROM k8s_pods kp
JOIN k8s_clusters k ON k.id = kp.k8s_cluster_id AND k.deleted_at IS NULL
JOIN resources r ON r.id = k.resource_id AND r.deleted_at IS NULL
JOIN workspaces w ON w.id = r.workspace_id
WHERE kp.removed_at IS NULL
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY w.name, r.name, kp.namespace, kp.pod_name;

-- === Generic K8s resources (Jobs/CronJobs/ReplicaSets/PVs/StorageClasses/
-- Ingresses/NetworkPolicies/EndpointSlices/ResourceQuotas/LimitRanges/
-- PodDisruptionBudgets/HorizontalPodAutoscalers) -- see migration
-- 059_k8s_resources.sql for why these 12 kinds share one generic table
-- instead of twelve near-identical ones. Mirrors the UpsertK8sPod/
-- MarkK8sPodsRemovedSince/ListK8sPodsForClusterResourceIDs trio above. ===

-- name: UpsertK8sResource :one
INSERT INTO k8s_resources (k8s_cluster_id, kind, namespace, name, detail, last_discovered_at, removed_at)
VALUES ($1, $2, $3, $4, $5, now(), NULL)
ON CONFLICT (k8s_cluster_id, kind, namespace, name) DO UPDATE SET
    detail             = EXCLUDED.detail,
    last_discovered_at = now(),
    removed_at         = NULL
RETURNING *;

-- name: MarkK8sResourcesRemovedSince :exec
-- Scoped to one (cluster, kind) at a time -- the discovery sweep must
-- skip this for any kind in that round's FailedKinds (see
-- AgentClusterResourceSummary's own doc comment): a failed fetch's
-- zero items must never be mistaken for confirmed emptiness.
UPDATE k8s_resources
SET removed_at = now()
WHERE k8s_cluster_id = $1 AND kind = $2 AND removed_at IS NULL AND last_discovered_at < $3;

-- name: ListK8sResourcesForClusterResourceIDs :many
-- Cross-cluster list of one resource kind, for the K8s Monitoring
-- dashboard's Overview stat cards/detail sheets -- resource_ids = NULL
-- means unrestricted (Admin). Mirrors ListK8sPodsForClusterResourceIDs
-- exactly, generalized over `kind`.
SELECT
    kr.id, kr.k8s_cluster_id, kr.kind, kr.namespace, kr.name, kr.detail, kr.last_discovered_at,
    r.id AS cluster_resource_id, r.name AS cluster_name, r.workspace_id, w.name AS workspace_name
FROM k8s_resources kr
JOIN k8s_clusters k ON k.id = kr.k8s_cluster_id AND k.deleted_at IS NULL
JOIN resources r ON r.id = k.resource_id AND r.deleted_at IS NULL
JOIN workspaces w ON w.id = r.workspace_id
WHERE kr.removed_at IS NULL AND kr.kind = $1
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY w.name, r.name, kr.namespace, kr.name;
