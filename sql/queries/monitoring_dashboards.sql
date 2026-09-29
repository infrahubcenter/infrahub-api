-- Monitoring/Logs Folder > Dashboard: the org entity backing the four
-- independent trees (Monitoring>Docker, Monitoring>Kubernetes,
-- Logs>Docker, Logs>Kubernetes), discriminated by `feature`. See
-- migration 042_monitoring_dashboards.sql for the full rationale and how
-- this differs from the retired dashboard_folders/dashboards (039/040),
-- app_folders (036), and saved_view_folders/saved_dashboard_views
-- (034/038).

-- name: CreateMonitoringFolder :one
INSERT INTO monitoring_folders (feature, workspace_id, name, created_by)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetMonitoringFolderByID :one
SELECT * FROM monitoring_folders WHERE id = $1;

-- name: ListMonitoringFoldersForWorkspace :many
SELECT * FROM monitoring_folders
WHERE feature = $1 AND workspace_id = $2
ORDER BY name;

-- name: UpdateMonitoringFolderName :one
UPDATE monitoring_folders SET name = $2 WHERE id = $1
RETURNING *;

-- name: DeleteMonitoringFolder :exec
DELETE FROM monitoring_folders WHERE id = $1;

-- name: CreateMonitoringDashboard :one
INSERT INTO monitoring_dashboards (
    monitoring_folder_id, feature, workspace_id, name, description,
    vm_resource_id, k8s_cluster_resource_id, refresh_interval_seconds, created_by
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetMonitoringDashboardByID :one
SELECT * FROM monitoring_dashboards WHERE id = $1;

-- name: GetMonitoringDashboardWithBindingByID :one
-- Joins the bound resource (VM or K8sCluster, whichever is set) plus the
-- Dashboard's own Workspace/Folder names, so the handler never needs
-- extra round trips to show "bound to: <name>" and a breadcrumb.
SELECT
    d.*,
    r.name AS bound_resource_name,
    r.resource_type AS bound_resource_type,
    r.status AS bound_resource_status,
    w.name AS workspace_name,
    mf.name AS folder_name
FROM monitoring_dashboards d
JOIN resources r ON r.id = COALESCE(d.vm_resource_id, d.k8s_cluster_resource_id)
JOIN workspaces w ON w.id = d.workspace_id
LEFT JOIN monitoring_folders mf ON mf.id = d.monitoring_folder_id
WHERE d.id = $1;

-- name: ListMonitoringDashboardsFiltered :many
-- Every filter beyond feature is optional (sqlc.narg); an Admin's list
-- page passes whichever of workspace/folder it's currently scoped to.
SELECT
    d.*,
    r.name AS bound_resource_name,
    r.resource_type AS bound_resource_type,
    r.status AS bound_resource_status,
    w.name AS workspace_name,
    mf.name AS folder_name
FROM monitoring_dashboards d
JOIN resources r ON r.id = COALESCE(d.vm_resource_id, d.k8s_cluster_resource_id)
JOIN workspaces w ON w.id = d.workspace_id
LEFT JOIN monitoring_folders mf ON mf.id = d.monitoring_folder_id
WHERE d.feature = $1
  AND (sqlc.narg('workspace_id')::uuid IS NULL OR d.workspace_id = sqlc.narg('workspace_id'))
  AND (sqlc.narg('monitoring_folder_id')::uuid IS NULL OR d.monitoring_folder_id = sqlc.narg('monitoring_folder_id'))
ORDER BY d.name;

-- name: ListMonitoringDashboardsByResourceIDs :many
-- Used by MonitoringDashboardService.ListAccessibleForUser to union a
-- Member's accessible VM/cluster resource IDs, FOLDER-scoped folder IDs,
-- and DASHBOARD-scoped dashboard IDs (all from docker_access_grants)
-- against every existing Dashboard for one feature. Each *_ids param is
-- never NULL from the Go caller (an empty-but-non-nil slice correctly
-- matches nothing) -- same convention as vm_resource_ids/
-- k8s_cluster_resource_ids.
SELECT
    d.*,
    r.name AS bound_resource_name,
    r.resource_type AS bound_resource_type,
    r.status AS bound_resource_status,
    w.name AS workspace_name,
    mf.name AS folder_name
FROM monitoring_dashboards d
JOIN resources r ON r.id = COALESCE(d.vm_resource_id, d.k8s_cluster_resource_id)
JOIN workspaces w ON w.id = d.workspace_id
LEFT JOIN monitoring_folders mf ON mf.id = d.monitoring_folder_id
WHERE d.feature = sqlc.arg('feature')
  AND (
    d.vm_resource_id = ANY(sqlc.arg('vm_resource_ids')::uuid[])
    OR d.k8s_cluster_resource_id = ANY(sqlc.arg('k8s_cluster_resource_ids')::uuid[])
    OR d.monitoring_folder_id = ANY(sqlc.arg('folder_ids')::uuid[])
    OR d.id = ANY(sqlc.arg('dashboard_ids')::uuid[])
  )
ORDER BY d.name;

-- name: UpdateMonitoringDashboardName :one
UPDATE monitoring_dashboards SET name = $2, description = $3 WHERE id = $1
RETURNING *;

-- name: MoveMonitoringDashboardFolder :one
UPDATE monitoring_dashboards SET monitoring_folder_id = $2 WHERE id = $1
RETURNING *;

-- name: UpdateMonitoringDashboardRefreshInterval :one
UPDATE monitoring_dashboards SET refresh_interval_seconds = $2 WHERE id = $1
RETURNING *;

-- name: DeleteMonitoringDashboard :exec
DELETE FROM monitoring_dashboards WHERE id = $1;

-- name: DeleteMonitoringDashboardsByResourceID :exec
-- Cleans up any Monitoring/Logs dashboards still bound to a VM or
-- K8sCluster resource once it's been soft-deleted. Soft-delete never
-- fires the schema's own vm_resource_id/k8s_cluster_resource_id ON
-- DELETE CASCADE (that only triggers on a real row DELETE) -- without
-- this, a dashboard is left dangling: it still loads fine (bound_
-- resource_status just reads UNKNOWN) but its resource picker renders
-- permanently empty, with nothing telling the viewer why. Called right
-- after the soft-delete itself (see K8sClusterService.Delete).
-- monitoring_dashboard_filters/_widgets cascade via their own FK.
DELETE FROM monitoring_dashboards WHERE vm_resource_id = $1 OR k8s_cluster_resource_id = $1;

-- ---- Resource selection (wizard "Resources" step) ----

-- name: ListMonitoringDashboardFilters :many
SELECT * FROM monitoring_dashboard_filters WHERE monitoring_dashboard_id = $1 ORDER BY filter_type, value;

-- name: DeleteMonitoringDashboardFilters :exec
-- Wholesale replace, mirroring syncContainerNetworkMemberships' own
-- delete-then-reinsert convention for "current selection, not history."
DELETE FROM monitoring_dashboard_filters WHERE monitoring_dashboard_id = $1;

-- name: CreateMonitoringDashboardFilter :one
INSERT INTO monitoring_dashboard_filters (monitoring_dashboard_id, filter_type, value)
VALUES ($1, $2, $3)
RETURNING *;

-- ---- Widgets (wizard "Metrics" step) ----

-- name: ListMonitoringDashboardWidgets :many
SELECT * FROM monitoring_dashboard_widgets WHERE monitoring_dashboard_id = $1 ORDER BY position;

-- name: DeleteMonitoringDashboardWidgets :exec
DELETE FROM monitoring_dashboard_widgets WHERE monitoring_dashboard_id = $1;

-- name: CreateMonitoringDashboardWidget :one
INSERT INTO monitoring_dashboard_widgets (monitoring_dashboard_id, widget_type, position)
VALUES ($1, $2, $3)
RETURNING *;
