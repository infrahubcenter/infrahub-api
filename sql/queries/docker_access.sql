-- docker_access_grants -- Workspace-scoped, view-only grants for the
-- top-level Docker/Kubernetes Monitoring/Logs section, independent of
-- vm.view/vm.connect. See migrations/031_docker_access_grants.sql,
-- 043_workspaces.sql.

-- name: CreateDockerAccessGrant :one
-- Workspace-wide scope: resource_id stays NULL, scope_type defaults to
-- 'WORKSPACE'. See CreateResourceDockerAccessGrant for the per-resource
-- variant.
INSERT INTO docker_access_grants (user_id, workspace_id, permission, granted_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, workspace_id, permission) WHERE scope_type = 'WORKSPACE' DO NOTHING
RETURNING *;

-- name: CreateResourceDockerAccessGrant :one
-- Per-resource scope: one specific VM (docker.monitor/docker.logs) or one
-- specific K8s cluster (k8s.monitor/k8s.logs) -- see
-- DockerAccessService.Grant for the resource-type-matches-permission
-- validation this relies on the caller having already done.
INSERT INTO docker_access_grants (user_id, resource_id, permission, granted_by, scope_type)
VALUES ($1, $2, $3, $4, 'RESOURCE')
ON CONFLICT (user_id, resource_id, permission) WHERE scope_type = 'RESOURCE' DO NOTHING
RETURNING *;

-- name: CreateFolderDockerAccessGrant :one
-- Per-Folder scope: every monitoring_dashboards row filed under this
-- monitoring_folders row, dynamically -- adding a Dashboard to the folder
-- later extends access automatically, no re-grant needed. See
-- DockerAccessService.Grant for the folder.Feature-matches-permission
-- validation this relies on the caller having already done.
INSERT INTO docker_access_grants (user_id, monitoring_folder_id, permission, granted_by, scope_type)
VALUES ($1, $2, $3, $4, 'FOLDER')
ON CONFLICT (user_id, monitoring_folder_id, permission) WHERE scope_type = 'FOLDER' DO NOTHING
RETURNING *;

-- name: CreateDashboardDockerAccessGrant :one
-- Per-Dashboard scope: exactly one monitoring_dashboards row, independent
-- of which VM/cluster it binds or which Folder (if any) it's filed under.
INSERT INTO docker_access_grants (user_id, monitoring_dashboard_id, permission, granted_by, scope_type)
VALUES ($1, $2, $3, $4, 'DASHBOARD')
ON CONFLICT (user_id, monitoring_dashboard_id, permission) WHERE scope_type = 'DASHBOARD' DO NOTHING
RETURNING *;

-- name: GetDockerAccessGrantByID :one
SELECT * FROM docker_access_grants WHERE id = $1;

-- name: DeleteDockerAccessGrant :exec
DELETE FROM docker_access_grants WHERE id = $1;

-- name: ListAllDockerAccessGrants :many
-- Admin-facing management list (the Docker Access admin page), with
-- joined display names so the frontend never has to resolve IDs itself.
-- resource_name/folder_name/dashboard_name are only non-null for their
-- matching scope_type.
SELECT
    g.id, g.user_id, g.workspace_id, g.resource_id, g.monitoring_folder_id, g.monitoring_dashboard_id, g.scope_type, g.permission, g.granted_by, g.created_at,
    u.name AS user_name, u.email AS user_email,
    w.name AS workspace_name,
    res.name AS resource_name,
    mf.name AS folder_name,
    md.name AS dashboard_name
FROM docker_access_grants g
JOIN users u ON u.id = g.user_id
LEFT JOIN workspaces w ON w.id = g.workspace_id
LEFT JOIN resources res ON res.id = g.resource_id
LEFT JOIN monitoring_folders mf ON mf.id = g.monitoring_folder_id
LEFT JOIN monitoring_dashboards md ON md.id = g.monitoring_dashboard_id
ORDER BY g.created_at DESC;

-- name: ListDockerAccessGrantsForUser :many
-- Powers "my access" -- what does the calling member currently see in
-- the Docker section, and why (which workspace/resource/folder/dashboard
-- granted it).
SELECT
    g.id, g.workspace_id, g.resource_id, g.monitoring_folder_id, g.monitoring_dashboard_id, g.scope_type, g.permission, g.created_at,
    w.name AS workspace_name,
    res.name AS resource_name,
    mf.name AS folder_name,
    md.name AS dashboard_name
FROM docker_access_grants g
LEFT JOIN workspaces w ON w.id = g.workspace_id
LEFT JOIN resources res ON res.id = g.resource_id
LEFT JOIN monitoring_folders mf ON mf.id = g.monitoring_folder_id
LEFT JOIN monitoring_dashboards md ON md.id = g.monitoring_dashboard_id
WHERE g.user_id = $1
ORDER BY g.created_at DESC;

-- name: ListMonitoringFolderIDsForAccessGrant :many
-- The set of monitoring_folders IDs userID holds a FOLDER-scoped grant on
-- for `permission` -- simpler than ListVMResourceIDsForDockerPermission
-- since there's no workspace-wide fan-out to compute: a FOLDER grant only
-- ever names the one folder it was created for.
SELECT monitoring_folder_id FROM docker_access_grants
WHERE user_id = $1 AND permission = $2 AND scope_type = 'FOLDER';

-- name: ListMonitoringDashboardIDsForAccessGrant :many
-- ListMonitoringFolderIDsForAccessGrant's exact counterpart for
-- DASHBOARD-scoped grants.
SELECT monitoring_dashboard_id FROM docker_access_grants
WHERE user_id = $1 AND permission = $2 AND scope_type = 'DASHBOARD';

-- name: ListVMResourceIDsForDockerPermission :many
-- The set of VM or Docker Host resource IDs userID can see in the Docker
-- section for `permission` (docker.monitor or docker.logs) -- the union
-- of every VM/Docker Host in a workspace they hold a WORKSPACE-scoped
-- grant on, plus every VM/Docker Host they hold a direct RESOURCE-scoped
-- grant on. Derived dynamically, never cached, so adding a VM to an
-- already-granted workspace extends access immediately with no separate
-- re-grant.
SELECT r.id
FROM resources r
WHERE r.resource_type IN ('VM', 'DOCKER_HOST') AND r.deleted_at IS NULL
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

-- name: CheckDockerAccessGrant :one
-- Single-resource authorization check (AuthorizationService.CanAccessDockerFeature):
-- does userID have `permission` via a workspace-wide grant on
-- vmWorkspaceID, OR a direct resource-scoped grant on vmResourceID?
SELECT EXISTS (
    SELECT 1 FROM docker_access_grants
    WHERE user_id = $1 AND permission = $2
        AND ((scope_type = 'WORKSPACE' AND workspace_id = $3) OR (scope_type = 'RESOURCE' AND resource_id = $4))
) AS allowed;

-- name: CheckMonitoringAccessGrantViaDashboard :one
-- CheckDockerAccessGrant's missing other half: a FOLDER/DASHBOARD-scoped
-- grant (see CreateFolderDockerAccessGrant/CreateDashboardDockerAccessGrant)
-- names a monitoring_folders/monitoring_dashboards row, not a VM/Docker
-- Host/K8s-cluster resource directly, so CheckDockerAccessGrant's own
-- WORKSPACE/RESOURCE-only check can never see it -- CanAccessDockerFeature/
-- CanAccessK8sFeature is keyed by resourceID (needed to gate the live
-- per-host/per-cluster containers/stats/logs endpoints), with no
-- dashboardID in scope to check directly. This is entered from the
-- resource side instead: does ANY Dashboard bound to resourceID for this
-- feature fall inside a folder or dashboard this user was granted
-- `permission` on? Mirrors MonitoringDashboardService.CanView's own
-- folder/dashboard-scope check exactly, just the reverse direction.
SELECT EXISTS (
    SELECT 1 FROM monitoring_dashboards md
    WHERE md.feature = $3
        AND (md.vm_resource_id = $2 OR md.k8s_cluster_resource_id = $2)
        AND (
            md.monitoring_folder_id IN (
                SELECT monitoring_folder_id FROM docker_access_grants
                WHERE user_id = $1 AND permission = $4 AND scope_type = 'FOLDER'
            )
            OR md.id IN (
                SELECT monitoring_dashboard_id FROM docker_access_grants
                WHERE user_id = $1 AND permission = $4 AND scope_type = 'DASHBOARD'
            )
        )
) AS allowed;

-- name: ListDockerContainersForResourceIDs :many
-- Cross-VM container list for the top-level Docker Monitoring/Logs
-- dashboards. resource_ids = NULL means unrestricted (Admin, who bypasses
-- the grant system entirely); a Member always passes their computed
-- ListVMResourceIDsForDockerPermission result, so an empty-but-non-nil
-- slice correctly matches nothing rather than everything -- same
-- NULL-vs-empty-slice convention used by every other cross-resource list
-- in this app (ListRecommendationsFiltered et al.).
SELECT
    dc.id, dc.vm_id, dc.container_id, dc.name, dc.display_name, dc.image, dc.image_tag, dc.status, dc.ports,
    dc.created_at_remote, dc.last_discovered_at,
    r.id AS vm_resource_id, r.name AS vm_name, r.workspace_id, w.name AS workspace_name
FROM docker_containers dc
JOIN vms v ON v.id = dc.vm_id
JOIN resources r ON r.id = v.resource_id AND r.deleted_at IS NULL
JOIN workspaces w ON w.id = r.workspace_id
WHERE (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.id = ANY(sqlc.narg('resource_ids')::uuid[]))
ORDER BY w.name, r.name, dc.name;
