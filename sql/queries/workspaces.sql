-- name: CreateWorkspace :one
INSERT INTO workspaces (name, description)
VALUES ($1, $2)
RETURNING *;

-- name: GetWorkspaceByID :one
SELECT * FROM workspaces WHERE id = $1;

-- name: ListWorkspaces :many
SELECT * FROM workspaces ORDER BY name;

-- name: UpdateWorkspace :one
UPDATE workspaces
SET name = $2, description = $3, is_active = $4
WHERE id = $1
RETURNING *;

-- A real, permanent delete -- callers must only reach this after confirming
-- via GetWorkspaceWithCountsByID that the workspace has zero VMs/databases/
-- object storage, since resources.workspace_id has no ON DELETE behavior
-- that silently orphans them -- see WorkspaceService.Delete, which enforces
-- that check before this ever runs. workspace_members is ON DELETE CASCADE,
-- so deleting a workspace simply ends every membership in it.
-- name: DeleteWorkspace :exec
DELETE FROM workspaces WHERE id = $1;

-- name: AddWorkspaceMember :exec
INSERT INTO workspace_members (workspace_id, user_id)
VALUES ($1, $2)
ON CONFLICT (workspace_id, user_id) DO NOTHING;

-- name: RemoveWorkspaceMember :exec
DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2;

-- name: ListWorkspaceMembers :many
SELECT u.* FROM users u
JOIN workspace_members wm ON wm.user_id = u.id
WHERE wm.workspace_id = $1
ORDER BY u.email;

-- name: ListWorkspacesForUser :many
SELECT w.* FROM workspaces w
JOIN workspace_members wm ON wm.workspace_id = w.id
WHERE wm.user_id = $1
ORDER BY w.name;

-- name: ListWorkspaceMembershipsForUser :many
SELECT w.id AS workspace_id, w.name AS workspace_name
FROM workspaces w
JOIN workspace_members wm ON wm.workspace_id = w.id
WHERE wm.user_id = $1
ORDER BY w.name;

-- A deactivated workspace must not grant (new) effective access, so both of
-- these require the workspace itself to be active -- membership in an
-- inactive workspace is preserved in workspace_members, just inert.

-- name: IsUserWorkspaceMember :one
SELECT EXISTS(
    SELECT 1 FROM workspace_members wm
    JOIN workspaces w ON w.id = wm.workspace_id
    WHERE wm.workspace_id = $1 AND wm.user_id = $2 AND w.is_active = true
);

-- name: ListVMResourceIDsForUserWorkspaces :many
SELECT r.id AS resource_id, r.workspace_id
FROM resources r
JOIN workspaces w ON w.id = r.workspace_id
JOIN workspace_members wm ON wm.workspace_id = r.workspace_id
WHERE wm.user_id = $1 AND w.is_active = true
    AND r.resource_type = 'VM' AND r.status != 'DISABLED' AND r.deleted_at IS NULL;

-- name: CountVMsForWorkspace :one
SELECT count(*) FROM resources
WHERE workspace_id = $1 AND resource_type = 'VM' AND deleted_at IS NULL;

-- name: CountMembersForWorkspace :one
SELECT count(*) FROM workspace_members WHERE workspace_id = $1;

-- database_count/object_storage_count/docker_host_count/k8s_cluster_count
-- mirror vm_count's shape, with the same child-table-deleted_at join:
-- standalone database/object storage/Docker Host/K8s cluster soft-delete
-- never touches the owning `resources` row's deleted_at (each of those
-- four writes only its own table's deleted_at -- see
-- SoftDeleteDatabaseResource/SoftDeleteObjectStorageResource/
-- SoftDeleteDockerHostResource/SoftDeleteK8sClusterResource), unlike VM
-- soft-delete which does set resources.deleted_at directly (SoftDeleteResource).
-- WorkspaceService.Delete's own "does this workspace still contain
-- anything" check depends on all six of these counts being present here --
-- omitting Docker Host/K8s Cluster is what let a workspace containing one
-- of those reach DeleteWorkspace and fail on resources.workspace_id's own
-- NOT-NULL-vs-ON-DELETE-SET-NULL contradiction instead of being blocked
-- with a clear message.

-- name: ListWorkspacesWithCounts :many
SELECT w.*,
    (SELECT count(*) FROM resources r WHERE r.workspace_id = w.id AND r.resource_type = 'VM' AND r.deleted_at IS NULL) AS vm_count,
    (SELECT count(*) FROM resources r JOIN databases d ON d.resource_id = r.id
        WHERE r.workspace_id = w.id AND r.resource_type = 'DATABASE' AND r.deleted_at IS NULL AND d.deleted_at IS NULL) AS database_count,
    (SELECT count(*) FROM resources r JOIN object_storages o ON o.resource_id = r.id
        WHERE r.workspace_id = w.id AND r.resource_type = 'OBJECT_STORAGE' AND r.deleted_at IS NULL AND o.deleted_at IS NULL) AS object_storage_count,
    (SELECT count(*) FROM resources r JOIN docker_hosts dh ON dh.resource_id = r.id
        WHERE r.workspace_id = w.id AND r.resource_type = 'DOCKER_HOST' AND r.deleted_at IS NULL AND dh.deleted_at IS NULL) AS docker_host_count,
    (SELECT count(*) FROM resources r JOIN k8s_clusters kc ON kc.resource_id = r.id
        WHERE r.workspace_id = w.id AND r.resource_type = 'K8S_CLUSTER' AND r.deleted_at IS NULL AND kc.deleted_at IS NULL) AS k8s_cluster_count,
    (SELECT count(*) FROM workspace_members wm WHERE wm.workspace_id = w.id) AS member_count
FROM workspaces w
ORDER BY w.name;

-- name: GetWorkspaceWithCountsByID :one
SELECT w.*,
    (SELECT count(*) FROM resources r WHERE r.workspace_id = w.id AND r.resource_type = 'VM' AND r.deleted_at IS NULL) AS vm_count,
    (SELECT count(*) FROM resources r JOIN databases d ON d.resource_id = r.id
        WHERE r.workspace_id = w.id AND r.resource_type = 'DATABASE' AND r.deleted_at IS NULL AND d.deleted_at IS NULL) AS database_count,
    (SELECT count(*) FROM resources r JOIN object_storages o ON o.resource_id = r.id
        WHERE r.workspace_id = w.id AND r.resource_type = 'OBJECT_STORAGE' AND r.deleted_at IS NULL AND o.deleted_at IS NULL) AS object_storage_count,
    (SELECT count(*) FROM resources r JOIN docker_hosts dh ON dh.resource_id = r.id
        WHERE r.workspace_id = w.id AND r.resource_type = 'DOCKER_HOST' AND r.deleted_at IS NULL AND dh.deleted_at IS NULL) AS docker_host_count,
    (SELECT count(*) FROM resources r JOIN k8s_clusters kc ON kc.resource_id = r.id
        WHERE r.workspace_id = w.id AND r.resource_type = 'K8S_CLUSTER' AND r.deleted_at IS NULL AND kc.deleted_at IS NULL) AS k8s_cluster_count,
    (SELECT count(*) FROM workspace_members wm WHERE wm.workspace_id = w.id) AS member_count
FROM workspaces w
WHERE w.id = $1;

-- Backs an ADMIN's GET /api/my-access Workspaces section -- admin access is
-- unconditional/global (mirrors GetUserVMAccess's own admin-sees-everything
-- behavior), so this lists every workspace in the system rather than
-- deriving from workspace_members like ListWorkspaceMembershipsForUser does
-- for a Member. Same row shape as ListWorkspaceMembershipsForUser so both
-- feed the same workspaceMembership DTO.

-- name: ListAllWorkspaces :many
SELECT w.id AS workspace_id, w.name AS workspace_name
FROM workspaces w
ORDER BY w.name;

-- "Members" here means everyone with any effective access to something in
-- the workspace (workspace membership, or a direct VM grant on one of its
-- resources) -- mirrors ListWorkspacesWithCounts' member-union EXISTS
-- logic. Powers a MEMBER's GET /api/my-access Workspaces section and
-- GET /api/users/:id's workspaces field for a MEMBER target; an ADMIN
-- target/caller uses plain ListWorkspaces instead (admin access is
-- unconditional/global, not derived).

-- name: ListWorkspacesForUserAccess :many
SELECT DISTINCT w.* FROM workspaces w
WHERE EXISTS (
    SELECT 1 FROM workspace_members wm WHERE wm.workspace_id = w.id AND wm.user_id = $1
) OR EXISTS (
    SELECT 1 FROM resource_permissions rp JOIN resources r ON r.id = rp.resource_id
    WHERE r.workspace_id = w.id AND rp.user_id = $1
)
ORDER BY w.name;
