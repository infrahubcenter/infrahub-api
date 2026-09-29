-- name: CreateResource :one
INSERT INTO resources (workspace_id, name, resource_type, description)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetResourceByID :one
SELECT * FROM resources WHERE id = $1 AND deleted_at IS NULL;

-- name: ListResourcesByWorkspace :many
SELECT * FROM resources WHERE workspace_id = $1 AND deleted_at IS NULL ORDER BY name;

-- name: ListResourcesByIDs :many
-- Batch workspace_id lookup for the unified Operations list's workspace
-- filter -- avoids an N+1 GetResourceByID call per operation row when
-- enriching a merged update/reboot/database-operation result set.
SELECT id, workspace_id, resource_type FROM resources WHERE id = ANY(sqlc.arg('ids')::uuid[]) AND deleted_at IS NULL;

-- name: ListResourcesByType :many
SELECT * FROM resources WHERE resource_type = $1 AND deleted_at IS NULL ORDER BY name;

-- name: UpdateResourceStatus :one
UPDATE resources
SET status = $2
WHERE id = $1
RETURNING *;

-- name: SoftDeleteResource :exec
UPDATE resources SET deleted_at = now() WHERE id = $1;

-- name: DeleteSoftDeletedResourcesByWorkspace :exec
-- Called by WorkspaceService.Delete immediately before the workspace row
-- itself is removed. resources.workspace_id's own FK is ON DELETE SET
-- NULL, but the column is NOT NULL -- deleting a workspace while any
-- (already soft-deleted, so already invisible everywhere else in the
-- app -- a live one would have blocked deletion earlier) resource row
-- still references it hits that contradiction and fails outright. Every
-- table cascading from resources.id (vms, databases, object_storages,
-- docker_hosts, k8s_clusters, and everything under them) is ON DELETE
-- CASCADE, so this is a clean hard removal of already-inert history, not
-- a live resource.
--
-- "Soft-deleted" means different things per type: VM soft-delete sets
-- resources.deleted_at directly, but Database/Object Storage/Docker
-- Host/K8s Cluster soft-delete only ever sets their OWN table's
-- deleted_at (resources.deleted_at stays NULL forever for those four --
-- see ListWorkspacesWithCounts' own doc comment). A plain
-- `deleted_at IS NOT NULL` filter here only ever matched the VM case,
-- leaving a soft-deleted Database/Object Storage/Docker Host/K8s Cluster
-- resource row behind to hit the exact same NOT-NULL-vs-SET-NULL
-- contradiction this query exists to avoid -- so each type is checked
-- against its own actual soft-delete signal instead.
DELETE FROM resources r
WHERE r.workspace_id = $1
  AND (
    (r.resource_type = 'VM' AND r.deleted_at IS NOT NULL)
    OR (r.resource_type = 'DATABASE' AND EXISTS (SELECT 1 FROM databases d WHERE d.resource_id = r.id AND d.deleted_at IS NOT NULL))
    OR (r.resource_type = 'OBJECT_STORAGE' AND EXISTS (SELECT 1 FROM object_storages o WHERE o.resource_id = r.id AND o.deleted_at IS NOT NULL))
    OR (r.resource_type = 'DOCKER_HOST' AND EXISTS (SELECT 1 FROM docker_hosts dh WHERE dh.resource_id = r.id AND dh.deleted_at IS NOT NULL))
    OR (r.resource_type = 'K8S_CLUSTER' AND EXISTS (SELECT 1 FROM k8s_clusters kc WHERE kc.resource_id = r.id AND kc.deleted_at IS NOT NULL))
  );

-- name: GrantResourcePermission :exec
INSERT INTO resource_permissions (resource_id, user_id, permission_id)
VALUES ($1, $2, $3)
ON CONFLICT (resource_id, user_id, permission_id) DO NOTHING;

-- name: RevokeResourcePermission :exec
DELETE FROM resource_permissions
WHERE resource_id = $1 AND user_id = $2 AND permission_id = $3;

-- name: ListResourcePermissionsForUser :many
SELECT rp.resource_id, rp.permission_id, p.name AS permission_name
FROM resource_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE rp.user_id = $1;

-- name: RevokeAllResourcePermissionsForUser :exec
DELETE FROM resource_permissions WHERE resource_id = $1 AND user_id = $2;

-- A deactivated (status = DISABLED) VM must not be newly accessible even
-- with an existing direct grant -- see docs/authorization.md.
-- name: ListDirectVMPermissionsForUser :many
SELECT rp.resource_id, p.name AS permission_name
FROM resource_permissions rp
JOIN permissions p ON p.id = rp.permission_id
JOIN resources r ON r.id = rp.resource_id
WHERE rp.user_id = $1 AND r.resource_type = 'VM' AND r.status != 'DISABLED' AND r.deleted_at IS NULL;

-- name: GetVMResourceByID :one
SELECT * FROM resources
WHERE id = $1 AND resource_type = 'VM' AND deleted_at IS NULL;

-- name: ListDirectPermissionsForUserResource :many
SELECT p.name AS permission_name
FROM resource_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE rp.user_id = $1 AND rp.resource_id = $2;

-- name: CreateCredential :one
INSERT INTO credentials (resource_id, credential_type, encrypted_data)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListCredentialsByResource :many
SELECT * FROM credentials WHERE resource_id = $1 ORDER BY created_at DESC;

-- name: GetCredentialByResourceAndType :one
SELECT * FROM credentials
WHERE resource_id = $1 AND credential_type = $2
ORDER BY created_at DESC
LIMIT 1;

-- name: DeleteCredential :exec
DELETE FROM credentials WHERE id = $1;

-- name: ListResourcesFiltered :many
SELECT * FROM resources
WHERE deleted_at IS NULL
    AND (sqlc.narg('workspace_id')::uuid IS NULL OR workspace_id = sqlc.narg('workspace_id'))
    AND (sqlc.narg('resource_type')::text IS NULL OR resource_type = sqlc.narg('resource_type'))
    AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
ORDER BY name;

-- name: UpdateResource :one
UPDATE resources
SET name = $2, description = $3, workspace_id = $4, status = $5, monitoring_enabled = $6
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: ListDirectAccessForResource :many
SELECT rp.user_id, u.name, u.email, p.name AS permission_name
FROM resource_permissions rp
JOIN users u ON u.id = rp.user_id
JOIN permissions p ON p.id = rp.permission_id
WHERE rp.resource_id = $1;

-- name: CountResourcesByWorkspaceAndType :one
SELECT count(*) FROM resources
WHERE workspace_id = $1 AND resource_type = $2 AND deleted_at IS NULL;

-- name: ListAllDirectResourceGrants :many
-- Cross-resource-type direct-grant listing for the unified Permissions page.
-- Scoped to DIRECT grants only, by design -- workspace-derived access
-- remains visible per-resource via each type's own ListAccess endpoint
-- instead, since a workspace-derived row here wouldn't be individually
-- revocable as this page's revoke action implies. One row per (resource,
-- user, permission) -- never merged into a permissions[] array -- matching
-- the spec's own §23 table shape (Permission, Description, Resource,
-- Scope, Role, Status: one row per permission, not one row per grant).
--
-- r.deleted_at IS NULL alone covers a deleted VM (Step 22 wired
-- SoftDeleteResource, previously unused, into VM delete) but is NOT
-- enough on its own to exclude a removed Database/Object Storage:
-- SoftDeleteDatabaseResource/SoftDeleteObjectStorageResource (spec §82)
-- only ever set deleted_at on the databases/object_storages row itself
-- (mirroring DatabaseHandler/ObjectStorageHandler's own
-- authorizeDatabase/authorizeObjectStorage 404 checks, which read that
-- same column), never on the generic resources row. Without the two LEFT
-- JOINs below, a direct grant on a deleted database/object storage would
-- leak into this list forever.
SELECT
    rp.resource_id, r.resource_type, r.name AS resource_name,
    r.workspace_id, w.name AS workspace_name,
    rp.user_id, u.name AS user_name, u.email AS user_email, ur_role.name AS user_role,
    perm.name AS permission_name, perm.description AS permission_description,
    rp.created_at AS granted_at
FROM resource_permissions rp
JOIN resources r ON r.id = rp.resource_id
JOIN workspaces w ON w.id = r.workspace_id
LEFT JOIN databases d ON d.resource_id = r.id
LEFT JOIN object_storages os ON os.resource_id = r.id
JOIN users u ON u.id = rp.user_id
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles ur_role ON ur_role.id = ur.role_id
JOIN permissions perm ON perm.id = rp.permission_id
WHERE r.deleted_at IS NULL
    AND (d.id IS NULL OR d.deleted_at IS NULL)
    AND (os.id IS NULL OR os.deleted_at IS NULL)
    AND (sqlc.narg('resource_type')::text IS NULL OR r.resource_type = sqlc.narg('resource_type'))
    AND (sqlc.narg('workspace_id')::uuid IS NULL OR r.workspace_id = sqlc.narg('workspace_id'))
    AND (sqlc.narg('user_id')::uuid IS NULL OR rp.user_id = sqlc.narg('user_id'))
    AND (sqlc.narg('role')::text IS NULL OR ur_role.name = sqlc.narg('role'))
ORDER BY w.name, r.name, u.email, perm.name;
