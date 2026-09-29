-- Notification fan-out recipient resolution. Admins always see every
-- alert (mirrors CanAccessVM/CanAccessDatabase's unconditional Admin
-- bypass everywhere else in this project); Members only for resources
-- they hold a direct grant on or reach via workspace membership --
-- exactly the same two access paths EffectiveVMAccess/
-- EffectiveDatabaseAccess already check, just resolved for "which users"
-- instead of "does this one user have access."

-- name: ListAdminUserIDs :many
SELECT u.id FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r ON r.id = ur.role_id
WHERE r.name = 'ADMIN' AND u.is_active;

-- name: ListAuthorizedMemberUserIDsForResource :many
SELECT DISTINCT u.id
FROM users u
WHERE u.is_active AND (
    u.id IN (SELECT rp.user_id FROM resource_permissions rp WHERE rp.resource_id = $1)
    OR u.id IN (
        SELECT wm.user_id FROM workspace_members wm
        JOIN resources res ON res.workspace_id = wm.workspace_id
        WHERE res.id = $1
    )
);
