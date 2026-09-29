-- name: CreateRole :one
INSERT INTO roles (name, description)
VALUES ($1, $2)
RETURNING *;

-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = $1;

-- name: ListRoles :many
SELECT * FROM roles ORDER BY name;

-- name: CreatePermission :one
INSERT INTO permissions (name, description)
VALUES ($1, $2)
RETURNING *;

-- name: GetPermissionByName :one
SELECT * FROM permissions WHERE name = $1;

-- name: ListPermissions :many
SELECT * FROM permissions ORDER BY name;

-- name: AssignUserRole :exec
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- name: RemoveUserRole :exec
DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2;

-- name: ListRolesForUser :many
SELECT r.* FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1
ORDER BY r.name;

-- name: ListUsersForRole :many
SELECT u.* FROM users u
JOIN user_roles ur ON ur.user_id = u.id
WHERE ur.role_id = $1
ORDER BY u.email;
