-- name: CreateUser :one
INSERT INTO users (email, name, password_hash)
VALUES (lower(sqlc.arg(email)), sqlc.arg(name), sqlc.arg(password_hash))
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
-- Deliberately matches a soft-deleted row too (no deleted_at filter) --
-- CreateUserWithRole depends on seeing the deleted_at of an existing row
-- with this email to decide between reactivating it and erroring as
-- already-taken.
SELECT * FROM users WHERE email = lower(sqlc.arg(email));

-- name: ListActiveUsers :many
SELECT * FROM users WHERE is_active = true ORDER BY email;

-- name: UpdateUser :one
UPDATE users
SET name = $2, is_active = $3
WHERE id = $1
RETURNING *;

-- name: SetUserPasswordHash :exec
UPDATE users SET password_hash = $2 WHERE id = $1;

-- name: DeactivateUser :exec
UPDATE users SET is_active = false WHERE id = $1;

-- name: TouchUserLastLogin :exec
-- Called from AuthService.Login only (inside the same transaction that
-- issues the refresh token), never from Refresh -- "Last Login" must
-- reflect an actual login, not merely an active session being kept alive.
UPDATE users SET last_login_at = now() WHERE id = $1;

-- Every user is assigned exactly one role at creation time (ADMIN via
-- bootstrap, MEMBER via admin-created accounts); user_roles supports many
-- roles per user for future flexibility, but these queries assume one and
-- take the first match, which is always correct under that invariant.

-- name: GetUserWithRoleByID :one
SELECT u.id, u.email, u.name, u.password_hash, u.is_active, u.created_at, u.updated_at,
       u.last_login_at, r.name AS role_name
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r ON r.id = ur.role_id
WHERE u.id = $1
LIMIT 1;

-- name: GetUserWithRoleByEmail :one
SELECT u.id, u.email, u.name, u.password_hash, u.is_active, u.created_at, u.updated_at,
       r.name AS role_name
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r ON r.id = ur.role_id
WHERE u.email = lower(sqlc.arg(email))
LIMIT 1;

-- name: ListUsersWithRole :many
SELECT u.id, u.email, u.name, u.password_hash, u.is_active, u.created_at, u.updated_at,
       u.last_login_at, r.name AS role_name
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r ON r.id = ur.role_id
ORDER BY u.email;

-- name: CountAdminUsers :one
-- Despite the name (kept to avoid touching every call site), this counts
-- ADMIN *and* OWNER together -- Owner is a strict superset of Admin
-- (AuthenticatedUser.IsAdmin()), so the "system must always have at least
-- one privileged user" invariant this backs must count both.
SELECT count(*) FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
WHERE r.name IN ('ADMIN', 'OWNER');

-- name: CountActiveAdminUsers :one
-- Like CountAdminUsers but filtered to is_active=true -- the count that
-- actually matters for the last-active-admin-or-owner invariant
-- (AuthService.UpdateUserAccount): a disabled account doesn't protect the
-- system, so it must not be counted as one of the safety margin.
SELECT count(*) FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
JOIN users u ON u.id = ur.user_id
WHERE r.name IN ('ADMIN', 'OWNER') AND u.is_active = true;

-- name: CountActiveOwnerUsers :one
-- Backs a second, narrower invariant: never demote/deactivate the last
-- active OWNER specifically -- since only an Owner can ever create or
-- promote another Owner (AuthService/handlers/users.go), losing the last
-- one would permanently lock the app out of ever having an Owner again,
-- even though plenty of Admins might remain.
SELECT count(*) FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
JOIN users u ON u.id = ur.user_id
WHERE r.name = 'OWNER' AND u.is_active = true;

-- name: ListUsersFiltered :many
-- Backing query for GET /api/users' search/role filters (Step 18 Phase 4).
-- Status is deliberately NOT filtered here -- it's derived from is_active +
-- last_login_at (services.DeriveUserStatus), not a real column, so encoding
-- its three-way derivation as a SQL predicate would duplicate that logic in
-- a second language; UserHandler.List applies the status filter in Go
-- after fetching this result instead. Sort/pagination are likewise done in
-- Go (see UserHandler.List) -- no dynamic-ORDER BY/query-builder pattern
-- exists anywhere else in this codebase, and this is an internal admin
-- list at a scale where an in-memory sort/paginate after one filtered
-- fetch is simpler and more consistent with existing conventions.
SELECT u.id, u.email, u.name, u.is_active, u.last_login_at, u.created_at, r.name AS role_name
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r ON r.id = ur.role_id
WHERE
    u.deleted_at IS NULL
    AND (sqlc.narg('search')::text IS NULL OR u.name ILIKE '%' || sqlc.narg('search')::text || '%' OR u.email ILIKE '%' || sqlc.narg('search')::text || '%')
    AND (sqlc.narg('role')::text IS NULL OR r.name = sqlc.narg('role'))
ORDER BY u.email;

-- name: SoftDeleteUser :one
-- "Remove User" -- see migration 056's own doc comment for why this is a
-- soft delete (deleted_at set, row kept) rather than a real DELETE FROM
-- users. Also clears is_active so every existing "is this account allowed
-- to sign in" check (already keyed on is_active, e.g. AuthService.Login/
-- Me) blocks a deleted account too, with zero changes needed there.
UPDATE users SET deleted_at = now(), is_active = false
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: ReactivateUser :one
-- Re-inviting the same email after a Remove User (SoftDeleteUser) must
-- succeed and resurrect this SAME row/id, rather than fail against
-- users_email_unique or spawn a second row -- reusing the id keeps every
-- historical created_by/requested_by/acknowledged_by/audit_logs reference
-- (the entire reason SoftDeleteUser preserves the row instead of deleting
-- it) attached to one coherent account instead of orphaning it under a
-- dead id while a lookalike new account starts fresh. Only called from
-- CreateUserWithRole, and only once it has already confirmed the existing
-- row with this email is soft-deleted -- the WHERE clause is a second,
-- defensive guard against ever reactivating a still-active row.
UPDATE users
SET name = $2, password_hash = $3, is_active = true, deleted_at = NULL
WHERE id = $1 AND deleted_at IS NOT NULL
RETURNING *;

-- name: RemoveAllUserRoles :exec
-- Clears every prior role assignment before CreateUserWithRole re-assigns
-- exactly one fresh role on a reactivated account -- the re-invite's role
-- may differ from whatever the account held before it was removed.
DELETE FROM user_roles WHERE user_id = $1;

-- Per-user resource-count aggregates backing GET /api/users' Workspaces/
-- VMs/Databases/Object Storage columns. Each is a single-pass GROUP BY
-- over the whole table rather than a per-row correlated subquery, so
-- UserHandler.List can join the results into a map[uuid.UUID]int64 in Go
-- without an N+1 query per listed user.

-- name: CountWorkspaceMembershipsPerUser :many
SELECT user_id, count(*) AS cnt FROM workspace_members GROUP BY user_id;

-- name: CountEffectiveWorkspaceAccessPerUser :many
-- Mirrors ListWorkspacesForUserAccess's own member-union EXISTS logic
-- (workspaces.sql), just aggregated across all users at once instead of
-- checked per-user -- a workspace counts once per user regardless of how
-- many resources within it they can reach.
SELECT user_id, count(DISTINCT workspace_id) AS cnt FROM (
    SELECT wm.user_id, wm.workspace_id FROM workspace_members wm
    UNION
    SELECT rp.user_id, r.workspace_id FROM resource_permissions rp JOIN resources r ON r.id = rp.resource_id
) combined GROUP BY user_id;

-- name: CountEffectiveVMAccessPerUser :many
-- Direct grants union workspace-derived access, mirroring
-- AuthorizationService.EffectiveVMAccess's two access paths -- a VM
-- reachable via both counts once. Excludes DISABLED/soft-deleted VMs and
-- inactive workspaces, matching EffectiveVMAccess's own exclusions.
SELECT user_id, count(DISTINCT resource_id) AS cnt FROM (
    SELECT rp.user_id, rp.resource_id FROM resource_permissions rp JOIN resources r ON r.id = rp.resource_id
    WHERE r.resource_type = 'VM' AND r.status != 'DISABLED' AND r.deleted_at IS NULL
    UNION
    SELECT wm.user_id, r.id FROM workspace_members wm JOIN workspaces w ON w.id = wm.workspace_id JOIN resources r ON r.workspace_id = w.id
    WHERE w.is_active = true AND r.resource_type = 'VM' AND r.status != 'DISABLED' AND r.deleted_at IS NULL
) combined GROUP BY user_id;

-- name: CountEffectiveDatabaseAccessPerUser :many
-- Same shape as CountEffectiveVMAccessPerUser, resource_type = 'DATABASE'.
-- resources.deleted_at alone is NOT enough to exclude a soft-deleted
-- database: SoftDeleteDatabaseResource only ever sets deleted_at on the
-- databases row itself (the generic resources.deleted_at column has no
-- writer anywhere in this codebase for Database/ObjectStorage) -- see
-- ListAllDirectResourceGrants (resources.sql) for the same caveat and the
-- LEFT JOIN pattern this mirrors exactly.
SELECT user_id, count(DISTINCT resource_id) AS cnt FROM (
    SELECT rp.user_id, rp.resource_id FROM resource_permissions rp
    JOIN resources r ON r.id = rp.resource_id
    JOIN databases d ON d.resource_id = r.id
    WHERE r.resource_type = 'DATABASE' AND r.status != 'DISABLED' AND r.deleted_at IS NULL AND d.deleted_at IS NULL
    UNION
    SELECT wm.user_id, r.id FROM workspace_members wm
    JOIN workspaces w ON w.id = wm.workspace_id
    JOIN resources r ON r.workspace_id = w.id
    JOIN databases d ON d.resource_id = r.id
    WHERE w.is_active = true AND r.resource_type = 'DATABASE' AND r.status != 'DISABLED' AND r.deleted_at IS NULL AND d.deleted_at IS NULL
) combined GROUP BY user_id;

-- name: CountEffectiveObjectStorageAccessPerUser :many
-- Same shape as CountEffectiveDatabaseAccessPerUser, resource_type =
-- 'OBJECT_STORAGE' -- same object_storages.deleted_at caveat.
SELECT user_id, count(DISTINCT resource_id) AS cnt FROM (
    SELECT rp.user_id, rp.resource_id FROM resource_permissions rp
    JOIN resources r ON r.id = rp.resource_id
    JOIN object_storages os ON os.resource_id = r.id
    WHERE r.resource_type = 'OBJECT_STORAGE' AND r.status != 'DISABLED' AND r.deleted_at IS NULL AND os.deleted_at IS NULL
    UNION
    SELECT wm.user_id, r.id FROM workspace_members wm
    JOIN workspaces w ON w.id = wm.workspace_id
    JOIN resources r ON r.workspace_id = w.id
    JOIN object_storages os ON os.resource_id = r.id
    WHERE w.is_active = true AND r.resource_type = 'OBJECT_STORAGE' AND r.status != 'DISABLED' AND r.deleted_at IS NULL AND os.deleted_at IS NULL
) combined GROUP BY user_id;

-- name: LockAdminRoleGuard :exec
-- Acquires a Postgres advisory lock scoped to the calling transaction
-- (released automatically at COMMIT/ROLLBACK), serializing concurrent
-- admin role/status changes against each other. Without it, two concurrent
-- requests could each read the same "2 active admins" count independently
-- and both proceed to demote/disable one of them, leaving zero active
-- admins -- a plain SELECT-then-UPDATE race with a genuinely catastrophic
-- outcome. This is the first and only advisory lock in this codebase: it's
-- justified specifically because this is a narrow, low-traffic, admin-only
-- path, not a general pattern to reach for on hotter paths. The constant
-- is arbitrary and has no meaning beyond being unique to this lock.
SELECT pg_advisory_xact_lock(823746192);
