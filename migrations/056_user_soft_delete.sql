-- +goose Up
-- "Remove User" (distinct from the existing Disable toggle) is a soft
-- delete, same as every other resource in this app (VMs, Workspaces,
-- Databases, Object Storage, Docker Hosts, K8s Clusters) -- never a real
-- DELETE FROM users. A hard delete would hit users.id's ON DELETE SET
-- NULL foreign keys across audit_logs, alert acknowledgements, dashboard/
-- database-operation created_by/requested_by, etc., silently anonymizing
-- who did what in every historical record. Soft-deleting keeps the row
-- (and its name/email) resolvable everywhere it's still referenced, while
-- removing it from the active Users list and (via is_active = false,
-- already set alongside deleted_at) blocking login exactly like Disable
-- already does.
ALTER TABLE users ADD COLUMN deleted_at timestamptz;

-- +goose Down
ALTER TABLE users DROP COLUMN deleted_at;
