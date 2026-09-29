-- ssh_key_credentials -- named, reusable SSH key credentials
-- (workspace-scoped). See migrations/051_ssh_key_credentials.sql and
-- services.SSHKeyCredentialService.

-- name: CreateSSHKeyCredential :one
INSERT INTO ssh_key_credentials (workspace_id, name, encrypted_private_key, fingerprint, created_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSSHKeyCredentialByID :one
SELECT * FROM ssh_key_credentials WHERE id = $1;

-- name: ListSSHKeyCredentialsByWorkspace :many
-- Includes how many VMs currently reference each credential, so the UI
-- can show "used by N VM(s)" and a delete confirmation can warn
-- accurately before the request is even attempted.
SELECT k.*, COUNT(v.id) AS in_use_count
FROM ssh_key_credentials k
LEFT JOIN vms v ON v.ssh_key_credential_id = k.id
WHERE k.workspace_id = $1
GROUP BY k.id
ORDER BY k.name;

-- name: RenameSSHKeyCredential :one
UPDATE ssh_key_credentials SET name = $2 WHERE id = $1 RETURNING *;

-- name: DeleteSSHKeyCredential :exec
DELETE FROM ssh_key_credentials WHERE id = $1;

-- name: CountVMsBySSHKeyCredential :one
SELECT COUNT(*) FROM vms WHERE ssh_key_credential_id = $1;

-- name: ListLegacySSHCredentialsForBackfill :many
-- One-off migration helper (see cmd/backfill-ssh-key-credentials): every
-- VM that still has an old-style credentials(SSH_PRIVATE_KEY) row but no
-- ssh_key_credential_id yet. Re-running is a no-op once every VM has been
-- migrated, since the WHERE clause excludes anything already attached.
SELECT
    c.id AS credential_id, c.encrypted_data,
    v.id AS vm_id, r.id AS resource_id, r.name AS resource_name, r.workspace_id
FROM credentials c
JOIN resources r ON r.id = c.resource_id
JOIN vms v ON v.resource_id = r.id
WHERE c.credential_type = 'SSH_PRIVATE_KEY' AND v.ssh_key_credential_id IS NULL
ORDER BY r.name;

-- name: SetVMSSHKeyCredentialID :exec
UPDATE vms SET ssh_key_credential_id = $2 WHERE id = $1;
