-- name: CreateVM :one
INSERT INTO vms (resource_id, hostname, username, address, ssh_port, ssh_key_credential_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetVMByID :one
SELECT * FROM vms WHERE id = $1;

-- name: GetVMByResourceID :one
SELECT * FROM vms WHERE resource_id = $1;

-- Partial update: every field is nullable here regardless of its
-- underlying column type, and a NULL argument leaves the existing value
-- untouched via COALESCE. This is what lets discovery save whatever
-- commands succeeded without erasing previously-known values when other
-- commands failed (Step 5 spec §35/§36 -- partial discovery must not
-- destroy old valid data).
-- name: UpdateVMDiscoveryResult :one
UPDATE vms
SET hostname            = COALESCE(sqlc.narg('hostname'), hostname),
    os_name             = COALESCE(sqlc.narg('os_name'), os_name),
    os_version          = COALESCE(sqlc.narg('os_version'), os_version),
    distribution_id     = COALESCE(sqlc.narg('distribution_id'), distribution_id),
    kernel_version      = COALESCE(sqlc.narg('kernel_version'), kernel_version),
    architecture        = COALESCE(sqlc.narg('architecture'), architecture),
    cpu_cores           = COALESCE(sqlc.narg('cpu_cores'), cpu_cores),
    total_memory_bytes  = COALESCE(sqlc.narg('total_memory_bytes'), total_memory_bytes),
    total_storage_bytes = COALESCE(sqlc.narg('total_storage_bytes'), total_storage_bytes),
    docker_installed    = COALESCE(sqlc.narg('docker_installed'), docker_installed),
    last_discovered_at  = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: UpdateVMLastSeen :exec
UPDATE vms SET last_seen_at = now() WHERE id = $1;

-- name: UpdateVMConnectionStatus :one
-- last_connection_at tracks the last *successful* connection (mirrors
-- last_seen_at's "only update if actually contacted" rule); the error
-- string is cleared on success and set on failure.
UPDATE vms
SET connection_status = sqlc.arg('connection_status'),
    last_connection_at = CASE WHEN sqlc.arg('connection_status') = 'CONNECTED' THEN now() ELSE last_connection_at END,
    last_connection_error = sqlc.narg('last_connection_error')
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: HasSSHCredentialConfigured :one
SELECT EXISTS(
    SELECT 1 FROM credentials
    WHERE resource_id = $1 AND credential_type = 'SSH_PRIVATE_KEY'
);

-- Editable at registration time / by an admin later. Discovery fields
-- (os_name, cpu_cores, ...) are deliberately not settable here -- only
-- UpdateVMDiscovery (a later step's discovery job) writes those, so the UI
-- can never inject fake hardware/OS data (Step 4 spec: "Do not insert fake
-- information").
-- name: UpdateVMFields :one
UPDATE vms
SET hostname = $2, username = $3, address = $4, ssh_port = $5, ssh_key_credential_id = $6
WHERE id = $1
RETURNING *;

-- VM detail views join the common resource row (identity, status,
-- workspace) with the vms detail row. "resource_id" here is the
-- authoritative VM identifier used throughout the API and the
-- authorization service -- see docs/database-architecture.md. Discovery
-- columns are included as-is (NULL until a later step's discovery job
-- runs) -- callers must render NULL as "Not discovered", never a fake
-- value.

-- name: GetVMDetailByResourceID :one
SELECT
    r.id AS resource_id, r.name, r.status, r.description, r.workspace_id, w.name AS workspace_name, r.monitoring_enabled,
    v.id AS vm_id, v.hostname, v.username, v.address, v.ssh_port,
    v.os_name, v.os_version, v.kernel_version, v.architecture,
    v.cpu_cores, v.total_memory_bytes, v.total_storage_bytes, v.docker_installed,
    v.distribution_id, v.connection_status, v.last_connection_at, v.last_connection_error, v.package_manager,
    v.last_discovered_at, v.last_seen_at, r.created_at, r.updated_at,
    v.ssh_key_credential_id, k.name AS ssh_key_credential_name,
    v.vm_agent_os, v.vm_agent_os_version, v.vm_agent_kernel_version, v.vm_agent_hostname
FROM resources r
JOIN vms v ON v.resource_id = r.id
JOIN workspaces w ON w.id = r.workspace_id
LEFT JOIN ssh_key_credentials k ON k.id = v.ssh_key_credential_id
WHERE r.id = $1 AND r.resource_type = 'VM' AND r.deleted_at IS NULL;

-- name: ListVMDetailsByResourceIDs :many
SELECT
    r.id AS resource_id, r.name, r.status, r.description, r.workspace_id, w.name AS workspace_name, r.monitoring_enabled,
    v.id AS vm_id, v.hostname, v.username, v.address, v.ssh_port,
    v.os_name, v.os_version, v.kernel_version, v.architecture,
    v.cpu_cores, v.total_memory_bytes, v.total_storage_bytes, v.docker_installed,
    v.distribution_id, v.connection_status, v.last_connection_at, v.last_connection_error, v.package_manager,
    v.last_discovered_at, v.last_seen_at, r.created_at, r.updated_at,
    v.ssh_key_credential_id, k.name AS ssh_key_credential_name,
    v.vm_agent_os, v.vm_agent_os_version, v.vm_agent_kernel_version, v.vm_agent_hostname
FROM resources r
JOIN vms v ON v.resource_id = r.id
JOIN workspaces w ON w.id = r.workspace_id
LEFT JOIN ssh_key_credentials k ON k.id = v.ssh_key_credential_id
WHERE r.id = ANY($1::uuid[]) AND r.resource_type = 'VM' AND r.deleted_at IS NULL
ORDER BY r.name;

-- name: ListAllVMDetails :many
SELECT
    r.id AS resource_id, r.name, r.status, r.description, r.workspace_id, w.name AS workspace_name, r.monitoring_enabled,
    v.id AS vm_id, v.hostname, v.username, v.address, v.ssh_port,
    v.os_name, v.os_version, v.kernel_version, v.architecture,
    v.cpu_cores, v.total_memory_bytes, v.total_storage_bytes, v.docker_installed,
    v.distribution_id, v.connection_status, v.last_connection_at, v.last_connection_error, v.package_manager,
    v.last_discovered_at, v.last_seen_at, r.created_at, r.updated_at,
    v.ssh_key_credential_id, k.name AS ssh_key_credential_name,
    v.vm_agent_os, v.vm_agent_os_version, v.vm_agent_kernel_version, v.vm_agent_hostname
FROM resources r
JOIN vms v ON v.resource_id = r.id
JOIN workspaces w ON w.id = r.workspace_id
LEFT JOIN ssh_key_credentials k ON k.id = v.ssh_key_credential_id
WHERE r.resource_type = 'VM' AND r.deleted_at IS NULL
ORDER BY r.name;
