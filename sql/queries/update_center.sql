-- Step 9: OS/kernel/reboot update detection and update planning. Package-
-- level data is deliberately never duplicated here -- every package-level
-- query (ListPackageUpdatesByVM, GetPackageWithStatusByID, ...) already
-- exists in packages.sql from Step 7 and is reused as-is.

-- === OS update status (one row per VM, upserted each scan) ===

-- name: UpsertOSUpdateStatus :one
-- Only ever called with a real detection result -- a transient scan
-- failure simply skips this call, leaving the previous good status in
-- place (mirrors UpdateVMPackageManager/UpdateVMDockerStatus).
INSERT INTO os_updates (vm_id, current_version, available_version, update_type, status, release_channel)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (vm_id) DO UPDATE SET
    current_version   = EXCLUDED.current_version,
    available_version = EXCLUDED.available_version,
    update_type        = EXCLUDED.update_type,
    status              = EXCLUDED.status,
    release_channel      = EXCLUDED.release_channel,
    detected_at           = now()
RETURNING *;

-- name: GetOSUpdateByVM :one
SELECT * FROM os_updates WHERE vm_id = $1;

-- === Kernel/reboot state (lives directly on vms, "current known state") ===

-- name: UpdateVMKernelStatus :one
UPDATE vms
SET kernel_version = $2, kernel_available = $3, reboot_status = $4, reboot_reason = $5
WHERE id = $1
RETURNING *;

-- === Update plans ===

-- name: CreateUpdatePlan :one
INSERT INTO update_plans (vm_id, created_by) VALUES ($1, $2) RETURNING *;

-- name: GetUpdatePlanByID :one
SELECT * FROM update_plans WHERE id = $1;

-- name: GetUpdatePlanDetail :one
-- The plan-detail endpoint's single read: VM identity + creator identity
-- alongside the plan row itself, so the handler never needs a second
-- round trip just to render "created by <name>" / "VM: <name>".
SELECT
    up.id, up.vm_id, up.created_by, up.status, up.created_at, up.updated_at,
    v.resource_id AS vm_resource_id, r.name AS vm_name,
    u.name AS created_by_name, u.email AS created_by_email
FROM update_plans up
JOIN vms v ON v.id = up.vm_id
JOIN resources r ON r.id = v.resource_id
LEFT JOIN users u ON u.id = up.created_by
WHERE up.id = $1;

-- name: ListUpdatePlansByVM :many
SELECT * FROM update_plans WHERE vm_id = $1 ORDER BY created_at DESC;

-- name: SetUpdatePlanStatus :one
UPDATE update_plans SET status = $2 WHERE id = $1 RETURNING *;

-- name: InsertUpdatePlanItem :one
INSERT INTO update_plan_items (
    update_plan_id, package_id, package_name, current_version, target_version, update_type, security_update, severity
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListUpdatePlanItemsByPlan :many
SELECT * FROM update_plan_items WHERE update_plan_id = $1 ORDER BY package_name;

-- === Prechecks ===

-- name: HasSSHCredential :one
-- Named credentials only (migration 051) -- a VM is SSH-eligible once it
-- points at an ssh_key_credentials row via vms.ssh_key_credential_id, not
-- via the legacy per-VM credentials table.
SELECT EXISTS (
    SELECT 1 FROM vms WHERE resource_id = $1 AND ssh_key_credential_id IS NOT NULL
) AS exists;

-- name: GetRunningUpdateOperationByResource :one
-- The concurrency lock (spec #40): a non-terminal OS_UPDATE/PACKAGE_UPDATE
-- operation for this VM blocks a plan from becoming READY/being executed.
-- Step 9 itself never creates such a row -- this only ever finds one Step
-- 10 created. Not itself row-locking (read-only precheck display); the
-- authoritative atomic check at execution time is
-- GetActiveOperationForResourceLocked inside a transaction.
--
-- exclude_operation_id lets the running operation's OWN precheck step
-- revalidate the plan without perpetually conflicting with itself -- by
-- the time Run() executes, the operation this check would otherwise find
-- IS this same operation (exclusivity was already guaranteed atomically
-- at claim time by GetActiveOperationForResourceLocked, so re-detecting
-- it here would be a false positive, not a real conflict). Every other
-- caller (the standalone /validate endpoint, RequestExecution's pre-claim
-- revalidation) passes NULL, since no operation exists yet at those call
-- sites.
SELECT * FROM operations
WHERE resource_id = $1 AND operation_type IN ('OS_UPDATE', 'PACKAGE_UPDATE')
    AND status IN ('PENDING', 'CONNECTING', 'RUNNING', 'VERIFYING')
    AND (sqlc.narg('exclude_operation_id')::uuid IS NULL OR id != sqlc.narg('exclude_operation_id')::uuid)
ORDER BY created_at DESC
LIMIT 1;

-- === Cross-VM update summary (spec #14/#44/#46) ===

-- name: ListVMUpdateSummaries :many
-- One row per VM with every count the Update Center dashboard and the
-- member-scoped "My VM Updates" list need. resource_ids is the same
-- optional sqlc.narg restriction ListRecommendationsFiltered already
-- uses: NULL (admin) is unrestricted, an explicit slice (member) matches
-- only their authorized VMs, and an empty-but-non-nil slice correctly
-- matches nothing rather than everything.
SELECT
    r.id AS resource_id, r.name AS vm_name, v.id AS vm_id,
    ou.status AS os_status, ou.current_version AS os_current_version, ou.available_version AS os_available_version,
    v.kernel_version AS kernel_running, v.kernel_available, v.reboot_status,
    count(pu.id) FILTER (WHERE pu.recommendation_status NOT IN ('RESOLVED', 'DISMISSED')) AS package_update_count,
    count(pu.id) FILTER (
        WHERE pu.recommendation_status NOT IN ('RESOLVED', 'DISMISSED') AND pu.security_status = 'CONFIRMED'
    ) AS security_update_count
FROM resources r
JOIN vms v ON v.resource_id = r.id
LEFT JOIN os_updates ou ON ou.vm_id = v.id
LEFT JOIN package_updates pu ON pu.vm_id = v.id
WHERE r.resource_type = 'VM' AND r.deleted_at IS NULL
    AND (sqlc.narg('resource_ids')::uuid[] IS NULL OR r.id = ANY(sqlc.narg('resource_ids')::uuid[]))
GROUP BY r.id, r.name, v.id, ou.status, ou.current_version, ou.available_version, v.kernel_version, v.kernel_available, v.reboot_status
ORDER BY r.name;

-- name: GetSecurityUpdateSeverityCounts :one
SELECT
    count(*) FILTER (WHERE pu.severity = 'CRITICAL') AS critical,
    count(*) FILTER (WHERE pu.severity = 'HIGH') AS high,
    count(*) FILTER (WHERE pu.severity = 'MEDIUM') AS medium,
    count(*) FILTER (WHERE pu.severity = 'LOW') AS low,
    count(*) FILTER (WHERE pu.severity = 'UNKNOWN') AS unknown
FROM package_updates pu
WHERE pu.vm_id = $1 AND pu.recommendation_status NOT IN ('RESOLVED', 'DISMISSED') AND pu.security_status = 'CONFIRMED';
