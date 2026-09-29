-- name: ListPackageScanEnabledVMs :many
-- The package scan scheduler's work list: every active VM with SSH
-- configured (same base eligibility as ListMonitoringEnabledVMs in Step
-- 6 -- there is no separate per-VM package-scan opt-out in this step).
SELECT r.id AS resource_id, v.id AS vm_id, r.name
FROM resources r
JOIN vms v ON v.resource_id = r.id
WHERE r.resource_type = 'VM'
  AND r.deleted_at IS NULL
  AND r.status != 'DISABLED'
  AND v.ssh_key_credential_id IS NOT NULL
ORDER BY r.name;

-- name: UpdateVMPackageManager :one
-- Only ever called with a real detected value (Step 7 spec §4: a
-- detection failure must never overwrite a previously-good value here --
-- the caller simply doesn't call this query on failure).
UPDATE vms SET package_manager = $2 WHERE id = $1 RETURNING *;

-- name: CreatePackageDiscoveryRun :one
INSERT INTO package_discovery_runs (vm_id, package_manager, status)
VALUES ($1, $2, 'RUNNING')
RETURNING *;

-- name: CompletePackageDiscoveryRun :one
UPDATE package_discovery_runs
SET status = $2, package_count = $3, error_summary = $4, completed_at = now()
WHERE id = $1
RETURNING *;

-- name: ListPackageDiscoveryRunsByVM :many
SELECT * FROM package_discovery_runs
WHERE vm_id = $1
ORDER BY started_at DESC
LIMIT $2;

-- name: GetLatestPackageDiscoveryRun :one
SELECT * FROM package_discovery_runs
WHERE vm_id = $1
ORDER BY started_at DESC
LIMIT 1;

-- name: SetVMPackageBaselineIfUnset :exec
-- Auto-stamp: only ever takes effect once, on the VM's first scan whose
-- package *inventory* step succeeds (services.PackageService.Scan calls
-- this right after the upsert loop, independent of whether the separate
-- update-metadata refresh also succeeded -- a scan can be PARTIAL purely
-- because "apt-get update" needs privileges the SSH user doesn't have,
-- which has nothing to do with whether the inventory itself was read) --
-- a no-op every time after, so it's safe to call on every scan without
-- re-checking state first. Stamps to the VM's own created_at, not now():
-- the first scan can legitimately run long after the VM was actually
-- registered/onboarded (an admin doesn't always click "Scan" the instant
-- they add a VM), and anything installed manually in that gap must still
-- count as "installed since onboarding" -- see migration 054.
UPDATE vms SET package_baseline_at = created_at WHERE id = $1 AND package_baseline_at IS NULL;

-- name: SetVMPackageBaselineNow :one
-- Admin-only manual override ("Reset Baseline to Now") for a VM that was
-- already customized before onboarding -- unlike the auto-stamp above,
-- this always overwrites, moving the cutoff forward.
UPDATE vms SET package_baseline_at = now() WHERE id = $1 RETURNING *;

-- name: UpsertPackage :one
-- removed_at is explicitly cleared here: a package that disappeared from
-- a previous scan (soft-deleted) and is now reported again by a fresh
-- scan is, by definition, reinstalled, not still-removed. installed_at is
-- the package manager's own install-time record (nil when unavailable --
-- see package_manager_impl.go); COALESCE on conflict so a scan that
-- couldn't determine it this time never blanks out a previously-known
-- value, and a package whose OS-level install time never changes doesn't
-- need re-writing every scan anyway.
INSERT INTO packages (vm_id, name, installed_version, package_manager, architecture, description, last_discovered_at, installed_at)
VALUES ($1, $2, $3, $4, $5, $6, now(), $7)
ON CONFLICT (vm_id, name, architecture)
DO UPDATE SET installed_version = EXCLUDED.installed_version,
              description = EXCLUDED.description,
              last_discovered_at = now(),
              removed_at = NULL,
              installed_at = COALESCE(EXCLUDED.installed_at, packages.installed_at)
RETURNING *;

-- name: MarkPackagesRemovedSince :exec
-- Any OS package for this VM whose last_discovered_at predates this
-- scan's start (i.e. a still-current scan didn't touch it) is no longer
-- installed. Soft-deleted (removed_at set), never hard-deleted, so
-- history is preserved (Step 7 spec §47). Scoped to OS package managers
-- only, mirroring MarkExternalPackagesRemovedSince's own scoping in the
-- other direction: an OS-only scan (services.PackageService.Scan) never
-- re-lists pip/npm/gem/snap packages, so without this restriction it
-- would incorrectly soft-delete every external package on the very next
-- OS-only scan after it was first discovered -- exactly what was
-- happening to a real "microk8s" (SNAP) package before this fix.
UPDATE packages
SET removed_at = now()
WHERE vm_id = $1 AND removed_at IS NULL AND last_discovered_at < $2
    AND package_manager IN ('APT', 'DPKG', 'DNF', 'YUM', 'RPM');

-- name: MarkExternalPackagesRemovedSince :exec
-- Same soft-delete-if-not-reseen shape as MarkPackagesRemovedSince, but
-- scoped to only the externally-installed ecosystems -- an external-
-- package scan only re-lists pip/npm/gem/snap, so it must never touch
-- (and accidentally soft-delete) OS packages it didn't just re-see.
UPDATE packages
SET removed_at = now()
WHERE vm_id = $1 AND removed_at IS NULL AND last_discovered_at < $2
    AND package_manager IN ('PIP', 'NPM', 'GEM', 'SNAP');

-- name: ListExternalPackagesForVM :many
-- The "Externally Installed Packages" section's listing -- no
-- package_updates join (these are list-only, no update checking).
SELECT * FROM packages
WHERE vm_id = $1 AND removed_at IS NULL AND package_manager IN ('PIP', 'NPM', 'GEM', 'SNAP')
ORDER BY package_manager, name;

-- name: GetPackageByID :one
SELECT * FROM packages WHERE id = $1;

-- name: ListPackagesByVM :many
-- Every current (non-removed) package, unfiltered/unjoined -- used to
-- build the name/architecture -> id map for RefreshUpdates, which
-- doesn't re-list installed packages and so needs to know what's already
-- on file.
SELECT * FROM packages WHERE vm_id = $1 AND removed_at IS NULL ORDER BY name;

-- name: ListPackagesWithStatus :many
-- The packages page's main listing: each package joined with whatever
-- *active* (not resolved/dismissed) update situation it has, if any --
-- letting the API derive UP_TO_DATE / UPDATE_AVAILABLE / SECURITY_UPDATE
-- without a second round-trip. Every filter is optional (sqlc.narg,
-- mirroring ListResourcesFiltered's established idiom in resources.sql)
-- so the same query serves the unfiltered "all packages" list too.
SELECT
    p.id, p.vm_id, p.name, p.installed_version, p.package_manager, p.architecture,
    p.description, p.last_discovered_at, p.created_at, p.updated_at, p.installed_at,
    pu.id AS update_id, pu.available_version, pu.severity AS update_severity,
    pu.is_security_update, pu.security_status, pu.recommendation_status,
    pu.release AS update_release
FROM packages p
JOIN vms v ON v.id = p.vm_id
LEFT JOIN package_updates pu
    ON pu.package_id = p.id AND pu.vm_id = p.vm_id AND pu.recommendation_status NOT IN ('RESOLVED', 'DISMISSED')
WHERE p.vm_id = $1
    AND p.removed_at IS NULL
    -- The OS-package-only restriction is skipped specifically for
    -- new_since_baseline=true: "Installed Since Onboarding" means
    -- anything installed after the cutoff, any package manager (pip/npm/
    -- gem/snap included) -- unlike the unfiltered/general listing below,
    -- which stays OS-only so it doesn't silently duplicate the separate
    -- "Externally Installed Packages" section.
    AND (sqlc.narg('new_since_baseline')::bool IS TRUE OR p.package_manager IN ('APT', 'DPKG', 'DNF', 'YUM', 'RPM'))
    AND (sqlc.narg('search')::text IS NULL OR p.name ILIKE '%' || sqlc.narg('search')::text || '%')
    AND (sqlc.narg('package_manager')::text IS NULL OR p.package_manager = sqlc.narg('package_manager'))
    AND (sqlc.narg('security_only')::bool IS NULL OR sqlc.narg('security_only')::bool = false OR pu.security_status = 'CONFIRMED')
    AND (
        sqlc.narg('new_since_baseline')::bool IS NULL OR sqlc.narg('new_since_baseline')::bool = false
        -- COALESCE(installed_at, created_at): the package manager's own
        -- install-time record is the ground truth when we have it (APT
        -- dpkg-info mtime, RPM INSTALLTIME); only falls back to our own
        -- discovery time when that's unavailable (pip/npm/gem/snap, or an
        -- APT/RPM read that failed). See migration 054.
        OR (v.package_baseline_at IS NOT NULL AND COALESCE(p.installed_at, p.created_at) > v.package_baseline_at)
    )
    AND (
        sqlc.narg('status')::text IS NULL
        OR (sqlc.narg('status')::text = 'UP_TO_DATE' AND pu.id IS NULL)
        OR (sqlc.narg('status')::text = 'UPDATE_AVAILABLE' AND pu.id IS NOT NULL AND pu.security_status != 'CONFIRMED')
        OR (sqlc.narg('status')::text = 'SECURITY_UPDATE' AND pu.security_status = 'CONFIRMED')
        OR (sqlc.narg('status')::text = 'HAS_UPDATE' AND pu.id IS NOT NULL)
    )
ORDER BY p.name
LIMIT $2 OFFSET $3;

-- name: CountPackagesWithStatus :one
-- Mirrors ListPackagesWithStatus's filters exactly, for pagination totals.
SELECT count(*)
FROM packages p
JOIN vms v ON v.id = p.vm_id
LEFT JOIN package_updates pu
    ON pu.package_id = p.id AND pu.vm_id = p.vm_id AND pu.recommendation_status NOT IN ('RESOLVED', 'DISMISSED')
WHERE p.vm_id = $1
    AND p.removed_at IS NULL
    AND (sqlc.narg('new_since_baseline')::bool IS TRUE OR p.package_manager IN ('APT', 'DPKG', 'DNF', 'YUM', 'RPM'))
    AND (sqlc.narg('search')::text IS NULL OR p.name ILIKE '%' || sqlc.narg('search')::text || '%')
    AND (sqlc.narg('package_manager')::text IS NULL OR p.package_manager = sqlc.narg('package_manager'))
    AND (sqlc.narg('security_only')::bool IS NULL OR sqlc.narg('security_only')::bool = false OR pu.security_status = 'CONFIRMED')
    AND (
        sqlc.narg('new_since_baseline')::bool IS NULL OR sqlc.narg('new_since_baseline')::bool = false
        OR (v.package_baseline_at IS NOT NULL AND COALESCE(p.installed_at, p.created_at) > v.package_baseline_at)
    )
    AND (
        sqlc.narg('status')::text IS NULL
        OR (sqlc.narg('status')::text = 'UP_TO_DATE' AND pu.id IS NULL)
        OR (sqlc.narg('status')::text = 'UPDATE_AVAILABLE' AND pu.id IS NOT NULL AND pu.security_status != 'CONFIRMED')
        OR (sqlc.narg('status')::text = 'SECURITY_UPDATE' AND pu.security_status = 'CONFIRMED')
        OR (sqlc.narg('status')::text = 'HAS_UPDATE' AND pu.id IS NOT NULL)
    );

-- name: GetPackageWithStatusByID :one
SELECT
    p.id, p.vm_id, p.name, p.installed_version, p.package_manager, p.architecture,
    p.description, p.last_discovered_at, p.created_at, p.updated_at, p.installed_at,
    pu.id AS update_id, pu.available_version, pu.severity AS update_severity,
    pu.is_security_update, pu.security_status, pu.recommendation_status,
    pu.release AS update_release
FROM packages p
LEFT JOIN package_updates pu
    ON pu.package_id = p.id AND pu.vm_id = p.vm_id AND pu.recommendation_status NOT IN ('RESOLVED', 'DISMISSED')
WHERE p.id = $1 AND p.vm_id = $2 AND p.removed_at IS NULL;

-- name: GetPackageSummaryByVM :one
SELECT
    count(*) FILTER (WHERE p.removed_at IS NULL) AS total,
    count(*) FILTER (WHERE p.removed_at IS NULL AND pu.id IS NULL) AS up_to_date,
    count(*) FILTER (WHERE p.removed_at IS NULL AND pu.id IS NOT NULL) AS updates_available,
    count(*) FILTER (WHERE p.removed_at IS NULL AND pu.security_status = 'CONFIRMED') AS security_updates
FROM packages p
LEFT JOIN package_updates pu
    ON pu.package_id = p.id AND pu.vm_id = p.vm_id AND pu.recommendation_status NOT IN ('RESOLVED', 'DISMISSED')
WHERE p.vm_id = $1 AND p.package_manager IN ('APT', 'DPKG', 'DNF', 'YUM', 'RPM');

-- name: UpsertPackageUpdate :one
-- ON CONFLICT (vm_id, package_id) is the deduplication Step 7 spec §19
-- requires: a repeat scan that finds the *same* available version leaves
-- recommendation_status untouched (an admin's ACKNOWLEDGED/DISMISSED
-- sticks); a *changed* available version, or a previously RESOLVED row
-- reappearing, resets to NEW since that's materially new information.
INSERT INTO package_updates (
    vm_id, package_id, current_version, available_version, severity,
    is_security_update, security_status, architecture, release
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (vm_id, package_id) DO UPDATE SET
    current_version    = EXCLUDED.current_version,
    available_version  = EXCLUDED.available_version,
    severity            = EXCLUDED.severity,
    is_security_update  = EXCLUDED.is_security_update,
    security_status      = EXCLUDED.security_status,
    architecture         = EXCLUDED.architecture,
    release              = EXCLUDED.release,
    detected_at          = now(),
    recommendation_status = CASE
        WHEN package_updates.available_version = EXCLUDED.available_version
             AND package_updates.recommendation_status != 'RESOLVED'
            THEN package_updates.recommendation_status
        ELSE 'NEW'
    END
RETURNING *;

-- name: ResolvePackageUpdatesNotSeenSince :many
-- A package_updates row not refreshed by the current scan (its
-- detected_at predates the scan's start) means that update situation no
-- longer exists -- either the package was upgraded to the available
-- version, or removed entirely. Resolved, never deleted (spec §48);
-- DISMISSED is left alone (an admin's explicit dismissal isn't
-- overridden by a scan just because the package also happens to now be
-- up to date -- there's nothing left to dismiss, but nothing to silently
-- relabel either). Returns the resolved rows' ids so callers can also
-- resolve their linked recommendations.
UPDATE package_updates
SET recommendation_status = 'RESOLVED'
WHERE vm_id = $1 AND detected_at < $2 AND recommendation_status NOT IN ('RESOLVED', 'DISMISSED')
RETURNING *;

-- name: ListPackageUpdatesByVM :many
SELECT pu.*, p.name AS package_name
FROM package_updates pu
JOIN packages p ON p.id = pu.package_id
WHERE pu.vm_id = $1
    AND pu.recommendation_status != 'RESOLVED'
    AND (sqlc.narg('search')::text IS NULL OR p.name ILIKE '%' || sqlc.narg('search')::text || '%')
    AND (sqlc.narg('security_only')::bool IS NULL OR sqlc.narg('security_only')::bool = false OR pu.security_status = 'CONFIRMED')
ORDER BY pu.detected_at DESC
LIMIT $2 OFFSET $3;

-- name: CountPackageUpdatesByVM :one
SELECT count(*)
FROM package_updates pu
JOIN packages p ON p.id = pu.package_id
WHERE pu.vm_id = $1
    AND pu.recommendation_status != 'RESOLVED'
    AND (sqlc.narg('search')::text IS NULL OR p.name ILIKE '%' || sqlc.narg('search')::text || '%')
    AND (sqlc.narg('security_only')::bool IS NULL OR sqlc.narg('security_only')::bool = false OR pu.security_status = 'CONFIRMED');

-- name: SetPackageUpdateStatus :one
-- vm_id is checked alongside id (not just id) as a belt-and-suspenders
-- IDOR guard even though the handler already authorizes the VM itself.
UPDATE package_updates
SET recommendation_status = $3
WHERE id = $1 AND vm_id = $2
RETURNING *;

-- name: GetPackageUpdateByID :one
SELECT * FROM package_updates WHERE id = $1 AND vm_id = $2;
