-- +goose Up
-- installed_at is the package manager's own record of when a package was
-- actually installed on the VM (dpkg .list file mtime for APT/DPKG,
-- %{INSTALLTIME} for RPM/DNF/YUM) -- distinct from created_at, which only
-- records when OUR scanner first discovered/inserted the row. Without this
-- column, "Installed Since Onboarding" (packages.created_at >
-- vms.package_baseline_at) is wrong for every VM whose baseline stamps on
-- its first scan: anything already installed on the box before that first
-- scan ran (e.g. docker/kubectl/microk8s installed manually right after
-- onboarding, before anyone ever clicked "Scan") gets created_at from that
-- same first scan and is incorrectly bucketed as "pre-existing" forever.
-- NULL when the package manager can't report a real install time (older
-- rpm, or the dpkg info-file stat failed) -- callers fall back to
-- created_at in that case, matching the pre-existing approximation.
ALTER TABLE packages ADD COLUMN installed_at timestamptz;

-- One-time correction for VMs already onboarded before this migration:
-- SetVMPackageBaselineIfUnset used to stamp package_baseline_at = now()
-- at whatever moment the *first scan* happened to run, which is often
-- well after the VM was actually registered -- anything a real user
-- manually installed in that gap (the exact "installed docker/kubectl
-- right after creating the VM, before ever clicking Scan" complaint)
-- got permanently misclassified as pre-existing, since the baseline
-- landed after it. Pulling every such baseline back to the VM's own
-- created_at is always safe (it only ever makes MORE packages qualify
-- as "new", never fewer) and correctly re-includes exactly that gap.
UPDATE vms SET package_baseline_at = created_at
WHERE package_baseline_at IS NOT NULL AND package_baseline_at > created_at;

-- +goose Down
ALTER TABLE packages DROP COLUMN installed_at;
-- The baseline backfill above is not reversed -- it only ever moved a
-- timestamp earlier, and re-widening "what counts as new" is not a
-- destructive change worth a down-migration round-trip.
