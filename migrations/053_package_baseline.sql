-- +goose Up
-- package_baseline_at is the cutoff moment used to derive "packages
-- installed since VM onboarding" (distinct from the existing "Externally
-- Installed Packages" pip/npm/gem/snap section, which this does not
-- touch): a package is new-since-onboarding when packages.created_at is
-- later than this timestamp. NULL until the VM's first-ever SUCCESS (not
-- PARTIAL) package discovery run completes -- see
-- services.PackageService.Scan -- or until an admin explicitly resets it
-- via PUT /api/vms/:id/packages/baseline.
ALTER TABLE vms ADD COLUMN package_baseline_at timestamptz;

-- +goose Down
ALTER TABLE vms DROP COLUMN package_baseline_at;
