-- +goose Up
-- Widens packages.package_manager to also allow the externally-installed
-- ecosystems (outside apt/dnf/yum) that ExternalPackageScanner detects:
-- PIP/NPM/GEM/SNAP. These are list-only (no available_version/update
-- checking -- see package_updates, never populated for these types) and
-- get their own "Externally Installed Packages" section, kept out of the
-- OS-package queries below via an explicit package_manager allowlist.
ALTER TABLE packages DROP CONSTRAINT packages_package_manager_check;
ALTER TABLE packages ADD CONSTRAINT packages_package_manager_check
    CHECK (package_manager IN ('APT', 'DPKG', 'DNF', 'YUM', 'RPM', 'PIP', 'NPM', 'GEM', 'SNAP'));

-- +goose Down
ALTER TABLE packages DROP CONSTRAINT packages_package_manager_check;
ALTER TABLE packages ADD CONSTRAINT packages_package_manager_check
    CHECK (package_manager IN ('APT', 'DPKG', 'DNF', 'YUM', 'RPM'));
