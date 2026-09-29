-- +goose Up
-- Widens docker_access_grants' scope_type (031/045) to add FOLDER (every
-- Dashboard filed under one monitoring_folders row) and DASHBOARD (exactly
-- one monitoring_dashboards row) scopes -- lets an admin grant "every
-- dashboard in Folder X" or "only Dashboard Y", independent of which
-- VM/cluster each dashboard happens to bind. Same partial-unique-index
-- discipline as 045_docker_access_resource_scope.sql: Postgres treats NULL
-- as distinct from NULL in a plain composite UNIQUE, so each scope needs
-- its own partial index rather than one combined constraint.
ALTER TABLE docker_access_grants
    ADD COLUMN monitoring_folder_id uuid REFERENCES monitoring_folders(id) ON DELETE CASCADE,
    ADD COLUMN monitoring_dashboard_id uuid REFERENCES monitoring_dashboards(id) ON DELETE CASCADE;

ALTER TABLE docker_access_grants DROP CONSTRAINT docker_access_grants_scope_type_check;
ALTER TABLE docker_access_grants ADD CONSTRAINT docker_access_grants_scope_type_check
    CHECK (scope_type IN ('WORKSPACE', 'RESOURCE', 'FOLDER', 'DASHBOARD'));

-- Replace the 2-branch scope-shape CHECK (045) with a 4-branch version:
-- exactly one of workspace_id/resource_id/monitoring_folder_id/
-- monitoring_dashboard_id is set, matching scope_type, and the other three
-- are NULL.
ALTER TABLE docker_access_grants DROP CONSTRAINT docker_access_grants_scope_shape;
ALTER TABLE docker_access_grants ADD CONSTRAINT docker_access_grants_scope_shape CHECK (
    (scope_type = 'WORKSPACE' AND workspace_id IS NOT NULL AND resource_id IS NULL AND monitoring_folder_id IS NULL AND monitoring_dashboard_id IS NULL) OR
    (scope_type = 'RESOURCE' AND resource_id IS NOT NULL AND workspace_id IS NULL AND monitoring_folder_id IS NULL AND monitoring_dashboard_id IS NULL) OR
    (scope_type = 'FOLDER' AND monitoring_folder_id IS NOT NULL AND workspace_id IS NULL AND resource_id IS NULL AND monitoring_dashboard_id IS NULL) OR
    (scope_type = 'DASHBOARD' AND monitoring_dashboard_id IS NOT NULL AND workspace_id IS NULL AND resource_id IS NULL AND monitoring_folder_id IS NULL)
);

CREATE UNIQUE INDEX docker_access_grants_folder_unique
    ON docker_access_grants(user_id, monitoring_folder_id, permission) WHERE scope_type = 'FOLDER';
CREATE UNIQUE INDEX docker_access_grants_dashboard_unique
    ON docker_access_grants(user_id, monitoring_dashboard_id, permission) WHERE scope_type = 'DASHBOARD';

-- +goose Down
DROP INDEX docker_access_grants_dashboard_unique;
DROP INDEX docker_access_grants_folder_unique;
DELETE FROM docker_access_grants WHERE scope_type IN ('FOLDER', 'DASHBOARD');
ALTER TABLE docker_access_grants DROP CONSTRAINT docker_access_grants_scope_shape;
ALTER TABLE docker_access_grants ADD CONSTRAINT docker_access_grants_scope_shape CHECK (
    (scope_type = 'WORKSPACE' AND workspace_id IS NOT NULL AND resource_id IS NULL) OR
    (scope_type = 'RESOURCE' AND resource_id IS NOT NULL)
);
ALTER TABLE docker_access_grants DROP CONSTRAINT docker_access_grants_scope_type_check;
ALTER TABLE docker_access_grants ADD CONSTRAINT docker_access_grants_scope_type_check CHECK (scope_type IN ('WORKSPACE', 'RESOURCE'));
ALTER TABLE docker_access_grants DROP COLUMN monitoring_dashboard_id;
ALTER TABLE docker_access_grants DROP COLUMN monitoring_folder_id;
