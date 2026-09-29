-- +goose Up
-- Adds a per-resource (one specific VM, for docker.monitor/docker.logs;
-- one specific K8s cluster, for k8s.monitor/k8s.logs) grant scope
-- alongside the existing workspace-wide scope -- reapplies the exact
-- same discriminator+partial-unique-index shape this table used for
-- PROJECT/GROUP scope before the Workspace migration collapsed it to
-- workspace-only (see migrations/031_docker_access_grants.sql): Postgres
-- treats NULL as distinct in a plain composite UNIQUE, so a nullable
-- scope column needs partial indexes, not a combined constraint.
ALTER TABLE docker_access_grants
    ADD COLUMN scope_type text NOT NULL DEFAULT 'WORKSPACE' CHECK (scope_type IN ('WORKSPACE', 'RESOURCE')),
    ADD COLUMN resource_id uuid REFERENCES resources(id) ON DELETE CASCADE;

ALTER TABLE docker_access_grants ALTER COLUMN workspace_id DROP NOT NULL;

ALTER TABLE docker_access_grants ADD CONSTRAINT docker_access_grants_scope_shape CHECK (
    (scope_type = 'WORKSPACE' AND workspace_id IS NOT NULL AND resource_id IS NULL) OR
    (scope_type = 'RESOURCE' AND resource_id IS NOT NULL)
);

DROP INDEX docker_access_grants_workspace_unique;
CREATE UNIQUE INDEX docker_access_grants_workspace_unique
    ON docker_access_grants(user_id, workspace_id, permission) WHERE scope_type = 'WORKSPACE';
CREATE UNIQUE INDEX docker_access_grants_resource_unique
    ON docker_access_grants(user_id, resource_id, permission) WHERE scope_type = 'RESOURCE';

-- +goose Down
DROP INDEX docker_access_grants_resource_unique;
DROP INDEX docker_access_grants_workspace_unique;
DELETE FROM docker_access_grants WHERE scope_type = 'RESOURCE';
ALTER TABLE docker_access_grants DROP CONSTRAINT docker_access_grants_scope_shape;
ALTER TABLE docker_access_grants ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE docker_access_grants DROP COLUMN resource_id;
ALTER TABLE docker_access_grants DROP COLUMN scope_type;
CREATE UNIQUE INDEX docker_access_grants_workspace_unique ON docker_access_grants(user_id, workspace_id, permission);
