-- +goose Up

-- Step 24: the new top-level Docker section (Monitoring + Logs) is
-- deliberately a SEPARATE access model from vm.view/vm.connect -- a
-- member can be granted "view Docker monitoring/logs for everything in
-- Project X or Group Y" without also holding vm.view on those VMs, and
-- conversely holding vm.view grants nothing here. Scope is PROJECT or
-- GROUP only (never a single VM -- that's what direct vm.view/vm.connect
-- grants via the existing Permissions page are for), and dynamic: adding
-- a VM to an already-granted project/group extends automatically, no
-- per-VM re-grant needed. View-only by construction -- there is no
-- "docker.manage" permission here, only docker.monitor/docker.logs.
CREATE TABLE docker_access_grants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_type  text NOT NULL CHECK (scope_type IN ('PROJECT', 'GROUP')),
    project_id  uuid REFERENCES projects(id) ON DELETE CASCADE,
    group_id    uuid REFERENCES groups(id) ON DELETE CASCADE,
    permission  text NOT NULL CHECK (permission IN ('docker.monitor', 'docker.logs')),
    granted_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT docker_access_grants_scope_shape CHECK (
        (scope_type = 'PROJECT' AND project_id IS NOT NULL AND group_id IS NULL) OR
        (scope_type = 'GROUP' AND group_id IS NOT NULL AND project_id IS NULL)
    )
);

CREATE INDEX docker_access_grants_user_idx ON docker_access_grants(user_id);

-- Two PARTIAL unique indexes rather than one UNIQUE(..., project_id,
-- group_id, ...) constraint: Postgres treats NULL as distinct from NULL
-- in a plain UNIQUE constraint (standard SQL), so with project_id/group_id
-- always having one NULL per row (per the CHECK above), a combined
-- constraint would never actually catch a duplicate grant -- every
-- GROUP-scoped row's NULL project_id would compare unequal to every other
-- GROUP-scoped row's NULL project_id, and likewise for PROJECT-scoped
-- rows' NULL group_id. Each partial index only ever indexes rows where
-- its own scope's ID column is guaranteed NOT NULL by the CHECK
-- constraint, so this comparison never arises.
CREATE UNIQUE INDEX docker_access_grants_project_unique
    ON docker_access_grants(user_id, project_id, permission) WHERE scope_type = 'PROJECT';
CREATE UNIQUE INDEX docker_access_grants_group_unique
    ON docker_access_grants(user_id, group_id, permission) WHERE scope_type = 'GROUP';

-- +goose Down
DROP TABLE docker_access_grants;
