-- +goose Up
-- ============================================================
-- Workspace migration: replaces the two-tier Project -> Group
-- hierarchy with one flat Workspace tier everywhere. Group is
-- already the real access-control primitive in this codebase --
-- group_members is what AuthorizationService actually consults
-- for group-derived access; project_members is defined but never
-- queried anywhere (see authorization.go's own "Project
-- membership never grants VM access on its own" comment). This
-- migration therefore renames groups/group_members to
-- workspaces/workspace_members IN PLACE (same ids, same rows,
-- same memberships -- nothing is recreated), backfills every
-- resource/grant/folder/dashboard that was scoped only by Project
-- (never grouped) into a new catch-all Workspace per Project so
-- nothing is left unscoped, then drops project_id everywhere and
-- finally the projects/project_members tables themselves.
--
-- Also drops dashboard_folders/dashboards (migration 039): they
-- were retired in code two passes ago (superseded by
-- monitoring_folders/monitoring_dashboards, migration 042) but
-- deliberately left in the database at the time to avoid an
-- unforced destructive migration. They still hold live FK
-- references to projects/groups, which blocks dropping those
-- tables below -- since they're confirmed dead (zero live code
-- references), this is the point where that deferred cleanup
-- finally happens.
-- ============================================================

-- 1. Promote groups -> workspaces in place. workspaces.project_id
-- is deliberately kept for now -- steps 4-7 below still need it to
-- resolve "which workspace(s) cover this project" before it's
-- dropped for good in step 11.
ALTER TABLE groups RENAME TO workspaces;
ALTER TABLE workspaces DROP CONSTRAINT groups_project_name_unique;
ALTER TRIGGER groups_set_updated_at ON workspaces RENAME TO workspaces_set_updated_at;

ALTER TABLE group_members RENAME TO workspace_members;
ALTER TABLE workspace_members RENAME COLUMN group_id TO workspace_id;
ALTER INDEX group_members_user_id_idx RENAME TO workspace_members_user_id_idx;

-- 1b. check_resource_group_project()'s body hardcodes `FROM groups`
-- (it's plain text resolved at execution time, not updated by the
-- table rename above) -- any INSERT/UPDATE on a table it's attached
-- to would now fail with "relation groups does not exist". It has
-- to go before the backfill UPDATEs below touch resources/
-- monitoring_folders/monitoring_dashboards, and there is no
-- cross-tier relationship left to validate anyway once resources
-- point at a flat workspace_id. CASCADE drops its trigger
-- attachments (resources, dashboard_folders, dashboards,
-- monitoring_folders, monitoring_dashboards) along with it.
DROP FUNCTION check_resource_group_project() CASCADE;

-- 2. One new catch-all Workspace per Project that has at least one
-- ungrouped resource/folder/dashboard (group_id IS NULL) -- named
-- after that Project, so an admin can still recognize where it
-- came from. Captures project_id -> new workspace_id for steps 4-7.
CREATE TEMP TABLE workspace_migration_catchall AS
SELECT p.id AS project_id, gen_random_uuid() AS workspace_id, p.name, p.description, p.is_active, p.created_at
FROM projects p
WHERE EXISTS (
    SELECT 1 FROM resources r WHERE r.project_id = p.id AND r.group_id IS NULL
) OR EXISTS (
    SELECT 1 FROM monitoring_folders f WHERE f.project_id = p.id AND f.group_id IS NULL
) OR EXISTS (
    SELECT 1 FROM monitoring_dashboards d WHERE d.project_id = p.id AND d.group_id IS NULL
);

INSERT INTO workspaces (id, project_id, name, description, is_active, created_at, updated_at)
SELECT workspace_id, project_id, name, description, is_active, created_at, now() FROM workspace_migration_catchall;

-- 3. Backfill: a resource keeps its existing group_id if it has
-- one; an ungrouped one picks up its project's new catch-all
-- workspace.
UPDATE resources r SET group_id = c.workspace_id
FROM workspace_migration_catchall c WHERE r.project_id = c.project_id AND r.group_id IS NULL;

-- 4. Every resource now has a Workspace -- promote the column.
ALTER TABLE resources RENAME COLUMN group_id TO workspace_id;
ALTER TABLE resources ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE resources DROP COLUMN project_id;
ALTER INDEX resources_group_id_idx RENAME TO resources_workspace_id_idx;

-- 5. docker_access_grants: fan every PROJECT-scoped grant out to
-- every Workspace now covering that project (its pre-existing
-- Groups, via workspaces.project_id which is still present, plus
-- the new catch-all from step 2 if one exists -- both already live
-- in `workspaces` by this point), then collapse the
-- scope_type/project_id/group_id three-column shape down to one
-- workspace_id. ON CONFLICT DO NOTHING because a user can already
-- hold the equivalent GROUP-scoped grant directly -- the fan-out
-- would otherwise try to insert an exact duplicate of it.
INSERT INTO docker_access_grants (user_id, scope_type, group_id, permission, granted_by, created_at)
SELECT DISTINCT g.user_id, 'GROUP', w.id, g.permission, g.granted_by, g.created_at
FROM docker_access_grants g
JOIN workspaces w ON w.project_id = g.project_id
WHERE g.scope_type = 'PROJECT'
ON CONFLICT (user_id, group_id, permission) WHERE scope_type = 'GROUP' DO NOTHING;

DELETE FROM docker_access_grants WHERE scope_type = 'PROJECT';

ALTER TABLE docker_access_grants DROP CONSTRAINT docker_access_grants_scope_shape;
DROP INDEX docker_access_grants_project_unique;
DROP INDEX docker_access_grants_group_unique;
ALTER TABLE docker_access_grants DROP COLUMN scope_type;
ALTER TABLE docker_access_grants DROP COLUMN project_id;
ALTER TABLE docker_access_grants RENAME COLUMN group_id TO workspace_id;
ALTER TABLE docker_access_grants ALTER COLUMN workspace_id SET NOT NULL;
CREATE UNIQUE INDEX docker_access_grants_workspace_unique ON docker_access_grants(user_id, workspace_id, permission);

-- 6. monitoring_folders (same shape as resources).
UPDATE monitoring_folders f SET group_id = c.workspace_id
FROM workspace_migration_catchall c WHERE f.project_id = c.project_id AND f.group_id IS NULL;
ALTER TABLE monitoring_folders RENAME COLUMN group_id TO workspace_id;
ALTER TABLE monitoring_folders ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE monitoring_folders DROP COLUMN project_id;
ALTER INDEX monitoring_folders_group_idx RENAME TO monitoring_folders_workspace_idx;

-- 7. monitoring_dashboards (same shape as resources).
UPDATE monitoring_dashboards d SET group_id = c.workspace_id
FROM workspace_migration_catchall c WHERE d.project_id = c.project_id AND d.group_id IS NULL;
ALTER TABLE monitoring_dashboards RENAME COLUMN group_id TO workspace_id;
ALTER TABLE monitoring_dashboards ALTER COLUMN workspace_id SET NOT NULL;
ALTER TABLE monitoring_dashboards DROP COLUMN project_id;
ALTER INDEX monitoring_dashboards_group_idx RENAME TO monitoring_dashboards_workspace_idx;

-- 8. alerts: derive workspace_id from the (already-migrated,
-- step 4) owning resource directly -- more reliable than
-- re-deriving from alerts' own old project/group columns
-- independently, and every alert always has a resource_id.
-- Stays nullable (denormalized, display/filter-only column, never
-- trusted for authorization -- same role group_id already had).
UPDATE alerts a SET group_id = r.workspace_id FROM resources r WHERE a.resource_id = r.id;
ALTER TABLE alerts DROP COLUMN project_id;
ALTER TABLE alerts RENAME COLUMN group_id TO workspace_id;
ALTER INDEX alerts_group_status_idx RENAME TO alerts_workspace_status_idx;

-- 9. Drop dashboard_folders/dashboards (039) -- dead code, and
-- blocks dropping projects/groups below via their FKs otherwise.
DROP TABLE dashboards;
DROP TABLE dashboard_folders;

-- 10. Nothing reads workspaces.project_id anymore -- drop it, then
-- the temp mapping table, then the two tables nothing references
-- at all now.
ALTER TABLE workspaces DROP COLUMN project_id;
DROP TABLE workspace_migration_catchall;
DROP TABLE project_members;
DROP TABLE projects;

-- +goose Down
-- This migration permanently reshapes data (Project-only resources
-- are absorbed into new catch-all Workspaces indistinguishable
-- from real former Groups; docker_access_grants' PROJECT-scoped
-- rows are fanned out and de-duplicated against existing GROUP
-- rows via ON CONFLICT DO NOTHING, which can discard rows outright;
-- dashboard_folders/dashboards are dropped entirely). A true
-- data-preserving reverse migration is not possible. This Down
-- restores the pre-043 table SHAPES only (empty projects/
-- project_members, project_id columns restored as nullable with no
-- backfill) so `goose down` leaves a structurally valid schema
-- rather than failing outright -- it is not a safe way to undo
-- this migration's data changes.
CREATE TABLE projects (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    description text,
    is_active   boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT projects_name_unique UNIQUE (name)
);
CREATE TRIGGER projects_set_updated_at BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE project_members (
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);
CREATE INDEX project_members_user_id_idx ON project_members(user_id);

ALTER TABLE workspaces ADD COLUMN project_id uuid REFERENCES projects(id) ON DELETE CASCADE;

-- +goose StatementBegin
CREATE FUNCTION check_resource_group_project() RETURNS trigger AS $$
DECLARE
    group_project_id uuid;
BEGIN
    IF NEW.group_id IS NOT NULL THEN
        SELECT project_id INTO group_project_id FROM workspaces WHERE id = NEW.group_id;
        IF group_project_id IS NULL OR group_project_id != NEW.project_id THEN
            RAISE EXCEPTION 'resource group_id % does not belong to project_id %', NEW.group_id, NEW.project_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

ALTER TABLE resources ADD COLUMN project_id uuid REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE resources RENAME COLUMN workspace_id TO group_id;
ALTER TABLE resources ALTER COLUMN group_id DROP NOT NULL;
CREATE TRIGGER resources_check_group_project BEFORE INSERT OR UPDATE ON resources FOR EACH ROW EXECUTE FUNCTION check_resource_group_project();

ALTER TABLE monitoring_folders ADD COLUMN project_id uuid REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE monitoring_folders RENAME COLUMN workspace_id TO group_id;
ALTER TABLE monitoring_folders ALTER COLUMN group_id DROP NOT NULL;

ALTER TABLE monitoring_dashboards ADD COLUMN project_id uuid REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE monitoring_dashboards RENAME COLUMN workspace_id TO group_id;
ALTER TABLE monitoring_dashboards ALTER COLUMN group_id DROP NOT NULL;

ALTER TABLE alerts ADD COLUMN project_id uuid REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE alerts RENAME COLUMN workspace_id TO group_id;

ALTER TABLE docker_access_grants ADD COLUMN scope_type text;
ALTER TABLE docker_access_grants ADD COLUMN project_id uuid REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE docker_access_grants RENAME COLUMN workspace_id TO group_id;
UPDATE docker_access_grants SET scope_type = 'GROUP';
ALTER TABLE docker_access_grants ALTER COLUMN scope_type SET NOT NULL;
DROP INDEX docker_access_grants_workspace_unique;
CREATE UNIQUE INDEX docker_access_grants_group_unique ON docker_access_grants(user_id, group_id, permission) WHERE scope_type = 'GROUP';

ALTER TABLE workspace_members RENAME COLUMN workspace_id TO group_id;
ALTER TABLE workspace_members RENAME TO group_members;
ALTER TABLE workspaces RENAME TO groups;
ALTER TABLE groups ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE groups ADD CONSTRAINT groups_project_name_unique UNIQUE (project_id, name);
