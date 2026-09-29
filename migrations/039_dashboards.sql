-- +goose Up
-- Folder > Dashboard: an org entity under Project > Group that binds
-- exactly one VM (Docker) or one K8sCluster (Kubernetes) resource to a
-- fixed Monitoring/Logs/Alerts tab set (see the Dashboard-scoped /dashboards
-- pages). Distinct from app_folders (036, admin-owned groups of individual
-- containers/pods, directly grantable per-user) and saved_view_folders/
-- saved_dashboard_views (034/038, private per-user filter snapshots, no
-- resource binding, no project/group scoping, and the frontend
-- DashboardFolderNav component) -- named dashboard_folders/dashboards
-- specifically so neither collides with those two unrelated features.
--
-- Access control is deliberately NOT a new grant table: a Dashboard is
-- visible to whoever already holds docker.monitor/docker.logs or
-- k8s.monitor/k8s.logs on its Project/Group via the existing
-- docker_access_grants system (see AuthorizationService in the Go
-- service layer) -- Dashboards organize what's already visible rather
-- than introducing a second permission surface.
CREATE TABLE dashboard_folders (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- Nullable, mirroring resources.group_id exactly: a folder can sit
    -- directly under a Project with no Group.
    group_id    uuid REFERENCES groups(id) ON DELETE CASCADE,
    name        text NOT NULL,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX dashboard_folders_project_idx ON dashboard_folders(project_id);
CREATE INDEX dashboard_folders_group_idx ON dashboard_folders(group_id);

CREATE TRIGGER dashboard_folders_set_updated_at
    BEFORE UPDATE ON dashboard_folders
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Reuses check_resource_group_project() from 004_resources.sql as-is --
-- it only ever reads NEW.group_id/NEW.project_id and the groups table, so
-- it works unmodified on any table with those two columns.
CREATE TRIGGER dashboard_folders_check_group_project
    BEFORE INSERT OR UPDATE ON dashboard_folders
    FOR EACH ROW EXECUTE FUNCTION check_resource_group_project();

CREATE TABLE dashboards (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Nullable ("or before folder also give create dashboard option") --
    -- a Dashboard can be created standalone straight under a Group/
    -- Project, or filed into a Folder, mirroring saved_view_folders'
    -- own nullable folder_id decision.
    dashboard_folder_id     uuid REFERENCES dashboard_folders(id) ON DELETE CASCADE,
    -- Always set from the bound resource's own resources.project_id/
    -- group_id at creation time (service layer), never independently
    -- admin-chosen -- keeps nav placement and docker_access_grants'
    -- actual authorization check from ever disagreeing.
    project_id              uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_id                uuid REFERENCES groups(id) ON DELETE CASCADE,
    name                    text NOT NULL,
    kind                    text NOT NULL CHECK (kind IN ('DOCKER', 'K8S')),
    -- Bound at creation time, immutable after (Phase 0: rebinding is a
    -- delete+recreate, not a PATCH -- keeps "picked once, not re-picked
    -- per visit" unambiguous, and gives alert_rules.resource_id a fixed
    -- target). Exactly one of these two is set, matching kind.
    vm_resource_id          uuid REFERENCES resources(id) ON DELETE CASCADE,
    k8s_cluster_resource_id uuid REFERENCES resources(id) ON DELETE CASCADE,
    created_by              uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dashboards_binding_matches_kind CHECK (
        (kind = 'DOCKER' AND vm_resource_id IS NOT NULL AND k8s_cluster_resource_id IS NULL) OR
        (kind = 'K8S' AND k8s_cluster_resource_id IS NOT NULL AND vm_resource_id IS NULL)
    )
);

CREATE INDEX dashboards_folder_idx ON dashboards(dashboard_folder_id);
CREATE INDEX dashboards_project_idx ON dashboards(project_id);
CREATE INDEX dashboards_group_idx ON dashboards(group_id);
CREATE INDEX dashboards_vm_resource_idx ON dashboards(vm_resource_id) WHERE vm_resource_id IS NOT NULL;
CREATE INDEX dashboards_k8s_cluster_resource_idx ON dashboards(k8s_cluster_resource_id) WHERE k8s_cluster_resource_id IS NOT NULL;
-- Deliberately no uniqueness constraint on the resource-id columns:
-- multiple Dashboards (e.g. in different Folders) may point at the same
-- VM/cluster -- "exactly one VM per Dashboard" is a Dashboard->resource
-- constraint, not the reverse.

CREATE TRIGGER dashboards_set_updated_at
    BEFORE UPDATE ON dashboards
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER dashboards_check_group_project
    BEFORE INSERT OR UPDATE ON dashboards
    FOR EACH ROW EXECUTE FUNCTION check_resource_group_project();

-- +goose Down
DROP TABLE dashboards;
DROP TABLE dashboard_folders;
