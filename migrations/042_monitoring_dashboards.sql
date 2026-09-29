-- +goose Up
-- Monitoring/Logs Folder > Dashboard: the new org entity replacing the
-- retired dashboard_folders/dashboards (039/040), which bound exactly one
-- Dashboard to exactly one VM/K8sCluster with a single combined
-- Monitoring/Logs/Alerts tab set. This model instead backs FOUR
-- independent trees -- Monitoring>Docker, Monitoring>Kubernetes,
-- Logs>Docker, Logs>Kubernetes -- discriminated by `feature`, where one
-- Dashboard still binds to exactly one VM or K8sCluster but scopes down
-- to a MULTI-resource selection on it (several containers, or several
-- namespaces/resource types), configured via a 4-step wizard (Basic/
-- Resources/Metrics/Review) rather than a single "enable" toggle.
--
-- Distinct from app_folders (036, admin-owned groups of individual
-- containers/pods, directly grantable per-user) and saved_view_folders/
-- saved_dashboard_views (034/038, private per-user filter snapshots, no
-- resource binding, no project/group scoping) -- same naming rationale
-- 039's own header comment gave for dashboard_folders/dashboards.
--
-- Access control is, again, deliberately NOT a new grant table: a
-- Dashboard is visible to whoever already holds docker.monitor/
-- docker.logs or k8s.monitor/k8s.logs on its Project/Group via the
-- existing docker_access_grants system.
CREATE TABLE monitoring_folders (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    feature     text NOT NULL CHECK (feature IN ('DOCKER_MONITORING', 'K8S_MONITORING', 'DOCKER_LOGS', 'K8S_LOGS')),
    project_id  uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_id    uuid REFERENCES groups(id) ON DELETE CASCADE,
    name        text NOT NULL,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX monitoring_folders_feature_idx ON monitoring_folders(feature);
CREATE INDEX monitoring_folders_project_idx ON monitoring_folders(project_id);
CREATE INDEX monitoring_folders_group_idx ON monitoring_folders(group_id);

CREATE TRIGGER monitoring_folders_set_updated_at
    BEFORE UPDATE ON monitoring_folders
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER monitoring_folders_check_group_project
    BEFORE INSERT OR UPDATE ON monitoring_folders
    FOR EACH ROW EXECUTE FUNCTION check_resource_group_project();

CREATE TABLE monitoring_dashboards (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Nullable, same rationale as dashboards.dashboard_folder_id: a
    -- Dashboard may be created standalone before any Folder exists.
    monitoring_folder_id     uuid REFERENCES monitoring_folders(id) ON DELETE CASCADE,
    feature                  text NOT NULL CHECK (feature IN ('DOCKER_MONITORING', 'K8S_MONITORING', 'DOCKER_LOGS', 'K8S_LOGS')),
    -- Always derived from the bound resource's own resources.project_id/
    -- group_id at creation time (service layer), never independently
    -- admin-chosen -- keeps nav placement and docker_access_grants'
    -- actual authorization check from ever disagreeing (mirrors 039).
    project_id               uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_id                 uuid REFERENCES groups(id) ON DELETE CASCADE,
    name                     text NOT NULL,
    description              text,
    -- Bound at creation time, immutable after (same rebind-is-delete-and-
    -- recreate discipline as 039). Exactly one of these two is set,
    -- matching feature's DOCKER/K8S half. A Monitoring dashboard and a
    -- Logs dashboard for the same VM/cluster are separate rows by design
    -- -- they live in different trees and are configured independently.
    vm_resource_id           uuid REFERENCES resources(id) ON DELETE CASCADE,
    k8s_cluster_resource_id  uuid REFERENCES resources(id) ON DELETE CASCADE,
    -- How often the Overview page's live charts/tables should refresh --
    -- the wizard's own Basic-step control (mockup: "Refresh: 30s").
    refresh_interval_seconds integer NOT NULL DEFAULT 30 CHECK (refresh_interval_seconds > 0),
    created_by               uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT monitoring_dashboards_binding_matches_feature CHECK (
        (feature IN ('DOCKER_MONITORING', 'DOCKER_LOGS') AND vm_resource_id IS NOT NULL AND k8s_cluster_resource_id IS NULL) OR
        (feature IN ('K8S_MONITORING', 'K8S_LOGS') AND k8s_cluster_resource_id IS NOT NULL AND vm_resource_id IS NULL)
    )
);

CREATE INDEX monitoring_dashboards_folder_idx ON monitoring_dashboards(monitoring_folder_id);
CREATE INDEX monitoring_dashboards_feature_idx ON monitoring_dashboards(feature);
CREATE INDEX monitoring_dashboards_project_idx ON monitoring_dashboards(project_id);
CREATE INDEX monitoring_dashboards_group_idx ON monitoring_dashboards(group_id);
CREATE INDEX monitoring_dashboards_vm_resource_idx ON monitoring_dashboards(vm_resource_id) WHERE vm_resource_id IS NOT NULL;
CREATE INDEX monitoring_dashboards_k8s_cluster_resource_idx ON monitoring_dashboards(k8s_cluster_resource_id) WHERE k8s_cluster_resource_id IS NOT NULL;
-- Deliberately no uniqueness on the resource-id columns, same rationale
-- as 039: multiple Dashboards may point at the same VM/cluster.

CREATE TRIGGER monitoring_dashboards_set_updated_at
    BEFORE UPDATE ON monitoring_dashboards
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER monitoring_dashboards_check_group_project
    BEFORE INSERT OR UPDATE ON monitoring_dashboards
    FOR EACH ROW EXECUTE FUNCTION check_resource_group_project();

-- One row per selection made in the wizard's "Resources" step -- a
-- DOCKER_MONITORING/DOCKER_LOGS dashboard holds CONTAINER rows (value =
-- container_id); a K8S_MONITORING/K8S_LOGS dashboard holds NAMESPACE rows
-- (value = namespace name) and/or RESOURCE_TYPE rows (value = e.g.
-- "PODS", "DEPLOYMENTS", "SERVICES") for the checked resource-kind boxes.
-- filter_type-vs-feature consistency (e.g. no CONTAINER row on a K8S
-- dashboard) is validated in Go at the service layer, not a DB
-- constraint -- this table has no independent feature column to check
-- against without a second join/trigger, and every write already goes
-- through the one service method that owns this invariant.
CREATE TABLE monitoring_dashboard_filters (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    monitoring_dashboard_id uuid NOT NULL REFERENCES monitoring_dashboards(id) ON DELETE CASCADE,
    filter_type            text NOT NULL CHECK (filter_type IN ('CONTAINER', 'NAMESPACE', 'RESOURCE_TYPE')),
    value                  text NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX monitoring_dashboard_filters_dashboard_idx ON monitoring_dashboard_filters(monitoring_dashboard_id);

-- One row per widget selected in the wizard's "Metrics" step -- controls
-- which stat cards/charts the Overview page renders and in what order.
-- Never populated for a *_LOGS dashboard (its Configure wizard skips the
-- Metrics/Review steps entirely -- a log viewer has no widget picks).
CREATE TABLE monitoring_dashboard_widgets (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    monitoring_dashboard_id uuid NOT NULL REFERENCES monitoring_dashboards(id) ON DELETE CASCADE,
    widget_type             text NOT NULL CHECK (widget_type IN (
        'CPU_CHART', 'MEMORY_CHART', 'NETWORK_CHART', 'STORAGE_CHART',
        'CONTAINER_COUNT', 'POD_COUNT', 'RESTART_COUNT', 'LATENCY',
        'LOGS', 'ERRORS', 'RESOURCE_STATUS'
    )),
    position                integer NOT NULL DEFAULT 0,
    created_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX monitoring_dashboard_widgets_dashboard_idx ON monitoring_dashboard_widgets(monitoring_dashboard_id);

-- +goose Down
DROP TABLE monitoring_dashboard_widgets;
DROP TABLE monitoring_dashboard_filters;
DROP TABLE monitoring_dashboards;
DROP TABLE monitoring_folders;
