-- +goose Up
-- Per-user saved filters for the Docker/Kubernetes Monitoring and Logs
-- dashboards ("save in dashboard name inside monitoring and logs I can
-- able to create") -- a named, reloadable snapshot of whatever filter
-- state the page that owns "feature" defines (search keyword/time range
-- for the Logs pages, project/VM/status filters for the Monitoring
-- pages). filters is opaque JSON to the backend; each page interprets its
-- own shape. Private per-user (never shared) -- the simplest, safest
-- semantics, and matches every other personal-preference concept in this
-- app (e.g. user_preferences).
CREATE TABLE saved_dashboard_views (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    feature     text NOT NULL CHECK (feature IN ('docker_monitor', 'docker_logs', 'k8s_monitor', 'k8s_logs')),
    name        text NOT NULL,
    filters     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT saved_dashboard_views_user_feature_name_unique UNIQUE (user_id, feature, name)
);

CREATE INDEX saved_dashboard_views_user_feature_idx ON saved_dashboard_views(user_id, feature);

CREATE TRIGGER saved_dashboard_views_set_updated_at
    BEFORE UPDATE ON saved_dashboard_views
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE saved_dashboard_views;
