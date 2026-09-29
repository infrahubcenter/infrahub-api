-- +goose Up
-- Adds a "Folder" grouping level above saved_dashboard_views ("Folder >
-- Dashboard", Grafana-style) for the Docker/Kubernetes Monitoring and Logs
-- pages -- a dashboard can live inside a folder, or stand alone
-- (folder_id NULL) when created straight from the top level. Private
-- per-user, same semantics as saved_dashboard_views itself (never shared).
CREATE TABLE saved_view_folders (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    feature     text NOT NULL CHECK (feature IN ('docker_monitor', 'docker_logs', 'k8s_monitor', 'k8s_logs')),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT saved_view_folders_user_feature_name_unique UNIQUE (user_id, feature, name)
);

CREATE INDEX saved_view_folders_user_feature_idx ON saved_view_folders(user_id, feature);

ALTER TABLE saved_dashboard_views
    ADD COLUMN folder_id uuid REFERENCES saved_view_folders(id) ON DELETE CASCADE;

CREATE INDEX saved_dashboard_views_folder_idx ON saved_dashboard_views(folder_id);

-- The pre-existing (user_id, feature, name) uniqueness stays as-is on
-- purpose: a dashboard name is still unique per user+feature regardless of
-- which folder (or no folder) it sits in, so "re-saving a view replaces
-- it" keeps working exactly as before even after a dashboard is moved
-- between folders.

-- +goose Down
ALTER TABLE saved_dashboard_views DROP COLUMN folder_id;
DROP TABLE saved_view_folders;
