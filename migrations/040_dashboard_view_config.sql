-- +goose Up
-- Per-Dashboard, admin-configured default view for its Monitoring and Logs
-- tabs -- opaque JSON, same convention as saved_dashboard_views.filters
-- (the backend never interprets the shape; the frontend fully owns it).
-- Before this is set, a Dashboard's Monitoring/Logs tabs show a
-- "Configure" prompt instead of immediately dumping live container/pod
-- data -- see the /dashboards/[id] page's own doc comments for the
-- interaction this backs.
ALTER TABLE dashboards
    ADD COLUMN monitoring_config jsonb,
    ADD COLUMN logs_config jsonb;

-- +goose Down
ALTER TABLE dashboards
    DROP COLUMN monitoring_config,
    DROP COLUMN logs_config;
