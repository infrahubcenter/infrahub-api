-- +goose Up
-- Docker Host containers had no persisted log history at all (see
-- migration 055's own doc comment: ListContainers is a pure live call to
-- the connected agent, no DB row). That made "Past Logs" for a Docker
-- Host silently depend on the agent being connected *right now*, and
-- bounded to whatever short window the agent's own `docker logs --since`
-- happened to still hold -- unlike VM-hosted Docker containers
-- (docker_container_log_lines, migration 033) and Kubernetes pods
-- (k8s_pod_log_lines, migration 033), both of which already have a
-- periodic background capture giving up to *_LOG_RETENTION_DAYS of
-- searchable history regardless of live connection status. This closes
-- that gap the same way, keyed off the one persistent per-container
-- identity row a Docker Host already has: docker_host_container_sightings.
ALTER TABLE docker_host_container_sightings ADD COLUMN last_log_captured_at timestamptz;

CREATE TABLE docker_host_container_log_lines (
    id                                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    docker_host_container_sighting_id   uuid NOT NULL REFERENCES docker_host_container_sightings(id) ON DELETE CASCADE,
    logged_at                           timestamptz NOT NULL,
    line                                text NOT NULL,
    created_at                          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX docker_host_container_log_lines_sighting_logged_idx
    ON docker_host_container_log_lines(docker_host_container_sighting_id, logged_at);

-- +goose Down
DROP TABLE docker_host_container_log_lines;
ALTER TABLE docker_host_container_sightings DROP COLUMN last_log_captured_at;
