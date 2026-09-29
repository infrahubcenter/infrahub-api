-- +goose Up
-- Custom "App Name" labels (Admin-settable, shown in Monitor/Logs instead
-- of the raw container/pod name wherever set) -- purely cosmetic, never
-- touched by a discovery/capture upsert.
ALTER TABLE docker_containers ADD COLUMN display_name text;
ALTER TABLE k8s_pods ADD COLUMN display_name text;

-- Background log-capture cursor: how far a periodic, bounded `docker logs
-- --since <cursor>` / GetLogs(SinceTime) pull has already advanced for
-- this container/pod -- distinct from the live-tail WebSocket (which never
-- persists anything), this is what makes searchable history possible.
ALTER TABLE docker_containers ADD COLUMN last_log_captured_at timestamptz;
ALTER TABLE k8s_pods ADD COLUMN last_log_captured_at timestamptz;

CREATE TABLE docker_container_log_lines (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    docker_container_id  uuid NOT NULL REFERENCES docker_containers(id) ON DELETE CASCADE,
    logged_at            timestamptz NOT NULL,
    line                 text NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX docker_container_log_lines_container_logged_idx
    ON docker_container_log_lines(docker_container_id, logged_at);

CREATE TABLE k8s_pod_log_lines (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    k8s_pod_id   uuid NOT NULL REFERENCES k8s_pods(id) ON DELETE CASCADE,
    logged_at    timestamptz NOT NULL,
    line         text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX k8s_pod_log_lines_pod_logged_idx
    ON k8s_pod_log_lines(k8s_pod_id, logged_at);

-- +goose Down
DROP TABLE k8s_pod_log_lines;
DROP TABLE docker_container_log_lines;
ALTER TABLE k8s_pods DROP COLUMN last_log_captured_at;
ALTER TABLE docker_containers DROP COLUMN last_log_captured_at;
ALTER TABLE k8s_pods DROP COLUMN display_name;
ALTER TABLE docker_containers DROP COLUMN display_name;
