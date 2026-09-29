-- +goose Up
-- ListContainers for a Docker Host (docker_host.go) is a pure live call to
-- the connected agent -- no DB row involved, by design, so a container's
-- own reported timestamps (created_at_remote/started_at_remote) are all
-- Docker's, never InfraHub's. This table is the one thing that IS ours:
-- first_seen_at is stamped the first time this container_id is ever
-- reported by this host's agent to InfraHub, and never touched again on
-- conflict -- exactly the "installed_at vs created_at" distinction
-- packages.installed_at (migration 054) already draws, just for "when did
-- InfraHub first see this container" instead of "when was it installed."
CREATE TABLE docker_host_container_sightings (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    docker_host_resource_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    container_id            text NOT NULL,
    first_seen_at           timestamptz NOT NULL DEFAULT now(),
    last_seen_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT docker_host_container_sightings_unique UNIQUE (docker_host_resource_id, container_id)
);

CREATE INDEX docker_host_container_sightings_host_idx ON docker_host_container_sightings(docker_host_resource_id);

-- +goose Down
DROP TABLE docker_host_container_sightings;
