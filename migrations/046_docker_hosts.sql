-- +goose Up

-- Docker Hosts: a standalone, admin-configured Docker agent target,
-- mirroring how k8s_clusters is already independent of vms (032/035) --
-- "Connect a Docker Host" (name + workspace) mints a bearer token shown
-- once, the admin runs `docker run ...` themselves anywhere with a Docker
-- daemon, and the agent dials OUT over the existing, already-generic
-- /api/docker-agent/connect endpoint. This is additive: a VM's own
-- SSH-installed/managed Docker agent (041_docker_agent.sql) is unchanged
-- and unrelated -- a Docker Host has no vms row, no SSH, at all.
ALTER TABLE resources DROP CONSTRAINT resources_resource_type_check;
ALTER TABLE resources ADD CONSTRAINT resources_resource_type_check
    CHECK (resource_type IN ('VM', 'DATABASE', 'OBJECT_STORAGE', 'K8S_CLUSTER', 'DOCKER_HOST'));

-- docker.monitor/docker.logs grants may now target either a VM (today's
-- SSH/agent-installed VM) or a standalone DOCKER_HOST resource -- carried
-- purely by resource_type at grant-validation time (services/
-- docker_access.go), no schema change needed on docker_access_grants
-- itself (it was already resource-type-agnostic, just resource_id + a
-- permission string).

CREATE TABLE docker_hosts (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id            uuid NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
    -- Populated from the agent's own reported `docker version` once
    -- connected -- never required/guessed at creation time.
    engine_version         text,
    monitoring_enabled     boolean NOT NULL DEFAULT true,
    last_connection_at     timestamptz,
    -- Soft-delete only, same as every other standalone resource -- the
    -- real Docker daemon/container this app never touches is unaffected.
    deleted_at             timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER docker_hosts_set_updated_at
    BEFORE UPDATE ON docker_hosts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX docker_hosts_monitoring_enabled_idx ON docker_hosts(monitoring_enabled) WHERE monitoring_enabled = true;

-- Mirrors docker_agent_tokens (041)/k8s_cluster_agent_tokens (035)
-- exactly: only the bearer token's SHA-256 hash is ever stored, shown
-- once in plaintext at generation time. Kept as its own table (not a
-- widened docker_agent_tokens) since that one's vm_resource_id column and
-- every existing call site is VM-specific end to end -- a parallel table
-- is the lower-risk move, same as K8s never tried to reuse a VM-shaped
-- token table either.
CREATE TABLE docker_host_agent_tokens (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    docker_host_id     uuid NOT NULL UNIQUE REFERENCES docker_hosts(id) ON DELETE CASCADE,
    token_hash         bytea NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_connected_at  timestamptz
);

CREATE UNIQUE INDEX docker_host_agent_tokens_hash_idx ON docker_host_agent_tokens(token_hash);

-- +goose Down
DROP TABLE docker_host_agent_tokens;
DROP TABLE docker_hosts;
ALTER TABLE resources DROP CONSTRAINT resources_resource_type_check;
ALTER TABLE resources ADD CONSTRAINT resources_resource_type_check
    CHECK (resource_type IN ('VM', 'DATABASE', 'OBJECT_STORAGE', 'K8S_CLUSTER'));
