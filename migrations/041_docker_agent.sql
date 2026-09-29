-- +goose Up
-- InfraHub's per-VM Docker agent (see /docker-agent at the repo root) --
-- mirrors k8s_cluster_agent_tokens (035_k8s_agent_tokens.sql) exactly:
-- only the bearer token's hash is ever stored, shown once in plaintext at
-- generation time. Unlike the K8s agent (which the admin installs
-- themselves by applying a manifest to an external cluster), this agent
-- is installed automatically by InfraHub itself over the VM's existing
-- SSH connection (see services/docker_agent_install.go) -- additive, not
-- a replacement: a VM with no agent installed keeps working exactly as
-- before via the existing SSH+CLI polling (docker_metrics_service.go/
-- docker_discovery_service.go/docker_log_capture.go); a VM with the
-- agent installed gets richer, faster, agent-based collection instead,
-- automatically, with no change to any downstream table or UI.
CREATE TABLE docker_agent_tokens (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_resource_id     uuid NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
    token_hash         bytea NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_connected_at  timestamptz
);

CREATE UNIQUE INDEX docker_agent_tokens_hash_idx ON docker_agent_tokens(token_hash);

-- Installation status, tracked separately from docker_daemon_status
-- (017_docker_monitoring.sql, which reflects the SSH-discovered Docker
-- daemon itself, present whether or not this agent is ever installed).
ALTER TABLE vms
    ADD COLUMN docker_agent_installed boolean NOT NULL DEFAULT false,
    ADD COLUMN docker_agent_version text,
    ADD COLUMN docker_agent_last_heartbeat_at timestamptz;

-- +goose Down
ALTER TABLE vms
    DROP COLUMN docker_agent_installed,
    DROP COLUMN docker_agent_version,
    DROP COLUMN docker_agent_last_heartbeat_at;

DROP TABLE docker_agent_tokens;
