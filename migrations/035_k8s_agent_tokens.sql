-- +goose Up
-- Replaces kubeconfig upload with an in-cluster agent model ("its not
-- safe instead give any agent"): the admin no longer hands InfraHub a
-- kubeconfig at all. Instead, configuring a cluster generates one opaque
-- bearer token (shown once, like a PAT); the admin installs a small agent
-- inside their own cluster (deploy/k8s-agent-manifest.yaml at the repo
-- root) configured with that token, and the agent dials OUT to InfraHub
-- over a WebSocket using its own in-cluster ServiceAccount credentials --
-- InfraHub's backend never holds cluster-admin credentials or needs
-- inbound network access to the cluster's API server. Only the token's
-- hash is ever stored, exactly like every other bearer-credential table
-- in this app.
CREATE TABLE k8s_cluster_agent_tokens (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    k8s_cluster_id     uuid NOT NULL UNIQUE REFERENCES k8s_clusters(id) ON DELETE CASCADE,
    token_hash         bytea NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_connected_at  timestamptz
);

CREATE UNIQUE INDEX k8s_cluster_agent_tokens_hash_idx ON k8s_cluster_agent_tokens(token_hash);

-- The kubeconfig-upload path is fully retired -- an uploaded kubeconfig is
-- exactly the credential-handling risk this migration removes, so there is
-- no reason to keep the table (encrypted or not) around unused.
DROP TABLE standalone_k8s_credentials;

-- context_name only ever meant something for a multi-context kubeconfig
-- file; the agent always uses its own single in-cluster identity, so the
-- concept no longer applies.
ALTER TABLE k8s_clusters DROP COLUMN context_name;

-- +goose Down
ALTER TABLE k8s_clusters ADD COLUMN context_name text;

CREATE TABLE standalone_k8s_credentials (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    k8s_cluster_id        uuid NOT NULL UNIQUE REFERENCES k8s_clusters(id) ON DELETE CASCADE,
    encrypted_kubeconfig  bytea NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER standalone_k8s_credentials_set_updated_at
    BEFORE UPDATE ON standalone_k8s_credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TABLE k8s_cluster_agent_tokens;
