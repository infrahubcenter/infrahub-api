-- +goose Up

-- Step 25: Kubernetes clusters as a standalone, admin-configured
-- infrastructure resource -- mirrors the Database/Object Storage pattern
-- exactly (a resources row for project/group placement + a detail table +
-- a dedicated encrypted-credential table for the secret, here the whole
-- kubeconfig), not the VM pattern. Widen resources.resource_type first so
-- the new resource_id FK below has somewhere valid to point.
ALTER TABLE resources DROP CONSTRAINT resources_resource_type_check;
ALTER TABLE resources ADD CONSTRAINT resources_resource_type_check
    CHECK (resource_type IN ('VM', 'DATABASE', 'OBJECT_STORAGE', 'K8S_CLUSTER'));

-- Step 24's docker_access_grants table is already fully generic (nothing
-- Docker-specific about its schema -- user/scope/permission/audit shape),
-- so Kubernetes reuses it unchanged rather than duplicating an entire
-- second grants subsystem: which feature area a grant applies to is
-- carried entirely by the permission string itself (docker.* vs k8s.*),
-- checked by AuthorizationService against whichever resource type
-- (VM-with-Docker vs K8S_CLUSTER) is actually being accessed.
ALTER TABLE docker_access_grants DROP CONSTRAINT docker_access_grants_permission_check;
ALTER TABLE docker_access_grants ADD CONSTRAINT docker_access_grants_permission_check
    CHECK (permission IN ('docker.monitor', 'docker.logs', 'k8s.monitor', 'k8s.logs'));

CREATE TABLE k8s_clusters (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id            uuid NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
    -- Populated from the kubeconfig once a connection succeeds -- never
    -- required at creation time (spec: admin uploads a kubeconfig, the
    -- cluster's own identity is discovered from it, never hand-typed).
    api_server_url         text,
    -- Which context inside the kubeconfig to use, for a multi-context
    -- file -- empty means "use the file's current-context".
    context_name           text,
    -- Empty/NULL means "every namespace"; set to restrict discovery/
    -- monitoring/logs to one namespace (spec allows scoping by what's
    -- "already available in app level" -- project/group -- this is an
    -- additional, optional cluster-side narrowing, not a replacement).
    namespace_filter       text,
    kubernetes_version     text,
    monitoring_enabled     boolean NOT NULL DEFAULT true,
    connection_status      text NOT NULL DEFAULT 'UNKNOWN' CHECK (connection_status IN (
        'CONNECTED', 'AUTH_FAILED', 'TIMEOUT', 'REFUSED', 'TLS_ERROR', 'UNAVAILABLE', 'UNKNOWN'
    )),
    last_connection_at     timestamptz,
    last_connection_error  text,
    last_discovered_at     timestamptz,
    -- Soft-delete only, same as Database/Object Storage: removing a
    -- cluster from Infra Hub Center means removing the monitoring
    -- registration only -- this project never modifies real cluster
    -- state, ever.
    deleted_at             timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER k8s_clusters_set_updated_at
    BEFORE UPDATE ON k8s_clusters
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX k8s_clusters_monitoring_enabled_idx ON k8s_clusters(monitoring_enabled) WHERE monitoring_enabled = true;

-- The kubeconfig is the ONLY secret here (it embeds whatever auth the
-- cluster needs -- client cert, bearer token, exec plugin, etc.) --
-- mirrors standalone_object_storage_credentials/
-- standalone_database_credentials exactly: dedicated table, AES-256-GCM
-- via the same EncryptionService, never returned by any API response.
CREATE TABLE standalone_k8s_credentials (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    k8s_cluster_id         uuid NOT NULL UNIQUE REFERENCES k8s_clusters(id) ON DELETE CASCADE,
    encrypted_kubeconfig   bytea NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER standalone_k8s_credentials_set_updated_at
    BEFORE UPDATE ON standalone_k8s_credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One row per pod currently known on a cluster -- mirrors
-- docker_containers' upsert-on-scan/removed_at-instead-of-delete shape
-- exactly (migration 008), so a pod that disappears between scans is
-- marked gone rather than losing its history. cpu_usage_millicores/
-- memory_usage_bytes are populated best-effort from the cluster's
-- metrics.k8s.io API (metrics-server) when available; NULL (never a
-- fabricated 0) when it isn't installed on that cluster -- same "N/A over
-- a fake number" discipline this app already applies everywhere else.
CREATE TABLE k8s_pods (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    k8s_cluster_id         uuid NOT NULL REFERENCES k8s_clusters(id) ON DELETE CASCADE,
    namespace              text NOT NULL,
    pod_name               text NOT NULL,
    node_name              text,
    phase                  text NOT NULL DEFAULT 'UNKNOWN' CHECK (phase IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'UNKNOWN')),
    ready_containers       integer,
    total_containers       integer,
    restart_count          integer,
    cpu_usage_millicores   bigint,
    memory_usage_bytes     bigint,
    started_at             timestamptz,
    last_discovered_at     timestamptz NOT NULL DEFAULT now(),
    removed_at             timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT k8s_pods_cluster_ns_name_unique UNIQUE (k8s_cluster_id, namespace, pod_name)
);

CREATE TRIGGER k8s_pods_set_updated_at
    BEFORE UPDATE ON k8s_pods
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX k8s_pods_cluster_idx ON k8s_pods(k8s_cluster_id);

-- +goose Down
DROP TABLE k8s_pods;
DROP TABLE standalone_k8s_credentials;
DROP TABLE k8s_clusters;
ALTER TABLE docker_access_grants DROP CONSTRAINT docker_access_grants_permission_check;
ALTER TABLE docker_access_grants ADD CONSTRAINT docker_access_grants_permission_check
    CHECK (permission IN ('docker.monitor', 'docker.logs'));
ALTER TABLE resources DROP CONSTRAINT resources_resource_type_check;
ALTER TABLE resources ADD CONSTRAINT resources_resource_type_check
    CHECK (resource_type IN ('VM', 'DATABASE', 'OBJECT_STORAGE'));
