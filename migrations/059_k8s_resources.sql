-- +goose Up
-- Generalized "survives agent offline" storage for the ~12 additional
-- Kubernetes resource kinds added to the Monitoring dashboard (Jobs,
-- CronJobs, ReplicaSets, PersistentVolumes, StorageClasses, Ingresses,
-- NetworkPolicies, EndpointSlices, ResourceQuotas, LimitRanges,
-- PodDisruptionBudgets, HorizontalPodAutoscalers) -- one generic table
-- instead of twelve near-identical ones, each of which would otherwise
-- just repeat k8s_pods' own shape (032_k8s_clusters.sql) with a
-- different name. `kind`/`namespace`/`name` stay real, indexed columns
-- (needed for filtering and as the upsert key); only each kind's own
-- extra fields (desired/ready replicas, capacity, provisioner, ...) go
-- in `detail`, since a fixed column set can't fit every kind's shape
-- without either a lot of always-mostly-NULL columns or twelve tables.
--
-- namespace is NOT NULL with '' standing in for "cluster-scoped, no
-- namespace" (PersistentVolume, StorageClass) rather than an actual
-- NULL -- Postgres treats every NULL as distinct for uniqueness
-- purposes, which would silently break the upsert-by-unique-constraint
-- pattern below for cluster-scoped kinds (two rows with the same
-- cluster/kind/name but NULL namespace would never be seen as
-- conflicting, so ON CONFLICT could never fire for them).
CREATE TABLE k8s_resources (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    k8s_cluster_id     uuid NOT NULL REFERENCES k8s_clusters(id) ON DELETE CASCADE,
    kind               text NOT NULL,
    namespace          text NOT NULL DEFAULT '',
    name               text NOT NULL,
    detail             jsonb NOT NULL DEFAULT '{}',
    last_discovered_at timestamptz NOT NULL DEFAULT now(),
    removed_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT k8s_resources_cluster_kind_ns_name_unique UNIQUE (k8s_cluster_id, kind, namespace, name)
);

CREATE INDEX k8s_resources_cluster_kind_idx ON k8s_resources(k8s_cluster_id, kind) WHERE removed_at IS NULL;

CREATE TRIGGER k8s_resources_set_updated_at
    BEFORE UPDATE ON k8s_resources
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE k8s_resources;
