-- +goose Up

-- Alert Rules originally covered VM/Database/Docker-container/Object-Storage
-- only (migrations 025/026). This widens coverage to the two remaining
-- resource kinds this app manages (K8S_CLUSTER, DOCKER_HOST -- see
-- resources.resource_type's own CHECK, migrations 032/046) and adds a new
-- log-based alert category (severity-classified log line count within the
-- rule's own duration window, reusing services.ClassifyLogLine -- the same
-- classification already used for search/summary counts, never a new
-- stored severity column) for every resource kind that has persisted log
-- history: VM-hosted Docker containers, standalone Docker Host containers,
-- and Kubernetes pods.
--
-- k8s_pod_id/docker_host_container_sighting_id narrow a rule to one pod or
-- one Docker Host container, exactly mirroring how container_id (migration
-- 025) already narrows a VM-scoped rule to one Docker container --
-- resource_id still always points at the *parent* resource (the K8S_CLUSTER
-- or DOCKER_HOST row) for authorization, matching the existing convention.
ALTER TABLE alert_rules ADD COLUMN k8s_pod_id uuid REFERENCES k8s_pods(id) ON DELETE CASCADE;
ALTER TABLE alert_rules ADD COLUMN docker_host_container_sighting_id uuid REFERENCES docker_host_container_sightings(id) ON DELETE CASCADE;

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_resource_container_type_unique;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_resource_container_type_unique
    UNIQUE (resource_id, container_id, k8s_pod_id, docker_host_container_sighting_id, alert_type);

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_alert_type_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_alert_type_check CHECK (alert_type IN (
    'VM_HIGH_CPU', 'VM_HIGH_MEMORY', 'VM_HIGH_STORAGE', 'VM_UNAVAILABLE',
    'DOCKER_CONTAINER_STOPPED', 'DOCKER_CONTAINER_RESTARTING', 'DOCKER_CONTAINER_UNHEALTHY', 'DOCKER_CONTAINER_OOM',
    'DOCKER_CONTAINER_HIGH_ERROR_LOGS',
    'DATABASE_UNAVAILABLE', 'DATABASE_HIGH_CONNECTIONS', 'DATABASE_HIGH_LATENCY', 'DATABASE_LOCK_CONTENTION',
    'DATABASE_REPLICATION_LAG', 'DATABASE_HIGH_STORAGE', 'DATABASE_LOW_CACHE_HIT',
    'OBJECT_STORAGE_UNAVAILABLE', 'OBJECT_STORAGE_HIGH_GROWTH', 'OBJECT_STORAGE_PUBLIC_ACCESS',
    'OBJECT_STORAGE_ENCRYPTION_DISABLED', 'OBJECT_STORAGE_HIGH_ERROR_RATE',
    'K8S_CLUSTER_UNAVAILABLE',
    'K8S_POD_NOT_RUNNING', 'K8S_POD_CRASH_LOOPING', 'K8S_POD_HIGH_CPU', 'K8S_POD_HIGH_MEMORY', 'K8S_POD_HIGH_ERROR_LOGS',
    'DOCKER_HOST_UNAVAILABLE', 'DOCKER_HOST_CONTAINER_HIGH_ERROR_LOGS'
));

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'CPU_PERCENT', 'MEMORY_PERCENT', 'STORAGE_PERCENT', 'VM_UNREACHABLE',
    'CONTAINER_STOPPED', 'CONTAINER_RESTARTING', 'CONTAINER_UNHEALTHY', 'CONTAINER_RESTART_COUNT', 'CONTAINER_LOG_ERROR_COUNT',
    'DB_UNREACHABLE', 'DB_CONNECTION_PERCENT', 'DB_LATENCY_P95_MS', 'DB_LOCKS_BLOCKED',
    'DB_REPLICATION_LAG_SECONDS', 'DB_STORAGE_BYTES', 'DB_CACHE_HIT_PERCENT',
    'OBJECT_STORAGE_UNREACHABLE', 'OBJECT_STORAGE_GROWTH_PERCENT', 'OBJECT_STORAGE_PUBLIC_ACCESS_FLAG',
    'OBJECT_STORAGE_ENCRYPTION_DISABLED_FLAG', 'OBJECT_STORAGE_ERROR_RATE_PERCENT',
    'K8S_CLUSTER_UNREACHABLE',
    'K8S_POD_UNAVAILABLE', 'K8S_POD_RESTART_COUNT', 'K8S_POD_CPU_MILLICORES', 'K8S_POD_MEMORY_BYTES', 'K8S_POD_LOG_ERROR_COUNT',
    'DOCKER_HOST_UNREACHABLE', 'DOCKER_HOST_CONTAINER_LOG_ERROR_COUNT'
));

-- +goose Down

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN (
    'CPU_PERCENT', 'MEMORY_PERCENT', 'STORAGE_PERCENT', 'VM_UNREACHABLE',
    'CONTAINER_STOPPED', 'CONTAINER_RESTARTING', 'CONTAINER_UNHEALTHY', 'CONTAINER_RESTART_COUNT',
    'DB_UNREACHABLE', 'DB_CONNECTION_PERCENT', 'DB_LATENCY_P95_MS', 'DB_LOCKS_BLOCKED',
    'DB_REPLICATION_LAG_SECONDS', 'DB_STORAGE_BYTES', 'DB_CACHE_HIT_PERCENT',
    'OBJECT_STORAGE_UNREACHABLE', 'OBJECT_STORAGE_GROWTH_PERCENT', 'OBJECT_STORAGE_PUBLIC_ACCESS_FLAG',
    'OBJECT_STORAGE_ENCRYPTION_DISABLED_FLAG', 'OBJECT_STORAGE_ERROR_RATE_PERCENT'
));

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_alert_type_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_alert_type_check CHECK (alert_type IN (
    'VM_HIGH_CPU', 'VM_HIGH_MEMORY', 'VM_HIGH_STORAGE', 'VM_UNAVAILABLE',
    'DOCKER_CONTAINER_STOPPED', 'DOCKER_CONTAINER_RESTARTING', 'DOCKER_CONTAINER_UNHEALTHY', 'DOCKER_CONTAINER_OOM',
    'DATABASE_UNAVAILABLE', 'DATABASE_HIGH_CONNECTIONS', 'DATABASE_HIGH_LATENCY', 'DATABASE_LOCK_CONTENTION',
    'DATABASE_REPLICATION_LAG', 'DATABASE_HIGH_STORAGE', 'DATABASE_LOW_CACHE_HIT',
    'OBJECT_STORAGE_UNAVAILABLE', 'OBJECT_STORAGE_HIGH_GROWTH', 'OBJECT_STORAGE_PUBLIC_ACCESS',
    'OBJECT_STORAGE_ENCRYPTION_DISABLED', 'OBJECT_STORAGE_HIGH_ERROR_RATE'
));

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_resource_container_type_unique;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_resource_container_type_unique UNIQUE (resource_id, container_id, alert_type);

ALTER TABLE alert_rules DROP COLUMN docker_host_container_sighting_id;
ALTER TABLE alert_rules DROP COLUMN k8s_pod_id;
