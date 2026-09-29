-- +goose Up
-- App Folders: an Admin-defined named group of specific Docker containers
-- and/or K8s pods ("I will create the app name individually by selecting
-- containers"), grantable directly to individual Members independent of
-- the existing Project/Group-scoped docker_access_grants model -- a member
-- granted a folder sees only that folder's app name and the logs/metrics
-- of the containers/pods placed in it, never anything else in that
-- project/group and never the underlying container/pod/VM/cluster
-- identity (enforced the same way docker_access_grants-derived access
-- already is, in docker_overview.go/k8s_overview.go/docker_logs.go/
-- k8s_logs.go).
CREATE TABLE app_folders (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    feature     text NOT NULL CHECK (feature IN ('DOCKER', 'K8S')),
    name        text NOT NULL,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Exactly one of docker_container_id/k8s_pod_id is set, matching the
-- folder's own feature -- enforced at the application layer (which column
-- the Admin picks follows directly from which feature they're managing).
CREATE TABLE app_folder_items (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_folder_id        uuid NOT NULL REFERENCES app_folders(id) ON DELETE CASCADE,
    docker_container_id  uuid REFERENCES docker_containers(id) ON DELETE CASCADE,
    k8s_pod_id           uuid REFERENCES k8s_pods(id) ON DELETE CASCADE,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (docker_container_id IS NOT NULL AND k8s_pod_id IS NULL) OR
        (docker_container_id IS NULL AND k8s_pod_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX app_folder_items_folder_docker_unique ON app_folder_items(app_folder_id, docker_container_id) WHERE docker_container_id IS NOT NULL;
CREATE UNIQUE INDEX app_folder_items_folder_k8s_unique ON app_folder_items(app_folder_id, k8s_pod_id) WHERE k8s_pod_id IS NOT NULL;
CREATE INDEX app_folder_items_folder_idx ON app_folder_items(app_folder_id);
CREATE INDEX app_folder_items_docker_container_idx ON app_folder_items(docker_container_id) WHERE docker_container_id IS NOT NULL;
CREATE INDEX app_folder_items_k8s_pod_idx ON app_folder_items(k8s_pod_id) WHERE k8s_pod_id IS NOT NULL;

-- Which users can see a given folder -- a direct per-user grant (no
-- Project/Group indirection, unlike docker_access_grants), since the whole
-- point of a folder is picking out specific people for specific apps.
CREATE TABLE app_folder_access_grants (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_folder_id  uuid NOT NULL REFERENCES app_folders(id) ON DELETE CASCADE,
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE(app_folder_id, user_id)
);

CREATE INDEX app_folder_access_grants_user_idx ON app_folder_access_grants(user_id);

-- +goose Down
DROP TABLE app_folder_access_grants;
DROP TABLE app_folder_items;
DROP TABLE app_folders;
