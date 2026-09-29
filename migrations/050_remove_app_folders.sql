-- +goose Up
-- Removes App Folders (036_app_folders.sql) -- superseded by
-- docker_access_grants' FOLDER/DASHBOARD scopes (see
-- 049_docker_access_folder_dashboard_scope.sql), which cover the same
-- "give this Member access to a named subset of dashboards/containers"
-- need without a second, parallel access-control table. See
-- services/app_folders.go (deleted) for the retired model.
DROP TABLE app_folder_access_grants;
DROP TABLE app_folder_items;
DROP TABLE app_folders;

-- +goose Down
CREATE TABLE app_folders (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    feature     text NOT NULL CHECK (feature IN ('DOCKER', 'K8S')),
    name        text NOT NULL,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

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

CREATE TABLE app_folder_access_grants (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    app_folder_id  uuid NOT NULL REFERENCES app_folders(id) ON DELETE CASCADE,
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE(app_folder_id, user_id)
);

CREATE INDEX app_folder_access_grants_user_idx ON app_folder_access_grants(user_id);
