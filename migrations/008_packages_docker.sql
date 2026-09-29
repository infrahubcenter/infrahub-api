-- +goose Up

CREATE TABLE packages (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id               uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name                text NOT NULL,
    installed_version   text NOT NULL,
    package_manager     text NOT NULL CHECK (package_manager IN ('APT', 'DPKG', 'DNF', 'YUM', 'RPM')),
    -- NOT NULL with a default so (vm_id, name, architecture) reliably
    -- de-duplicates; Postgres treats NULLs as distinct in unique
    -- constraints, which would otherwise let duplicates through.
    architecture        text NOT NULL DEFAULT 'unknown',
    description         text,
    last_discovered_at  timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT packages_vm_name_arch_unique UNIQUE (vm_id, name, architecture)
);

CREATE INDEX packages_vm_id_idx ON packages(vm_id);

CREATE TRIGGER packages_set_updated_at
    BEFORE UPDATE ON packages
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE package_updates (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id                  uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    package_id             uuid NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    current_version        text NOT NULL,
    available_version      text NOT NULL,
    severity               text NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    is_security_update     boolean NOT NULL DEFAULT false,
    recommendation_status  text NOT NULL DEFAULT 'NEW' CHECK (recommendation_status IN ('NEW', 'REVIEWED', 'DISMISSED', 'RESOLVED')),
    detected_at            timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX package_updates_vm_status_idx ON package_updates(vm_id, recommendation_status);

CREATE TRIGGER package_updates_set_updated_at
    BEFORE UPDATE ON package_updates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE os_updates (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id                  uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    current_os_version     text NOT NULL,
    available_os_version   text NOT NULL,
    update_type            text NOT NULL CHECK (update_type IN ('PATCH', 'MINOR', 'MAJOR', 'SECURITY')),
    severity               text NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    reboot_required        boolean NOT NULL DEFAULT false,
    recommendation_status  text NOT NULL DEFAULT 'NEW' CHECK (recommendation_status IN ('NEW', 'REVIEWED', 'DISMISSED', 'RESOLVED')),
    detected_at            timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX os_updates_vm_id_idx ON os_updates(vm_id);

CREATE TRIGGER os_updates_set_updated_at
    BEFORE UPDATE ON os_updates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE docker_images (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id               uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    repository          text NOT NULL,
    tag                 text,
    -- Docker image IDs are only unique within a single host, hence scoped
    -- by vm_id rather than treated as a global identifier.
    image_id            text NOT NULL,
    size_bytes          bigint,
    created_at_remote   timestamptz,
    last_discovered_at  timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT docker_images_vm_image_unique UNIQUE (vm_id, image_id)
);

CREATE INDEX docker_images_vm_id_idx ON docker_images(vm_id);

CREATE TRIGGER docker_images_set_updated_at
    BEFORE UPDATE ON docker_images
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE docker_containers (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id               uuid NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    container_id        text NOT NULL,
    name                text NOT NULL,
    image               text NOT NULL,
    image_tag           text,
    status              text NOT NULL CHECK (status IN ('RUNNING', 'STOPPED', 'RESTARTING', 'PAUSED', 'EXITED', 'UNKNOWN')),
    -- Structured port mappings only (e.g. [{"host":8080,"container":80,"protocol":"tcp"}]),
    -- never raw command output.
    ports               jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at_remote   timestamptz,
    last_discovered_at  timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT docker_containers_vm_container_unique UNIQUE (vm_id, container_id)
);

CREATE INDEX docker_containers_vm_id_idx ON docker_containers(vm_id);

CREATE TRIGGER docker_containers_set_updated_at
    BEFORE UPDATE ON docker_containers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE docker_containers;
DROP TABLE docker_images;
DROP TABLE os_updates;
DROP TABLE package_updates;
DROP TABLE packages;
