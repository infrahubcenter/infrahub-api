-- +goose Up

-- Resource-specific detail tables. Each has a 1:1 relationship back to
-- resources via a unique resource_id, so the common resource row carries
-- identity/status/authorization while these carry type-specific fields.

CREATE TABLE vms (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id          uuid NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
    hostname             text NOT NULL,
    username             text,
    address              text NOT NULL,
    ssh_port             integer NOT NULL DEFAULT 22,
    os_name              text,
    os_version           text,
    kernel_version       text,
    architecture         text,
    cpu_cores            integer,
    total_memory_bytes   bigint,
    total_storage_bytes  bigint,
    docker_installed     boolean NOT NULL DEFAULT false,
    last_discovered_at   timestamptz,
    last_seen_at         timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER vms_set_updated_at
    BEFORE UPDATE ON vms
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE databases (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id         uuid NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
    engine              text NOT NULL CHECK (engine IN ('POSTGRESQL', 'MYSQL', 'REDIS')),
    host                text NOT NULL,
    port                integer NOT NULL,
    database_name       text,
    username            text,
    version             text,
    ssl_enabled         boolean NOT NULL DEFAULT false,
    last_discovered_at  timestamptz,
    last_seen_at        timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER databases_set_updated_at
    BEFORE UPDATE ON databases
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE object_storages (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id         uuid NOT NULL UNIQUE REFERENCES resources(id) ON DELETE CASCADE,
    provider            text NOT NULL CHECK (provider IN ('AWS_S3', 'DIGITALOCEAN_SPACES', 'MINIO', 'S3_COMPATIBLE')),
    endpoint            text,
    region              text,
    bucket              text NOT NULL,
    base_path           text,
    access_key_id       text,
    last_discovered_at  timestamptz,
    last_seen_at        timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER object_storages_set_updated_at
    BEFORE UPDATE ON object_storages
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE object_storages;
DROP TABLE databases;
DROP TABLE vms;
