-- +goose Up

-- Generic recommendation record for any resource. metadata is JSONB so new
-- recommendation types can carry type-specific detail without a schema
-- change; add to the "type" CHECK constraint when a genuinely new category
-- is introduced.
CREATE TABLE recommendations (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id  uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    type         text NOT NULL CHECK (type IN (
        'OS_UPDATE', 'PACKAGE_UPDATE', 'DOCKER_UPDATE', 'DATABASE_UPDATE',
        'STORAGE_WARNING', 'CPU_WARNING', 'MEMORY_WARNING', 'DISK_WARNING',
        'SECURITY', 'CONFIGURATION'
    )),
    severity     text NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    title        text NOT NULL,
    description  text,
    status       text NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'ACKNOWLEDGED', 'DISMISSED', 'RESOLVED')),
    metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
    detected_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX recommendations_resource_status_idx ON recommendations(resource_id, status);

CREATE TRIGGER recommendations_set_updated_at
    BEFORE UPDATE ON recommendations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE recommendations;
