-- +goose Up

-- Operations are historical records of admin-requested actions. Unlike the
-- resource detail tables, they must survive their resource (or requester)
-- being removed, so both foreign keys are nullable with ON DELETE SET NULL
-- rather than CASCADE. Command execution itself is implemented in a later
-- step; this table only tracks the request/result lifecycle.
CREATE TABLE operations (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id      uuid REFERENCES resources(id) ON DELETE SET NULL,
    operation_type   text NOT NULL CHECK (operation_type IN (
        'OS_UPDATE', 'PACKAGE_UPDATE', 'DOCKER_OPERATION', 'DATABASE_OPERATION', 'STORAGE_OPERATION'
    )),
    requested_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    status           text NOT NULL DEFAULT 'PENDING' CHECK (status IN (
        'PENDING', 'APPROVED', 'RUNNING', 'SUCCESS', 'FAILED', 'CANCELLED'
    )),
    command_preview  text,
    started_at       timestamptz,
    completed_at     timestamptz,
    exit_code        integer,
    summary          text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX operations_resource_created_idx ON operations(resource_id, created_at);

CREATE TRIGGER operations_set_updated_at
    BEFORE UPDATE ON operations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Operation logs are owned by their operation, so they do cascade with it;
-- operations rows themselves are expected to be retained indefinitely by
-- the application rather than deleted.
CREATE TABLE operation_logs (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id     uuid NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    sequence_number  integer NOT NULL,
    stream           text NOT NULL CHECK (stream IN ('STDOUT', 'STDERR', 'SYSTEM')),
    -- Log lines must never contain credential values; the application layer
    -- is responsible for redaction before insert.
    message          text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT operation_logs_operation_sequence_unique UNIQUE (operation_id, sequence_number)
);

-- +goose Down
DROP TABLE operation_logs;
DROP TABLE operations;
