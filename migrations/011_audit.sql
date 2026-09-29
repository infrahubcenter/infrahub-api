-- +goose Up

-- Audit logs record actions across every entity type (users, projects,
-- groups, resources, permissions, ...), so resource_id is intentionally a
-- plain uuid rather than a foreign key into resources -- it may point at
-- rows in other tables entirely, or be null for actions with no single
-- target (e.g. USER_LOGIN).
CREATE TABLE audit_logs (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid REFERENCES users(id) ON DELETE SET NULL,
    action         text NOT NULL,
    resource_type  text,
    resource_id    uuid,
    ip_address     inet,
    user_agent     text,
    metadata       jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_logs_user_created_idx ON audit_logs(user_id, created_at);
CREATE INDEX audit_logs_resource_created_idx ON audit_logs(resource_id, created_at);

-- Audit logs are append-only: enforce it in the database, not just in
-- application discipline.
-- +goose StatementBegin
CREATE FUNCTION prevent_audit_log_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

CREATE TRIGGER audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

-- +goose Down
DROP TABLE audit_logs;
DROP FUNCTION prevent_audit_log_mutation();
