-- +goose Up

-- Bug fix: 011_audit.sql's append-only trigger blocked ALL updates,
-- including the audit_logs.user_id FK's own ON DELETE SET NULL action --
-- meaning deleting a user whose actions were audited failed outright with
-- "audit_logs is append-only", even though preserving the audit row with
-- user_id nulled out is exactly the declared, intended behavior. Split
-- into two triggers: DELETE stays fully blocked; UPDATE is blocked except
-- for the one specific case of user_id transitioning from set to NULL
-- with every other column unchanged (i.e. genuinely just the FK's own
-- cascade, never an application-level content edit).

DROP TRIGGER audit_logs_no_update ON audit_logs;
DROP TRIGGER audit_logs_no_delete ON audit_logs;
DROP FUNCTION prevent_audit_log_mutation();

-- +goose StatementBegin
CREATE FUNCTION prevent_audit_log_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: DELETE is not permitted';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION prevent_audit_log_content_update() RETURNS trigger AS $$
BEGIN
    IF NEW.user_id IS NULL
        AND OLD.user_id IS NOT NULL
        AND NEW.action = OLD.action
        AND NEW.resource_type IS NOT DISTINCT FROM OLD.resource_type
        AND NEW.resource_id IS NOT DISTINCT FROM OLD.resource_id
        AND NEW.ip_address IS NOT DISTINCT FROM OLD.ip_address
        AND NEW.user_agent IS NOT DISTINCT FROM OLD.user_agent
        AND NEW.metadata = OLD.metadata
        AND NEW.created_at = OLD.created_at
    THEN
        -- The referenced user was deleted; this is the FK's own
        -- ON DELETE SET NULL action, not a content edit.
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'audit_logs is append-only: content cannot be modified';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_delete();

CREATE TRIGGER audit_logs_no_content_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_content_update();

-- +goose Down
DROP TRIGGER audit_logs_no_content_update ON audit_logs;
DROP TRIGGER audit_logs_no_delete ON audit_logs;
DROP FUNCTION prevent_audit_log_content_update();
DROP FUNCTION prevent_audit_log_delete();

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
