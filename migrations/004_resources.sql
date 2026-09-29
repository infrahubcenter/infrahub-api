-- +goose Up

-- The common resource table every infrastructure item (VM, database, object
-- storage, and future types) attaches to. This is what lets the
-- authorization model and the infrastructure UI stay resource-type-agnostic:
-- Project -> Group -> Resource -> resource-specific detail table.
CREATE TABLE resources (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_id      uuid REFERENCES groups(id) ON DELETE SET NULL,
    name          text NOT NULL,
    resource_type text NOT NULL CHECK (resource_type IN ('VM', 'DATABASE', 'OBJECT_STORAGE')),
    status        text NOT NULL DEFAULT 'UNKNOWN' CHECK (status IN ('UNKNOWN', 'ONLINE', 'OFFLINE', 'WARNING', 'ERROR', 'DISABLED')),
    description   text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- Resources are soft-deleted so that monitoring history, operations,
    -- and audit records tied to resource_id keep their referent.
    deleted_at    timestamptz
);

CREATE INDEX resources_project_id_idx ON resources(project_id);
CREATE INDEX resources_group_id_idx ON resources(group_id);
CREATE INDEX resources_resource_type_idx ON resources(resource_type);
CREATE INDEX resources_status_idx ON resources(status);

CREATE TRIGGER resources_set_updated_at
    BEFORE UPDATE ON resources
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A resource's group (when set) must belong to the same project as the
-- resource itself -- a group can't silently pull a resource into a
-- different project's hierarchy.
-- +goose StatementBegin
CREATE FUNCTION check_resource_group_project() RETURNS trigger AS $$
DECLARE
    group_project_id uuid;
BEGIN
    IF NEW.group_id IS NOT NULL THEN
        SELECT project_id INTO group_project_id FROM groups WHERE id = NEW.group_id;
        IF group_project_id IS NULL OR group_project_id != NEW.project_id THEN
            RAISE EXCEPTION 'resource group_id % does not belong to project_id %', NEW.group_id, NEW.project_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER resources_check_group_project
    BEFORE INSERT OR UPDATE ON resources
    FOR EACH ROW EXECUTE FUNCTION check_resource_group_project();

-- Direct, resource-level authorization grants. Project and group access are
-- derived from project_members / group_members; this table is the third,
-- most specific tier of the hierarchy (see docs/database-architecture.md).
CREATE TABLE resource_permissions (
    resource_id   uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (resource_id, user_id, permission_id)
);

CREATE INDEX resource_permissions_user_id_idx ON resource_permissions(user_id);

-- +goose Down
DROP TABLE resource_permissions;
DROP TRIGGER resources_check_group_project ON resources;
DROP FUNCTION check_resource_group_project();
DROP TRIGGER resources_set_updated_at ON resources;
DROP TABLE resources;
