-- +goose Up

-- Step 20 hardening: CredentialService.ConfigureCredential
-- (internal/services/credential.go) already prevents duplicate
-- (resource_id, credential_type) rows in the normal case via its own
-- delete-then-insert transaction, but nothing at the schema level stopped
-- two concurrent configure requests from both reading "no existing row"
-- and each inserting one. This constraint closes that race outright,
-- matching what the application already intends to be true: at most one
-- live credential per resource per type.
--
-- If any pre-existing duplicates already exist (e.g. from an earlier,
-- unclean state), keep only the most recently created row per
-- (resource_id, credential_type) -- the same "replace the old one" intent
-- ConfigureCredential itself already has -- so this migration never fails
-- against real data. (created_at, id) is used as the ordering key, not
-- created_at alone, so two rows inserted in the same transaction/instant
-- still resolve to exactly one survivor.
DELETE FROM credentials a
USING credentials b
WHERE a.resource_id = b.resource_id
  AND a.credential_type = b.credential_type
  AND (a.created_at, a.id) < (b.created_at, b.id);

ALTER TABLE credentials
    ADD CONSTRAINT credentials_resource_type_unique UNIQUE (resource_id, credential_type);

-- +goose Down
ALTER TABLE credentials DROP CONSTRAINT credentials_resource_type_unique;
