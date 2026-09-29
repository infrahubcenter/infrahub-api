-- +goose Up

-- Generic credential store for any resource. encrypted_data must always
-- contain ciphertext produced by the application layer -- this migration
-- only creates the structure; encryption/decryption is implemented in a
-- later step. Never write plaintext secrets into this table, and never log
-- its contents.
CREATE TABLE credentials (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id     uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    credential_type text NOT NULL CHECK (credential_type IN ('SSH_PRIVATE_KEY', 'DATABASE_PASSWORD', 'S3_SECRET_ACCESS_KEY')),
    encrypted_data  bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN credentials.encrypted_data IS
    'Ciphertext only. The application layer encrypts before insert and decrypts after select; this column must never hold plaintext.';

CREATE INDEX credentials_resource_id_idx ON credentials(resource_id);
CREATE INDEX credentials_resource_type_idx ON credentials(resource_id, credential_type);

CREATE TRIGGER credentials_set_updated_at
    BEFORE UPDATE ON credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE credentials;
