-- +goose Up
-- Named, reusable SSH key credentials (workspace-scoped): the replacement
-- for the old 1:1 credentials(resource_id, 'SSH_PRIVATE_KEY') row. Reuses
-- EncryptionService's exact AES-256-GCM format (see encryption.go) --
-- encrypted_private_key holds base64(nonce||ciphertext||tag) exactly like
-- credentials.encrypted_data does today, just as raw bytea, not text.
CREATE TABLE ssh_key_credentials (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    encrypted_private_key bytea NOT NULL,
    fingerprint           text NOT NULL,
    created_by            uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

COMMENT ON COLUMN ssh_key_credentials.encrypted_private_key IS
    'Ciphertext only (AES-256-GCM via EncryptionService, same key/format as credentials.encrypted_data) -- the application layer encrypts before insert and decrypts after select; this column must never hold plaintext.';

CREATE INDEX ssh_key_credentials_workspace_id_idx ON ssh_key_credentials(workspace_id);

CREATE TRIGGER ssh_key_credentials_set_updated_at
    BEFORE UPDATE ON ssh_key_credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- vms gains a nullable pointer to the named credential it connects with.
-- ON DELETE SET NULL is a non-destructive DB-level safety net only --
-- SSHKeyCredentialService.Delete blocks deletion at the application layer
-- whenever any VM still references the credential, so this clause should
-- never actually fire through normal API use; it exists only so a
-- credential can never leave a dangling FK if it is ever removed by hand.
ALTER TABLE vms ADD COLUMN ssh_key_credential_id uuid REFERENCES ssh_key_credentials(id) ON DELETE SET NULL;
CREATE INDEX vms_ssh_key_credential_id_idx ON vms(ssh_key_credential_id);

-- +goose Down
ALTER TABLE vms DROP COLUMN ssh_key_credential_id;
DROP TABLE ssh_key_credentials;
