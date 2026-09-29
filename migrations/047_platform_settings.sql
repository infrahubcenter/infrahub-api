-- +goose Up

-- Singleton, UI-configurable sign-in-method settings (GitHub/Google OAuth,
-- SMTP for invite emails) -- Owner-editable, takes effect immediately with
-- no restart, since it's read fresh from Postgres on every use rather than
-- cached (mirrors notification_policies' own "admin edits it, no restart
-- needed" precedent exactly -- see NotificationPolicyService.
-- EnsureDefaultPolicy). Never a CHECK-enforced single row (goose has no
-- clean idiom for that); the service layer creates exactly one row once,
-- at startup, if none exists, and every read/update thereafter targets
-- whichever row SELECT ... LIMIT 1 returns.
--
-- Secrets are encrypted via the same shared EncryptionService (AES-256-GCM,
-- keyed by SSH_CREDENTIAL_ENCRYPTION_KEY) every other encrypted-at-rest
-- credential in this app already uses -- mirrors
-- standalone_object_storage_credentials' shape (migration 026): non-secret
-- fields in plaintext, only the actual secret encrypted.
--
-- Values left NULL here fall back to the equivalent GITHUB_CLIENT_ID/
-- GOOGLE_CLIENT_ID/SMTP_* env vars (PlatformSettingsService.Get) -- an
-- already-deployed .env-only setup keeps working unchanged until an Owner
-- explicitly overrides a field through the UI.
CREATE TABLE platform_settings (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    github_client_id         text,
    github_client_secret_enc bytea,
    google_client_id         text,
    google_client_secret_enc bytea,
    smtp_host                text,
    smtp_port                integer,
    smtp_username            text,
    smtp_password_enc        bytea,
    smtp_from_email          text,
    smtp_use_tls             boolean,
    updated_at               timestamptz NOT NULL DEFAULT now(),
    updated_by               uuid REFERENCES users(id) ON DELETE SET NULL
);

CREATE TRIGGER platform_settings_set_updated_at
    BEFORE UPDATE ON platform_settings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE platform_settings;
