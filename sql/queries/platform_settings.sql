-- Singleton, UI-configurable sign-in-method settings (see migration
-- 047_platform_settings.sql for the full design rationale). Exactly one
-- row ever exists in practice, created once by
-- PlatformSettingsService.EnsureRow -- every query below either creates
-- that one row or operates on whichever row GetPlatformSettings returns.

-- name: GetPlatformSettings :one
SELECT * FROM platform_settings LIMIT 1;

-- name: CreatePlatformSettingsRow :one
INSERT INTO platform_settings DEFAULT VALUES RETURNING *;

-- name: UpdatePlatformSettingsGitHub :one
-- secret_enc left NULL means "leave the currently stored secret
-- unchanged" -- re-saving just the Client ID never blows away an already-
-- configured secret.
UPDATE platform_settings
SET github_client_id = sqlc.arg('client_id'),
    github_client_secret_enc = COALESCE(sqlc.narg('client_secret_enc'), github_client_secret_enc),
    updated_by = sqlc.arg('updated_by')
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: UpdatePlatformSettingsGoogle :one
UPDATE platform_settings
SET google_client_id = sqlc.arg('client_id'),
    google_client_secret_enc = COALESCE(sqlc.narg('client_secret_enc'), google_client_secret_enc),
    updated_by = sqlc.arg('updated_by')
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: UpdatePlatformSettingsSMTP :one
UPDATE platform_settings
SET smtp_host = sqlc.arg('host'),
    smtp_port = sqlc.arg('port'),
    smtp_username = sqlc.arg('username'),
    smtp_password_enc = COALESCE(sqlc.narg('password_enc'), smtp_password_enc),
    smtp_from_email = sqlc.arg('from_email'),
    smtp_use_tls = sqlc.arg('use_tls'),
    updated_by = sqlc.arg('updated_by')
WHERE id = sqlc.arg('id')
RETURNING *;
