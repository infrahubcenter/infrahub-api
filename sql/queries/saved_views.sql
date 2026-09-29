-- name: UpsertSavedDashboardView :one
-- Saving under a name that already exists for this user+feature replaces
-- it (re-saving a view is the expected way to update it), rather than
-- erroring or creating a duplicate. folder_id is nullable -- a dashboard
-- created "before folder" (standalone) has none.
INSERT INTO saved_dashboard_views (user_id, feature, name, filters, folder_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, feature, name) DO UPDATE SET
    filters = EXCLUDED.filters, folder_id = EXCLUDED.folder_id, updated_at = now()
RETURNING *;

-- name: ListSavedDashboardViewsForUser :many
SELECT * FROM saved_dashboard_views
WHERE user_id = $1 AND feature = $2
ORDER BY name;

-- name: GetSavedDashboardViewByID :one
SELECT * FROM saved_dashboard_views WHERE id = $1;

-- name: DeleteSavedDashboardView :exec
DELETE FROM saved_dashboard_views WHERE id = $1 AND user_id = $2;

-- === saved_view_folders ===

-- name: CreateSavedViewFolder :one
INSERT INTO saved_view_folders (user_id, feature, name)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListSavedViewFoldersForUser :many
SELECT * FROM saved_view_folders
WHERE user_id = $1 AND feature = $2
ORDER BY name;

-- name: GetSavedViewFolderByID :one
-- Scoped to user_id so a caller can never save a dashboard into (or
-- otherwise reference) a folder that isn't theirs, even by guessing an ID.
SELECT * FROM saved_view_folders WHERE id = $1 AND user_id = $2;

-- name: DeleteSavedViewFolder :exec
-- folder_id has ON DELETE CASCADE, so deleting a folder also deletes every
-- dashboard saved inside it -- the frontend confirms this with the
-- dashboard count before calling it, same pattern as any other destructive
-- delete in this app.
DELETE FROM saved_view_folders WHERE id = $1 AND user_id = $2;
