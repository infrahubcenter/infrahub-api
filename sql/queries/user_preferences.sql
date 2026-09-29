-- name: GetUserPreferences :one
SELECT * FROM user_preferences WHERE user_id = $1;

-- name: UpsertUserPreferences :one
INSERT INTO user_preferences (user_id, theme, timezone, date_format, muted_notification_categories)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id) DO UPDATE SET
    theme = EXCLUDED.theme,
    timezone = EXCLUDED.timezone,
    date_format = EXCLUDED.date_format,
    muted_notification_categories = EXCLUDED.muted_notification_categories
RETURNING *;

-- Step 21: NotificationService.NotifyAlert consults this before creating an
-- IN_APP row for a given recipient/category so a muted category is simply
-- never delivered to that one user -- every other recipient and every other
-- channel for the same alert is unaffected. A user with no preferences row
-- has muted nothing (LEFT JOIN, not an inner join).
-- name: GetMutedNotificationCategoriesForUsers :many
SELECT user_id, muted_notification_categories FROM user_preferences
WHERE user_id = ANY(sqlc.arg('user_ids')::uuid[]) AND array_length(muted_notification_categories, 1) > 0;
