-- Step 16: per-recipient notification delivery records + policies.

-- name: CreateNotification :one
INSERT INTO notifications (alert_id, user_id, category, channel, severity, title, body, status, error_message, attempt_count)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetRecentNotificationForDedup :one
-- Cooldown/dedup check (spec §44/§45): has this (alert, channel,
-- recipient) triple already been notified within the cooldown window?
SELECT * FROM notifications
WHERE alert_id = $1 AND channel = $2 AND (user_id = sqlc.narg('user_id') OR (user_id IS NULL AND sqlc.narg('user_id')::uuid IS NULL))
    AND created_at >= $3
ORDER BY created_at DESC
LIMIT 1;

-- name: ListNotificationsForUser :many
SELECT * FROM notifications
WHERE user_id = $1
    AND (sqlc.narg('unread_only')::bool IS NOT TRUE OR read_at IS NULL)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountUnreadNotifications :one
SELECT count(*) FROM notifications WHERE user_id = $1 AND read_at IS NULL;

-- name: MarkNotificationRead :one
UPDATE notifications SET read_at = now() WHERE id = $1 AND user_id = $2 AND read_at IS NULL RETURNING *;

-- name: MarkAllNotificationsRead :exec
UPDATE notifications SET read_at = now() WHERE user_id = $1 AND read_at IS NULL;

-- name: DeleteNotificationsOlderThan :execrows
DELETE FROM notifications WHERE created_at < $1;

-- === notification_policies ===

-- name: CreateNotificationPolicy :one
INSERT INTO notification_policies (
    name, is_default, info_channels, warning_channels, critical_channels,
    quiet_hours_start, quiet_hours_end, quiet_hours_timezone, webhook_url,
    slack_webhook_url, teams_webhook_url, created_by
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: UpdateNotificationPolicy :one
UPDATE notification_policies
SET name = $2, info_channels = $3, warning_channels = $4, critical_channels = $5,
    quiet_hours_start = $6, quiet_hours_end = $7, quiet_hours_timezone = $8, webhook_url = $9,
    slack_webhook_url = $10, teams_webhook_url = $11
WHERE id = $1
RETURNING *;

-- name: GetNotificationPolicyByID :one
SELECT * FROM notification_policies WHERE id = $1;

-- name: GetDefaultNotificationPolicy :one
SELECT * FROM notification_policies WHERE is_default LIMIT 1;

-- name: ListNotificationPolicies :many
-- Newest first (except the system Default, always pinned to top -- it's
-- the one every admin expects to find immediately, not buried under
-- whatever was created most recently) -- a brand-new policy from "New
-- Policy" is then always visible without scrolling, unlike the previous
-- ascending order, which silently appended new policies to the bottom of
-- a list that only grows.
SELECT * FROM notification_policies ORDER BY is_default DESC, created_at DESC;

-- name: DeleteNotificationPolicy :exec
DELETE FROM notification_policies WHERE id = $1;
