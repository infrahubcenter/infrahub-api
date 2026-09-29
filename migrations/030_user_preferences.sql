-- +goose Up

-- Step 21: personal settings (/settings' Personal tab). One row per user,
-- created on first write (GET returns defaults for a user with no row yet
-- rather than requiring a row to exist -- see UserPreferencesService.Get).
-- muted_notification_categories holds a subset of notifications.category
-- (migration 025) that this user does not want an IN_APP notification for;
-- validated against that same enum in application code rather than a
-- second CHECK constraint here, and CRITICAL_ALERT is never a valid value
-- to add to it (see UserPreferencesService.validateMutedCategories) -- a
-- critical alert must always still reach every admin/authorized member,
-- mirroring NotificationService.NotifyAlert's existing "Admins always
-- receive every alert" guarantee.
CREATE TABLE user_preferences (
    user_id                        uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme                          text NOT NULL DEFAULT 'SYSTEM' CHECK (theme IN ('SYSTEM', 'LIGHT', 'DARK')),
    timezone                       text NOT NULL DEFAULT 'UTC',
    date_format                    text NOT NULL DEFAULT 'YYYY-MM-DD' CHECK (date_format IN ('YYYY-MM-DD', 'MM/DD/YYYY', 'DD/MM/YYYY')),
    muted_notification_categories  text[] NOT NULL DEFAULT '{}',
    created_at                     timestamptz NOT NULL DEFAULT now(),
    updated_at                     timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER user_preferences_set_updated_at
    BEFORE UPDATE ON user_preferences
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE user_preferences;
