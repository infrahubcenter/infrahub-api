-- +goose Up
-- Slack and Teams both deliver via an "Incoming Webhook" URL, just like
-- the generic WEBHOOK channel -- but each needs its OWN target URL (a
-- policy might want Slack notifications going to one channel and Teams to
-- a different one, independent of the generic webhook_url). See
-- services/notification_provider.go's SlackProvider/TeamsProvider.
ALTER TABLE notification_policies ADD COLUMN slack_webhook_url text;
ALTER TABLE notification_policies ADD COLUMN teams_webhook_url text;

-- +goose Down
ALTER TABLE notification_policies DROP COLUMN teams_webhook_url;
ALTER TABLE notification_policies DROP COLUMN slack_webhook_url;
