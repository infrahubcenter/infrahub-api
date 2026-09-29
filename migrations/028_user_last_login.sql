-- +goose Up
ALTER TABLE users ADD COLUMN last_login_at timestamptz;
CREATE INDEX users_last_login_at_idx ON users(last_login_at);

-- +goose Down
DROP INDEX users_last_login_at_idx;
ALTER TABLE users DROP COLUMN last_login_at;
