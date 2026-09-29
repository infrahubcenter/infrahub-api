-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Shared trigger function: every table with an updated_at column attaches
-- this so callers never have to remember to set it manually.
-- +goose StatementBegin
CREATE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS set_updated_at();
DROP EXTENSION IF EXISTS pgcrypto;
