CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE IF NOT EXISTS auth.schema_migrations (
    version     varchar(255) PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
);
