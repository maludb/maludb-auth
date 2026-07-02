CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE auth.users (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    aud                   varchar(255) NOT NULL DEFAULT 'authenticated',
    role                  varchar(255) NOT NULL DEFAULT 'authenticated',
    email                 citext,
    encrypted_password    text,
    email_confirmed_at    timestamptz,
    phone                 text,
    phone_confirmed_at    timestamptz,
    confirmed_at          timestamptz GENERATED ALWAYS AS (LEAST(email_confirmed_at, phone_confirmed_at)) STORED,
    last_sign_in_at       timestamptz,
    raw_app_meta_data     jsonb NOT NULL DEFAULT '{}'::jsonb,
    raw_user_meta_data    jsonb NOT NULL DEFAULT '{}'::jsonb,
    is_super_admin        boolean NOT NULL DEFAULT false,
    is_anonymous          boolean NOT NULL DEFAULT false,
    banned_until          timestamptz,
    deleted_at            timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_unique ON auth.users (email) WHERE deleted_at IS NULL;

CREATE TABLE auth.identities (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider        text NOT NULL,
    provider_id     text NOT NULL,
    identity_data   jsonb NOT NULL DEFAULT '{}'::jsonb,
    email           citext,
    last_sign_in_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_id)
);

CREATE TABLE auth.sessions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    aal           varchar(10) NOT NULL DEFAULT 'aal1' CHECK (aal IN ('aal1','aal2','aal3')),
    factor_id     uuid,
    not_after     timestamptz,
    refreshed_at  timestamptz,
    user_agent    text,
    ip            varchar(45),
    csrf_token    varchar(64) NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_id_idx ON auth.sessions (user_id);

CREATE TABLE auth.refresh_tokens (
    id          bigserial PRIMARY KEY,
    token_hash  varchar(64) NOT NULL UNIQUE,
    session_id  uuid NOT NULL REFERENCES auth.sessions(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    parent      varchar(64),
    revoked     boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_session_revoked_idx ON auth.refresh_tokens (session_id, revoked);

CREATE TABLE auth.audit_log_entries (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    payload     jsonb NOT NULL,
    ip_address  varchar(45) NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_created_at_idx ON auth.audit_log_entries (created_at);

CREATE TABLE auth.rate_limits (
    bucket_key  varchar(255) PRIMARY KEY,
    tokens      double precision NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
