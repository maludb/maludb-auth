-- One-time tokens: emailed OTP codes / verify links, stored HASHED (sha256).
-- Invariant: at most one live token per (user_id, token_type) — minting a new
-- token replaces the previous one. Rows are consumed (deleted) on redemption;
-- TTL is enforced at redeem time from created_at (config otp.ttl).
CREATE TABLE auth.one_time_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_type  varchar(32) NOT NULL CHECK (token_type IN
                ('confirmation','recovery','magiclink','reauthentication','invite')),
    token_hash  varchar(64) NOT NULL,
    relates_to  citext NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, token_type)
);
CREATE INDEX one_time_tokens_hash_idx ON auth.one_time_tokens (token_hash);
