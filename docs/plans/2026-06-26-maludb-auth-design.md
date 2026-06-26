# Maludb Auth — Design

**Date:** 2026-06-26
**Status:** Approved design, pre-implementation
**Owner:** edward.honour@gmail.com

A Supabase-Auth-compatible authentication service for the Maludb hosting platform,
built in PHP as the **canonical reference implementation** that other-language clones
(Go, Node/TypeScript, Python) will be modeled on. Adds a **CSRF-protected,
cookie-based browser mode** on top of the Supabase-style JWT/bearer model.

---

## 1. Goals & Non-Goals

### Goals
- Functional parity with [Supabase Auth (GoTrue)](https://github.com/supabase/auth) for the
  selected feature tiers.
- **Dual-mode token delivery**: Bearer tokens (API/mobile, Supabase-compatible) **and**
  `httpOnly` cookies + CSRF tokens (browser apps).
- Clean, low-magic PHP that reads as a specification — so ports to other languages are
  near-mechanical translations of the `Services/` and `Security/` layers.
- Supabase-compatible JWT claims and (where sensible) endpoint paths, so existing client
  libraries can interoperate.

### Non-Goals (v1)
SAML/SSO, Web3 wallet auth, anonymous sign-in, OAuth-server mode, WebAuthn & phone MFA,
custom server-side hooks, captcha, and HIBP leaked-password checks. All are deferred to
later phases; the design leaves seams for them.

---

## 2. Key Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Reference model | **PHP code is the model** | Honors platform lean; other stacks port from clean PHP. |
| Language/runtime | **Vanilla PHP 8.x + PSR-4 + Composer**, small hand-rolled router | Explicit logic, low framework magic, easy to translate. |
| Database | **PostgreSQL** | Port Supabase schema 1:1 (uuid, jsonb, timestamptz). |
| JWT signing | **Asymmetric RS256/ES256 + JWKS** (`/.well-known/jwks.json`) | Verifiers need no shared secret; key rotation via `kid`. |
| Token delivery | **Dual-mode** (Bearer + cookie+CSRF) | Supabase compatibility **and** the CSRF requirement. |
| CSRF scheme | **Session-bound synchronizer token** | Strongest (revocable), fits our `sessions` table. |
| v1 scope | **Core + Passwordless + OAuth + MFA(TOTP)** | Agreed feature tiers. |

---

## 3. Architecture

A standalone stateless HTTP service (PHP-FPM behind nginx; `php -S` for dev). Every request
is authenticated from scratch — **no reliance on PHP's native `$_SESSION`**. All state lives
in Postgres.

### Request pipeline (middleware chain)
```
Request
 → SecurityHeaders (no-store, X-Frame-Options, Referrer-Policy)
 → CORS
 → RateLimit (per-IP / per-account, token-bucket in Postgres)
 → AuthContext (resolve identity: Bearer JWT  OR  session cookie)
 → CSRF (enforced ONLY when auth came from a cookie + unsafe method)
 → Route handler
 → JSON response
```
**The CSRF fork:** if the caller authenticated via `Authorization: Bearer`, CSRF is skipped
(no ambient credential to forge). If via cookie, CSRF is required on POST/PUT/PATCH/DELETE.

### Directory layout
```
maludb-auth/
├── public/index.php          # front controller (only web-exposed file)
├── src/
│   ├── Http/                  # Router, Request, Response, Middleware/
│   ├── Controllers/          # Signup, Token, User, Admin, OAuth, Factors, Verify, Recover...
│   ├── Services/             # AuthService, TokenService, SessionService, MfaService, MailerService
│   ├── Models/ + Repositories/   # PDO data access, one repo per table
│   ├── Security/             # Jwt, Csrf, Password, RateLimiter, OneTimeToken
│   ├── Providers/            # OAuth provider adapters (Google, GitHub...)
│   └── Support/              # Config, Container, Validation, Mailer drivers
├── migrations/               # versioned SQL (ported from Supabase)
├── config/ + .env
├── tests/                    # unit + HTTP conformance suite
└── keys/                     # JWT signing keys (gitignored)
```
Services hold logic, controllers stay thin, repositories isolate SQL.

---

## 4. Data Model (PostgreSQL, schema `auth`)

Ported from Supabase, trimmed to v1. `citext` for case-insensitive email; **CHECK constraints
instead of Postgres ENUMs** for easier portability to the other-language clones.

- **`users`** — `id uuid PK`, `email citext`, `encrypted_password text NULL` (bcrypt; null for
  OAuth-only), `email_confirmed_at`, `phone`, `phone_confirmed_at`,
  `raw_app_meta_data jsonb` (server-controlled → JWT `app_metadata`),
  `raw_user_meta_data jsonb` (user-editable → `user_metadata`), `banned_until`,
  `last_sign_in_at`, `deleted_at` (soft delete), timestamps. **Strict app-vs-user metadata
  boundary** (app_metadata is never user-writable).
- **`identities`** — linked providers / account linking. `(provider, provider_id)` unique,
  `user_id` FK CASCADE, `identity_data jsonb`, `email`. Password user gets an `email` identity.
- **`sessions`** — `id uuid PK`, `user_id` FK, `aal` ('aal1'/'aal2'), `factor_id`,
  `not_after` (hard expiry), `refreshed_at` (inactivity), `user_agent`, `ip`,
  **`csrf_token`** (our addition — session-bound synchronizer token), timestamps.
- **`refresh_tokens`** — `token` (hashed), `session_id` FK CASCADE, `parent` (rotation chain),
  `revoked bool`. Revoked-token reuse ⇒ revoke whole session family.
- **`mfa_factors`** — `id`, `user_id`, `factor_type` ('totp'), `status`
  ('unverified'/'verified'), `secret` (encrypted TOTP secret), `friendly_name`.
- **`mfa_challenges`** — `id`, `factor_id` FK, `verified_at`, `ip_address`.
- **`mfa_amr_claims`** — `(session_id, authentication_method)` — drives `aal`/`amr` JWT claims.
- **`one_time_tokens`** — unified **hashed** store (confirm/recovery/magiclink/email-change/
  phone-change). `token_hash`, `token_type`, `relates_to`, `user_id`,
  unique `(user_id, token_type)`. Never plaintext.
- **`flow_state`** — PKCE scratch: `auth_code`, `code_challenge`, `code_challenge_method`,
  `authentication_method`, `auth_code_issued_at`.
- **`audit_log_entries`** — append-only `(id, payload jsonb, ip_address, created_at)`.
- **`rate_limits`** — token-bucket counters (our addition; Supabase uses in-memory).
- **`schema_migrations`** — migration ledger.

---

## 5. Tokens, Sessions & CSRF (core engine)

### Access token (JWT, RS256/ES256)
Short-lived (default 3600s). Claims mirror Supabase: `iss`, `sub` (user uuid),
`aud` (`authenticated`), `exp`, `iat`, `jti`, plus `email`, `phone`, `role`, `app_metadata`,
`user_metadata`, `aal`, `amr`, `session_id`, `is_anonymous`. Signed with a private key; public
keys at `/.well-known/jwks.json` with a `kid` (current + standby for rotation). Verification is
stateless (signature + exp) — no DB hit on the hot path.

### Refresh tokens
Opaque random string, **stored hashed**. On `POST /token?grant_type=refresh_token`: in one
transaction, mark old `revoked=true`, insert new with `parent=old`, same `session_id`.
Presenting an already-revoked token ⇒ **theft detected** ⇒ revoke entire session family +
audit-log. Short reuse window (10s) tolerates network retries.

### Session validity (checked on each refresh)
`not_after` (hard expiry) → timebox (absolute max) → inactivity timeout (`refreshed_at`) →
AAL step-up needed. Any failure ⇒ refresh denied; client must re-authenticate.

### Dual-mode delivery

| | API/mobile client | Browser client |
|---|---|---|
| Login requests | `?cookie=false` (default) | `?cookie=true` |
| Access token | JSON body | `mb-access-token` httpOnly cookie |
| Refresh token | JSON body | `mb-refresh-token` httpOnly cookie (path `/auth/v1/token`) |
| CSRF token | n/a | `csrf_token` in JSON body **and** session row |
| Per-request | `Authorization: Bearer <jwt>` | cookies (auto) + `X-CSRF-Token` on unsafe methods |

### CSRF (session-bound synchronizer)
On cookie-mode login: generate `csrf_token = bin2hex(random_bytes(32))`, store on the
`sessions` row, return in JSON body (client keeps it in memory/JS-readable storage — **not**
httpOnly). CSRF middleware: if request authenticated via cookie AND method ∈
{POST,PUT,PATCH,DELETE}, require `X-CSRF-Token` to `hash_equals` the session's token; else 403.
Bearer requests skip CSRF. Token **rotates on privilege change** (login, MFA elevation,
password change). Logout is always POST + CSRF-guarded; revokes session and clears cookies.

**AuthContext resolution order:** `Authorization: Bearer` header → else access-token cookie.
Cookie-sourced auth flags the request "CSRF-required."

---

## 6. Endpoints & Flows (v1)

Base path `/auth/v1`. `[B]` = Bearer or cookie+CSRF; `[A]` = admin (service-role JWT);
`[P]` = public.

### Tier 1 — Core
- `POST /signup` [P] — email+password; sends confirmation (unless autoconfirm). Generic response.
- `POST /token?grant_type=password` [P] — login; MFA users get `aal1` + step-up signal.
- `POST /token?grant_type=refresh_token` [P] — rotate.
- `POST /logout` [B] — scope `local`/`global`/`others`; revoke + clear cookies.
- `GET/PUT /user` [B] — read / update email, phone, password, `user_metadata`.
- `POST /recover` [P] — request password reset (generic response).
- `POST /reauthenticate` [B] — nonce for sensitive changes.
- `GET /settings` [P], `GET /health` [P], `GET /.well-known/jwks.json` [P].
- **Admin:** `GET/POST /admin/users`, `GET/PUT/DELETE /admin/users/{id}`, `POST /invite`,
  `POST /admin/generate_link`, `GET /admin/audit`.

### Tier 2 — Passwordless
- `POST /otp` [P] — magic link or email/SMS OTP (creates user per config).
- `POST /magiclink` [P] — legacy alias of `/otp`.
- `POST /resend` [P] — resend confirmation/OTP.
- `GET /verify` [P] — link click → verify → redirect with session (validated vs allowlist).
- `POST /verify` [P] — verify token, return tokens.

### Tier 3 — OAuth social login
- `GET /authorize` [P] — start OAuth (PKCE `flow_state`), redirect to provider.
- `GET /callback` [P] — provider returns; exchange, link/create identity, issue session.
- `POST /token?grant_type=pkce` [P] — exchange auth code + verifier for session.
- `GET /user/identities/authorize` [B], `DELETE /user/identities/{id}` [B] — link/unlink.
- **v1 providers: Google + GitHub** (adapter pattern; more = config + a small class each).

### Tier 4 — MFA (TOTP)
- `POST /factors` [B] — enroll; returns secret + otpauth URI + QR.
- `POST /factors/{id}/challenge` [B] — create challenge.
- `POST /factors/{id}/verify` [B] — verify; first verify activates, later verifies elevate to
  `aal2` (adds `amr`, rotates CSRF token).
- `DELETE /factors/{id}` [B] — unenroll.

### Deferred (post-v1)
SAML/SSO, Web3, anonymous sign-in, OAuth-server mode, WebAuthn & phone MFA, custom hooks,
captcha, HIBP leaked-password check.

---

## 7. Security Policy (hard rules)

Derived from the `php-session-auth` skill's judgment calls.

- **Passwords:** `password_hash(PASSWORD_DEFAULT)` (bcrypt) + `password_verify`; re-hash via
  `password_needs_rehash`. Min 12 chars, **max 72 bytes**. Config-driven complexity. HIBP hook
  left for later.
- **Enumeration defense:** generic responses on `/signup`, `/recover`, `/otp`, login. Login
  verifies a **precomputed dummy bcrypt hash at the same cost** when the user is missing, so
  timing doesn't leak existence.
- **Brute-force / rate limiting (non-negotiable):** token-bucket in `rate_limits`, per-IP **and**
  per-account. Distinct limits per category (login, refresh, verify, OTP/email send, MFA, signup).
  Returns `429`.
- **Email normalization:** `strtolower(trim())` / `citext` before every insert and lookup;
  `UNIQUE` index; catch SQLSTATE `23000`.
- **Cookies:** `HttpOnly`, `Secure` (prod), `SameSite=Lax`; refresh cookie path-scoped to
  `/auth/v1/token`. SameSite is defense-in-depth — the token is the real guard.
- **Headers (all auth responses):** `Cache-Control: no-store`, `X-Frame-Options: DENY`,
  `Referrer-Policy: same-origin`, strict `Content-Type`.
- **One-time tokens:** stored **hashed** (SHA-256), single live token per `(user_id, type)`,
  TTL-checked, consumed on use.
- **Redirect safety:** every redirect validated against `SITE_URL` + `URI_ALLOW_LIST` (wildcards).
- **Secrets/keys:** JWT private keys gitignored / env; TOTP + OAuth secrets encrypted at rest
  (libsodium). Key rotation via JWKS `kid`.
- **Audit logging:** every auth event → `audit_log_entries`.
- **Anti-patterns we will NOT do:** no IP/User-Agent session pinning, no GET logout, no
  SameSite-as-sole-CSRF-defense, no CSRF guard that checks only POST.

---

## 8. Testing Strategy

1. **Unit tests (PHPUnit):** JWT sign/verify, CSRF compare, password hashing/rehash, refresh
   rotation + theft detection, TOTP validation, one-time-token hashing/TTL, rate-limiter,
   redirect allowlist.
2. **HTTP integration tests:** app against disposable Postgres (Docker); assert status, JSON,
   cookies, headers. Cover each flow including the dual-mode fork and negatives (missing CSRF →
   403, replayed refresh → family revoked, rate-limit → 429, enumeration timing).
3. **Conformance doc (OpenAPI):** capture the HTTP contract as an executable target for future
   Go/Node/Python ports.

Each phase ends with its tests green before the next begins.

---

## 9. Phasing (build order)

- **Phase 0 — Skeleton:** router, middleware chain, config, container, DB connection, migrations
  runner, JWKS keygen, health/settings endpoints.
- **Phase 1 — Tier 1 Core:** users, signup, password login, JWT + refresh rotation, sessions,
  **CSRF + dual-mode**, logout, `/user`, recover/reauth, admin CRUD, audit, rate limiting.
- **Phase 2 — Tier 2 Passwordless:** one-time tokens, mailer abstraction, `/otp`, `/magiclink`,
  `/verify`, `/resend`.
- **Phase 3 — Tier 3 OAuth:** `flow_state`/PKCE, provider adapters (Google, GitHub), identities,
  link/unlink.
- **Phase 4 — Tier 4 MFA:** TOTP enroll/challenge/verify, AAL/AMR, step-up, CSRF rotation on
  elevation.
- **Phase 5 — Hardening:** full conformance suite, OpenAPI, docs, example clients
  (Bearer + browser).

---

## 10. References

- Supabase Auth repo: https://github.com/supabase/auth
- Supabase Auth docs: https://supabase.com/docs/guides/auth
- Auth REST reference: https://supabase.com/docs/reference/auth
- PKCE flow: https://supabase.com/docs/guides/auth/sessions/pkce-flow
- JWTs: https://supabase.com/docs/guides/auth/jwts
- Rate limits: https://supabase.com/docs/guides/auth/rate-limits
