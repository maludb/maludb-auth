# Maludb Auth — Phase 2 (Tier 2 Passwordless) Implementation Plan

> **For Claude:** Execute task-by-task with TDD (red→green→refactor), exactly like the
> Phase 0/1 plan. One logical change per commit. All existing conventions from
> [2026-06-26-phase-0-1-core-auth.md](2026-06-26-phase-0-1-core-auth.md) apply.

**Goal:** One-time-token machinery + mailer abstraction, and the passwordless surface built
on them: `/otp`, `/magiclink`, `/resend`, `GET|POST /verify`, a real `/recover` +
`/reauthenticate`, confirmation-required signup (`MAILER_AUTOCONFIRM=false`), and the
mailer-dependent admin endpoints (`/invite`, `/admin/generate_link`, `GET /admin/audit`).

**Design source:** [2026-06-26-maludb-auth-design.md](2026-06-26-maludb-auth-design.md)
§6 Tier 2, §7 (one-time tokens stored hashed, single live token per `(user_id, type)`,
TTL-checked, consumed on use; redirect safety vs `SITE_URL` + `URI_ALLOW_LIST`).

**Branch:** `feat/phase-2-passwordless`. Tag on completion: `phase-2-passwordless`.

---

## Model decisions (locked)

- **Token types** (column `token_type`): `confirmation`, `recovery`, `magiclink`,
  `reauthentication`, `invite`. (`email_change` deferred — PUT /user email change keeps
  its Phase 1 behavior with a TODO.)
- **Dual redemption forms, Supabase-compatible:** every emailed token is a 6-digit numeric
  OTP `token`; we store `token_hash = sha256(token)`. Emails carry both the code and a
  verify **link** containing `token_hash`. `/verify` accepts either
  `{type, email, token}` (code) or `{type, token_hash}` (link).
- **Single live token per (user_id, type):** minting deletes any previous row first
  (`DELETE` then `INSERT`, in the caller's transaction when one is active).
- **TTL:** checked at redeem time from `created_at`, config `otp.ttl` (env `OTP_TTL`,
  default 3600s). Expired tokens are consumed (deleted) on the failed attempt.
- **Consume on use:** redemption deletes the row in the same transaction that applies the
  effect (confirm/session/etc.). A token can never be redeemed twice.
- **Enumeration defense:** `/otp`, `/magiclink`, `/resend`, `/recover` always return the
  same generic 200 whether or not the user exists. Verification failures are a single
  generic `otp_expired`-style 401 body — invalid, expired, and consumed tokens are
  indistinguishable.
- **What each type does on successful verify:**
  - `confirmation` (verify type `signup`) → `markEmailConfirmed` + issue session.
  - `recovery` (verify type `recovery`) → issue session (client then `PUT /user` to set a
    new password; the session is `aal1` with `amr: ["otp"]`).
  - `magiclink` (verify type `magiclink` or `email`) → user must be confirmed or is
    confirmed by this proof-of-inbox; issue session.
  - `invite` (verify type `invite`) → confirm + issue session (user sets password after).
  - `reauthentication` → NOT redeemed via `/verify`; consumed by `PUT /user` password
    change as the `nonce` field.
- **OTP signups:** `POST /otp` with an unknown email creates the user
  (passwordless, `encrypted_password` NULL) unless `DISABLE_SIGNUP=true` — in that case
  still return generic 200, send nothing.
- **Mailer:** `MailerInterface::send(string $to, string $subject, string $text): void`.
  Drivers: `log` (error_log, default for local), `null` (drop), `array` (in-memory, tests).
  Real SMTP delivery is deliberately out of scope (deploys can drop in a driver later);
  `MAILER_DRIVER` env selects. Message bodies come from a small `MailComposer` that builds
  subject/body + verify links per token type.
- **GET /verify redirect flow:** query `token_hash` (or `token`+`email`) + `type` +
  optional `redirect_to`. `redirect_to` validated against `SITE_URL` + `URI_ALLOW_LIST`
  (wildcard `*` suffix match) — invalid/missing falls back to `SITE_URL`. Success →
  302 to `redirect_to` with tokens in the **fragment**
  (`#access_token=…&refresh_token=…&token_type=bearer&expires_in=…&type=<type>`).
  Failure → 302 to `redirect_to` with `#error=access_denied&error_code=otp_expired&…`
  (no oracle: same shape for invalid/expired/consumed).
- **Reauth gate:** new env `UPDATE_PASSWORD_REQUIRE_REAUTHENTICATION` (default `false`).
  When true, `PUT /user` password changes must carry a valid `nonce` (a live
  `reauthentication` token for that user), which is consumed.

---

## Task 1: Migration 0003 — `auth.one_time_tokens`

**Files:** `migrations/0003_one_time_tokens.sql`; extend `tests/Integration/CoreSchemaTest.php`.

```sql
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
```

Test: table + key columns exist; the `(user_id, token_type)` uniqueness is enforced.
Run `php bin/migrate.php` (dev) and testing-mode migrate. Commit.

## Task 2: OneTimeTokenRepository

**Files:** `src/Repositories/OneTimeTokenRepository.php`;
`tests/Integration/OneTimeTokenRepositoryTest.php`.

API: `replace(string $userId, string $type, string $tokenHash, string $relatesTo): array`
(delete-then-insert → the single-live-token invariant), `findByHash(string $hash): ?array`,
`findForUser(string $userId, string $type): ?array`, `delete(string $id): void`,
`deleteAllFor(string $userId, string $type): void`.

Tests: replace twice → one row (second hash wins); findByHash roundtrip; delete removes.

## Task 3: OTP primitive — 6-digit code generation

**Files:** extend `src/Security/TokenHash.php` with `otp(int $digits = 6): string`
(crypto-random, zero-padded, `random_int(0, 10^d − 1)`); `tests/Unit/Security/TokenHashTest.php`.

Tests: returns exactly 6 digits; stays in range over many draws; `hash()` of a code is
64-hex sha256 (already covered).

## Task 4: RedirectValidator

**Files:** `src/Security/RedirectValidator.php`; `tests/Unit/Security/RedirectValidatorTest.php`.

`__construct(?string $siteUrl, array $allowList)`,
`resolve(?string $requested): string` — returns `$requested` when it exactly matches
`SITE_URL` or matches an allow-list entry (entries may end in `*` for prefix match;
otherwise exact); anything else (including scheme-relative `//evil`, `javascript:`,
non-http(s)) falls back to `SITE_URL`. Case-insensitive scheme/host compare.

Tests: exact site url passes; wildcard prefix passes; foreign origin → falls back;
`https://localhost:3000.evil.com` with allow `http://localhost:3000/*` → falls back;
`javascript:alert(1)` → falls back; null/empty → SITE_URL.

## Task 5: Mailer abstraction

**Files:** `src/Mail/MailerInterface.php`, `src/Mail/NullMailer.php`,
`src/Mail/LogMailer.php`, `src/Mail/ArrayMailer.php` (test double: `public array $sent`),
`src/Mail/MailComposer.php`; `tests/Unit/Mail/MailComposerTest.php`.

`MailComposer::__construct(string $appUrl, ?string $siteUrl)`;
`compose(string $type, string $email, string $otp, string $tokenHash, string $redirectTo): array{subject:string, text:string}`
— builds the verify link
`{APP_URL}/auth/v1/verify?token_hash={hash}&type={verifyType}&redirect_to={urlencoded}`
and embeds both the link and the 6-digit code. `reauthentication` mails carry the code
only (no link). Config additions: `mailer.driver` (`MAILER_DRIVER`, default `log`),
`mailer.from` (`MAILER_FROM`) — from-address unused by log/null/array drivers but part of
the contract. App boot picks the driver (`array` never selectable via env in prod paths —
tests construct it directly).

Tests: compose for `recovery` embeds link with `type=recovery`, the code, and the
url-encoded redirect; `reauthentication` has no link.

## Task 6: OtpService — mint + send + redeem (the heart of Phase 2)

**Files:** `src/Services/OtpService.php`, exceptions `InvalidOtpException`;
`tests/Integration/OtpServiceTest.php`.

ctor: `UserRepository`, `IdentityRepository`, `OneTimeTokenRepository`, `TokenService`,
`AuditRepository`, `MailerInterface`, `MailComposer`, `TokenHash`, `Config`, `PDO`.

- `send(string $type, string $email, string $ip, bool $createUser = false, string $redirectTo = ''): void`
  — normalize email; find user. Missing user: if `$createUser` && signups enabled →
  create passwordless user + `email` identity (transaction, reusing the AuthService
  pattern); else **return silently** (generic-200 upstream). Mint OTP →
  `replace(...)` → `mailer->send(compose(...))` → audit (`{type}_sent`, user_id only).
  For `confirmation`: skip + return silently when the user is already confirmed.
- `verify(string $type, ?string $email, ?string $token, ?string $tokenHash, string $ip, string $ua): IssuedTokens`
  — resolve row: by `sha256(token)` + user email match when code form; by `token_hash`
  when link form. No row / wrong type / TTL exceeded → delete row when present, throw
  `InvalidOtpException`. In a transaction: consume (delete) + apply effect per the
  locked table above + issue session via `TokenService::issueForUser(user, ip, ua,
  'aal1', ['otp'])`. Audit `otp_verified` / `user_confirmed`.
- `consumeReauthentication(string $userId, string $nonce): bool` — hash + lookup for that
  user/type, TTL-check, consume; used by `PUT /user`.

Tests (integration, ArrayMailer): send recovery mints row + one mail whose body contains
the code; unknown email sends nothing but does not throw; send twice → single live row,
old code dead; verify happy path returns tokens + consumes (second verify throws);
expired (backdate `created_at` via SQL) throws + row gone; `magiclink` with
`createUser=true` creates a passwordless user; confirmation verify sets
`email_confirmed_at`; wrong-type redemption fails.

`ErrorMapper`: map `InvalidOtpException` → 401 `{"error":"otp_expired"}` (single generic
body).

## Task 7: OtpController — POST /otp, /magiclink, /resend

**Files:** `src/Controllers/OtpController.php`; `tests/Integration/OtpEndpointTest.php`.

- `POST /otp` `{email, create_user?, redirect_to?}` → `send('magiclink', …,
  createUser: create_user ?? true)` → generic `{}` 200. Always 200 on
  known/unknown/disabled-signup (catch service errors → ErrorMapper only for validation).
- `POST /magiclink` — alias, `create_user` defaults false (legacy Supabase semantics).
- `POST /resend` `{type: signup|magiclink|recovery, email, redirect_to?}` → re-send that
  token type (maps `signup`→`confirmation`); generic 200; already-confirmed signup resend
  sends nothing, still 200.

Rate limits: add `resend` category (`config/ratelimits.php`, ~10/hr) and categorize
`/resend` + `/magiclink` (`magiclink` shares the `otp` bucket category) in
`RateLimit::categorize()`. Extend its unit/integration coverage.

## Task 8: VerifyController — GET + POST /verify

**Files:** `src/Controllers/VerifyController.php`; `tests/Integration/VerifyEndpointTest.php`.

- `POST /verify` `{type, token, email}` or `{type, token_hash}` → on success
  `TokenResponder::respond(...)` (supports `?cookie=true`); failure → ErrorMapper
  (`otp_expired` 401). Verify types map: `signup|invite`→`confirmation`? No —
  `signup`→`confirmation`, `invite`→`invite`, `recovery`→`recovery`,
  `magiclink|email`→`magiclink`; unknown type → 400 validation.
- `GET /verify?token_hash&type&redirect_to` → resolve redirect via `RedirectValidator`;
  success → 302 `Location: {redirect}#access_token=…&refresh_token=…&token_type=bearer&expires_in=…&type={type}`;
  failure → 302 `{redirect}#error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired`.
  GET never sets cookies (link clicks are top-level navigations; the SPA picks tokens off
  the fragment).

Tests: full POST happy path both token forms; GET success carries tokens in fragment (and
NOT in query — assert no `access_token=` before `#`); GET with disallowed `redirect_to`
lands on SITE_URL; GET failure fragment shape; replay → failure.

## Task 9: Real /recover + /reauthenticate

**Files:** modify `src/Controllers/RecoverController.php`;
extend `tests/Integration/RecoverEndpointTest.php`.

- `recover`: validate email → `otp->send('recovery', email, ip, createUser: false,
  redirectTo)` → generic 200 (unknown email identical).
- `reauthenticate`: requires auth (existing 401 branch); load user; mint + send
  `reauthentication` (code-only mail); generic 200.

## Task 10: Reauth-gated password change

**Files:** modify `src/Controllers/UserController.php`, `config/config.php`,
`.env.example`; extend `tests/Integration/UserEndpointTest.php`.

When `security.update_password_require_reauthentication` is true and the request sets
`password`: require body `nonce`, `OtpService::consumeReauthentication` must succeed,
else 400 `{"error":"reauthentication_needed"}`. Flag off (default) → Phase 1 behavior
unchanged. Existing rotate-CSRF/revoke-others behavior stays.

## Task 11: Confirmation-required signup

**Files:** modify `src/Services/AuthService.php` (inject `OtpService` or a minting
callback — prefer injecting `OtpService`), `src/App.php` wiring;
extend `tests/Integration/SignupEndpointTest.php`.

With `MAILER_AUTOCONFIRM=false`: signup creates the unconfirmed user (existing behavior),
then mints + emails a `confirmation` token; response stays `{user}` with **no session**
(already the case). Test: mail sent; `POST /verify type=signup` with the mailed code →
confirmed + session; login before confirmation → still allowed? **No**: add the
Supabase rule — password login for an unconfirmed user throws new
`EmailNotConfirmedException` → 400 `{"error":"email_not_confirmed"}` **only when
autoconfirm is off** (avoid breaking existing autoconfirm tests; check
`email_confirmed_at` directly, after the credential check, before ban check? — after ban
check, so ban still masks nothing; wrong password on unconfirmed account stays generic).

## Task 12: Admin — /invite, /admin/generate_link, GET /admin/audit

**Files:** modify `src/Controllers/AdminUsersController.php` (or new
`AdminActionsController`), `src/Repositories/AuditRepository.php` (add `recent(limit,
page)` listing if missing), `src/App.php`;
`tests/Integration/AdminActionsEndpointTest.php`.

- `POST /admin/invite` (service-role) `{email, data?, redirect_to?}` → create unconfirmed
  passwordless user (or reuse existing unconfirmed) + mint `invite` + send; returns the
  user. 422 when the email is already registered+confirmed.
- `POST /admin/generate_link` `{type: signup|invite|recovery|magiclink, email,
  redirect_to?}` → mint the token **without sending**; return
  `{action_link, email_otp, hashed_token, verification_type}` (Supabase shape).
- `GET /admin/audit` → paginated `audit_log_entries` (newest first).
  All three behind `RequireAdmin`; all audited.

## Task 13: Wire routes + settings + E2E

**Files:** `src/App.php`, `src/Controllers/MetaController.php`,
`tests/Integration/EndToEndPasswordlessFlowTest.php`.

Routes: `POST /otp`, `POST /magiclink`, `POST /resend`, `GET /verify`, `POST /verify`,
`POST /admin/invite`, `POST /admin/generate_link`, `GET /admin/audit`.
Settings adds `mailer_otp_exp` + keeps existing keys.

E2E test (ArrayMailer injected via a test-mode App factory hook):
```
POST /otp (new email, create_user) → mail captured → POST /verify {email, token} →
session works on GET /user → replayed verify fails →
POST /recover for that user → GET /verify?token_hash=…&redirect_to=allowed →
302 fragment tokens → PUT /user sets password with that session →
password login now succeeds.
```

**Definition of Done:** full suite green; migrations apply cleanly; every new endpoint
rate-limited + audited + enumeration-safe; no token plaintext ever stored or logged
(LogMailer redacts nothing — acceptable for `log` driver in dev only; document);
tag `phase-2-passwordless`.

## Deferred (do NOT build here)

Email-change confirmation flow, SMS/phone OTP, SMTP driver, OAuth (Phase 3), MFA/TOTP
(Phase 4), captcha, HIBP.
