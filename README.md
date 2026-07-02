# Maludb Auth

A [Supabase Auth](https://github.com/supabase/auth)–compatible authentication service, written in **vanilla PHP 8.2 / PostgreSQL** as the reference implementation for the Maludb hosting platform.

Its distinguishing feature is **dual-mode token delivery**:

- **Bearer tokens** (`Authorization: Bearer …`) for API/mobile clients — Supabase-compatible, no CSRF needed.
- **`httpOnly` cookies + a session-bound CSRF token** for browser apps.

See [`docs/plans/2026-06-26-maludb-auth-design.md`](docs/plans/2026-06-26-maludb-auth-design.md) for the full design and [`docs/plans/2026-06-26-phase-0-1-core-auth.md`](docs/plans/2026-06-26-phase-0-1-core-auth.md) for the implementation plan.

**Status:** Phase 0 (skeleton) + Phase 1 (email/password core) complete. Phase 2 (passwordless, OAuth, MFA) is planned but not built.

---

## Requirements

- **PHP 8.2+** with extensions: `pdo_pgsql`, `openssl`, `sodium` (verify with `php -m`).
- **Composer** 2.x
- **PostgreSQL 14+**, reachable over TCP. The migrations run `CREATE EXTENSION IF NOT EXISTS citext` and `pgcrypto`, so the database role used for migration must be allowed to create extensions (a superuser, or have them pre-created by a DBA).

## Quick start (fresh server)

```bash
# 1. Install PHP dependencies
composer install

# 2. Create the two databases (names must match your .env — see below)
createdb maludb_auth
createdb maludb_auth_test        # throwaway DB used only by the test suite

# 3. Configure
cp .env.example .env
$EDITOR .env                     # set DB_HOST/PORT/NAME/USER/PASSWORD, URLs, etc.

# 4. Generate the JWT signing keypair (NOT in git — see "JWT keys" below)
php bin/keygen.php               # writes keys/jwt_private.pem + keys/jwt_public.pem

# 5. Apply database migrations to the dev database
php bin/migrate.php              # applies migrations/*.sql; idempotent

# 6. Run the test suite (migrates the test DB automatically on first run)
vendor/bin/phpunit
```

A green `vendor/bin/phpunit` (all tests passing) confirms the environment is wired correctly.

## Configuration

All configuration is environment-driven; [`.env.example`](.env.example) is the authoritative contract (copy it to `.env`). Key variables:

| Variable | Purpose |
|---|---|
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | Dev/prod database connection |
| `TEST_DB_NAME` | Throwaway database for the test suite (selected when `APP_ENV=testing`) |
| `APP_URL` / `SITE_URL` / `URI_ALLOW_LIST` | Base URL, browser redirect base, and the allow-list (also the CORS origin source) |
| `JWT_ISSUER` / `JWT_AUDIENCE` / `JWT_EXP` / `JWT_KID` | JWT claims and key id |
| `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH` | Paths to the RS256 keypair (default `keys/`) |
| `REFRESH_TOKEN_TTL` / `REFRESH_TOKEN_REUSE_INTERVAL` | Refresh lifetime and theft-detection grace window |
| `SESSION_TIMEBOX` / `SESSION_INACTIVITY_TIMEOUT` | Session limits (`0` = disabled) |
| `PASSWORD_MIN_LENGTH` / `DISABLE_SIGNUP` / `MAILER_AUTOCONFIRM` | Password policy and signup behavior |
| `COOKIE_SECURE` / `COOKIE_SAMESITE` | Cookie flags for browser (cookie) mode |
| `SERVICE_ROLE_KEY` | Optional shared secret that grants admin access (in addition to a `service_role` JWT) |

## JWT keys

The RS256 signing keys live in `keys/` and are **git-ignored** — they are **not** in the repository and must be generated on each environment:

```bash
php bin/keygen.php               # refuses to overwrite existing keys; pass --force to rotate
```

Rotating keys invalidates all previously issued JWTs. The public key is served at `/auth/v1/.well-known/jwks.json` for external verifiers.

## Running the service

**Development** — use the built-in server with the front controller as the router script:

```bash
php -S 127.0.0.1:8080 public/index.php
curl http://127.0.0.1:8080/auth/v1/health
```

> Run it as `php -S … public/index.php` (router-script mode), **not** `-t public`. In document-root mode PHP's built-in server 404s paths beginning with a dot (e.g. `/.well-known/jwks.json`). This quirk does not affect nginx/Apache.

**Production** — serve `public/index.php` as the front controller behind **PHP-FPM + nginx/Apache**, with only `public/` web-exposed. All routes are under the base path `/auth/v1`.

## Testing

```bash
vendor/bin/phpunit                       # full suite (unit + integration)
vendor/bin/phpunit --testsuite unit      # unit tests only (no DB)
vendor/bin/phpunit --filter SomeTest     # a single test
```

Integration tests run against `TEST_DB_NAME` (never the dev DB — selected by `APP_ENV=testing`, which `phpunit.xml` sets). `tests/bootstrap.php` migrates the test database once per run, and each test executes inside a rolled-back transaction, so the suite is self-cleaning.

## Project layout

```
public/index.php     Front controller (only web-exposed file)
src/
  Http/              Router, Request/Response, middleware, TokenResponder, presenters
  Controllers/       Signup, Token, Logout, User, Recover, Admin, Meta
  Services/          AuthService, TokenService, SessionService
  Repositories/      One per auth table (PDO)
  Security/          Jwt, Csrf, Password, RateLimiter, TokenHash, Jwks
  Support/           Config, Env, Database, Migrator, EmailNormalizer
  Exceptions/
bin/                 keygen.php, migrate.php, issue-service-token.php
migrations/          Versioned SQL (schema in the `auth` schema)
config/              config.php, ratelimits.php
tests/               Unit + Integration
docs/plans/          Design doc + implementation plan
keys/                JWT keys (git-ignored; generate with bin/keygen.php)
```

## Before exposing to production

The Phase 1 defaults are tuned for local development. Flip these before a real deployment:

- **`COOKIE_SECURE=true`** — cookies must only travel over HTTPS.
- **`MAILER_AUTOCONFIRM=false`** — once email confirmation (Phase 2) is available; this also closes a residual signup-enumeration gap.
- **`SERVICE_ROLE_KEY`** — set a strong secret (or rely solely on `service_role` JWTs). An empty value disables the header path (fails closed).
- **Add an `HSTS` header** and serve everything over TLS.
- **Trusted-proxy hardening** — `Request::clientIp()` currently trusts the first hop of `X-Forwarded-For`. Behind a proxy/load balancer, restrict this to a configured trusted-proxy allowlist before relying on IP-based rate limiting or audit IPs. (Tracked as the top pre-production task.)
- Provision a **service token** for admin API access with `php bin/issue-service-token.php` (dev helper; treat the output as a secret).
