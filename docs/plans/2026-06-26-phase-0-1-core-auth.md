# Maludb Auth — Phase 0 + Phase 1 (Skeleton + Core Auth) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> Also use superpowers:test-driven-development (red→green→refactor) and the `php-session-auth` skill for the security primitives.

**Goal:** Stand up the PHP/Postgres auth service skeleton (Phase 0) and the complete email+password authentication core with dual-mode (Bearer + cookie/CSRF) JWT sessions, refresh-token rotation with theft detection, rate limiting, and admin user CRUD (Phase 1).

**Architecture:** Standalone stateless HTTP service. A front controller (`public/index.php`) runs requests through a middleware chain (SecurityHeaders → CORS → RateLimit → AuthContext → CSRF → route handler). Logic lives in `Services/`, SQL in `Repositories/`, security primitives in `Security/`. JWTs are asymmetric (RS256) verified statelessly; refresh tokens and sessions live in Postgres. See the design doc: [docs/plans/2026-06-26-maludb-auth-design.md](2026-06-26-maludb-auth-design.md).

**Tech Stack:** PHP 8.2+, Composer, PDO (pgsql), ext-openssl, ext-sodium, PostgreSQL 14+, PHPUnit 11, `firebase/php-jwt`, `ramsey/uuid`, `vlucas/phpdotenv`.

---

## Conventions for the executing engineer

- **TDD always:** write the failing test, run it, see it fail for the *right* reason, implement minimally, see it pass, commit. One logical change per commit.
- **Two test suites:** `tests/Unit/` (no DB, pure logic) and `tests/Integration/` (real test Postgres + full HTTP stack). Integration tests run each test in a transaction that is rolled back in `tearDown()`.
- **No `$_SESSION` anywhere.** Sessions are our `auth.sessions` rows.
- **Exact namespaces:** root namespace is `Maludb\Auth\` mapped to `src/` (PSR-4).
- **Run tests:** `vendor/bin/phpunit` (all), or `vendor/bin/phpunit --filter testName` (one).
- **Commit prefix:** `feat:`, `test:`, `chore:`, `fix:`.

---

# PHASE 0 — SKELETON

## Task 1: Composer project + autoload

**Files:**
- Create: `composer.json`
- Create: `src/.gitkeep`, `tests/.gitkeep`

**Step 1:** Create `composer.json`:
```json
{
    "name": "maludb/auth",
    "description": "Maludb Auth — Supabase-compatible auth service (PHP reference implementation)",
    "type": "project",
    "require": {
        "php": ">=8.2",
        "ext-pdo": "*",
        "ext-openssl": "*",
        "ext-sodium": "*",
        "firebase/php-jwt": "^6.10",
        "ramsey/uuid": "^4.7",
        "vlucas/phpdotenv": "^5.6"
    },
    "require-dev": {
        "phpunit/phpunit": "^11.0"
    },
    "autoload": {
        "psr-4": { "Maludb\\Auth\\": "src/" }
    },
    "autoload-dev": {
        "psr-4": { "Maludb\\Auth\\Tests\\": "tests/" }
    },
    "config": { "sort-packages": true },
    "minimum-stability": "stable"
}
```

**Step 2:** Run `composer install`. Expected: creates `vendor/` and `composer.lock`.

**Step 3:** Create `phpunit.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="vendor/phpunit/phpunit/phpunit.xsd"
         bootstrap="vendor/autoload.php"
         colors="true"
         cacheDirectory=".phpunit.cache">
    <testsuites>
        <testsuite name="unit"><directory>tests/Unit</directory></testsuite>
        <testsuite name="integration"><directory>tests/Integration</directory></testsuite>
    </testsuites>
    <php>
        <env name="APP_ENV" value="testing"/>
    </php>
</phpunit>
```

**Step 4:** Verify `vendor/bin/phpunit --version` runs.

**Step 5:** Commit:
```bash
git add composer.json composer.lock phpunit.xml src tests
git commit -m "chore: composer project scaffold + phpunit"
```

---

## Task 2: Config loader

**Files:**
- Create: `src/Support/Config.php`
- Create: `.env.example`
- Test: `tests/Unit/Support/ConfigTest.php`

**Step 1: Failing test** — `tests/Unit/Support/ConfigTest.php`:
```php
<?php
namespace Maludb\Auth\Tests\Unit\Support;

use Maludb\Auth\Support\Config;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function test_get_returns_value_with_dot_notation(): void
    {
        $c = new Config(['jwt' => ['exp' => 3600]]);
        $this->assertSame(3600, $c->get('jwt.exp'));
    }

    public function test_get_returns_default_when_missing(): void
    {
        $c = new Config([]);
        $this->assertSame('fallback', $c->get('nope.here', 'fallback'));
    }
}
```

**Step 2:** Run `vendor/bin/phpunit --filter ConfigTest`. Expected: FAIL (class not found).

**Step 3: Implement** — `src/Support/Config.php`:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

final class Config
{
    public function __construct(private array $items = []) {}

    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->items;
        foreach (explode('.', $key) as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return $default;
            }
            $value = $value[$segment];
        }
        return $value;
    }
}
```

**Step 4:** Run the test. Expected: PASS.

**Step 5:** Create `.env.example` (full env contract; copy to `.env` locally):
```ini
APP_ENV=local
APP_URL=http://localhost:8080
SITE_URL=http://localhost:3000
URI_ALLOW_LIST=http://localhost:3000/*

DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=maludb_auth
DB_USER=postgres
DB_PASSWORD=postgres

# Integration test DB (must be a throwaway database)
TEST_DB_NAME=maludb_auth_test

JWT_ISSUER=http://localhost:8080/auth/v1
JWT_AUDIENCE=authenticated
JWT_EXP=3600
JWT_PRIVATE_KEY_PATH=keys/jwt_private.pem
JWT_PUBLIC_KEY_PATH=keys/jwt_public.pem
JWT_KID=key-1

REFRESH_TOKEN_TTL=2592000          # 30 days (inactivity window)
REFRESH_TOKEN_REUSE_INTERVAL=10    # seconds
SESSION_TIMEBOX=0                   # 0 = disabled (absolute max lifetime in seconds)
SESSION_INACTIVITY_TIMEOUT=0       # 0 = disabled

PASSWORD_MIN_LENGTH=12
DISABLE_SIGNUP=false
MAILER_AUTOCONFIRM=true            # skip email confirmation until Phase 2 mailer exists

COOKIE_SECURE=false                # true in prod
COOKIE_SAMESITE=Lax
```

**Step 6:** Commit:
```bash
git add src/Support/Config.php tests/Unit/Support/ConfigTest.php .env.example
git commit -m "feat: dot-notation config loader + env contract"
```

---

## Task 3: Environment bootstrap → Config factory

**Files:**
- Create: `src/Support/Env.php`
- Create: `config/config.php`

**Step 1:** `src/Support/Env.php` loads `.env` via phpdotenv (safe-load, no overwrite of real env) and exposes typed helpers:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

use Dotenv\Dotenv;

final class Env
{
    public static function load(string $basePath): void
    {
        if (is_file($basePath . '/.env')) {
            Dotenv::createImmutable($basePath)->safeLoad();
        }
    }

    public static function get(string $key, ?string $default = null): ?string
    {
        $v = $_ENV[$key] ?? getenv($key);
        return $v === false ? $default : ($v ?? $default);
    }

    public static function bool(string $key, bool $default = false): bool
    {
        $v = self::get($key);
        return $v === null ? $default : in_array(strtolower($v), ['1','true','yes','on'], true);
    }

    public static function int(string $key, int $default = 0): int
    {
        $v = self::get($key);
        return $v === null ? $default : (int) $v;
    }
}
```

**Step 2:** `config/config.php` returns a nested array consumed by `Config` (maps env → structured config). Include `db`, `jwt`, `refresh`, `session`, `password`, `signup`, `cookie`, `site` sections. Example:
```php
<?php
use Maludb\Auth\Support\Env;

return [
    'app' => ['env' => Env::get('APP_ENV', 'local'), 'url' => Env::get('APP_URL')],
    'site' => [
        'url' => Env::get('SITE_URL'),
        'uri_allow_list' => array_filter(explode(',', Env::get('URI_ALLOW_LIST', ''))),
    ],
    'db' => [
        'host' => Env::get('DB_HOST', '127.0.0.1'),
        'port' => Env::int('DB_PORT', 5432),
        'name' => Env::get('APP_ENV') === 'testing' ? Env::get('TEST_DB_NAME') : Env::get('DB_NAME'),
        'user' => Env::get('DB_USER'),
        'password' => Env::get('DB_PASSWORD'),
    ],
    'jwt' => [
        'issuer' => Env::get('JWT_ISSUER'),
        'audience' => Env::get('JWT_AUDIENCE', 'authenticated'),
        'exp' => Env::int('JWT_EXP', 3600),
        'private_key_path' => Env::get('JWT_PRIVATE_KEY_PATH', 'keys/jwt_private.pem'),
        'public_key_path' => Env::get('JWT_PUBLIC_KEY_PATH', 'keys/jwt_public.pem'),
        'kid' => Env::get('JWT_KID', 'key-1'),
    ],
    'refresh' => [
        'ttl' => Env::int('REFRESH_TOKEN_TTL', 2592000),
        'reuse_interval' => Env::int('REFRESH_TOKEN_REUSE_INTERVAL', 10),
    ],
    'session' => [
        'timebox' => Env::int('SESSION_TIMEBOX', 0),
        'inactivity_timeout' => Env::int('SESSION_INACTIVITY_TIMEOUT', 0),
    ],
    'password' => ['min_length' => Env::int('PASSWORD_MIN_LENGTH', 12)],
    'signup' => [
        'disabled' => Env::bool('DISABLE_SIGNUP', false),
        'autoconfirm' => Env::bool('MAILER_AUTOCONFIRM', true),
    ],
    'cookie' => [
        'secure' => Env::bool('COOKIE_SECURE', false),
        'samesite' => Env::get('COOKIE_SAMESITE', 'Lax'),
    ],
];
```

**Step 3:** No dedicated test (config wiring). Sanity-run: `php -r "require 'vendor/autoload.php'; \Maludb\Auth\Support\Env::load(getcwd()); var_dump((require 'config/config.php')['jwt']['exp']);"` → prints `int(3600)`.

**Step 4:** Commit:
```bash
git add src/Support/Env.php config/config.php
git commit -m "feat: env bootstrap and structured config factory"
```

---

## Task 4: HTTP Request value object

**Files:**
- Create: `src/Http/Request.php`
- Test: `tests/Unit/Http/RequestTest.php`

**Step 1: Failing test:**
```php
<?php
namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\Request;
use PHPUnit\Framework\TestCase;

final class RequestTest extends TestCase
{
    public function test_parses_method_path_query_json_body_headers(): void
    {
        $r = new Request(
            method: 'POST',
            path: '/auth/v1/signup',
            query: ['cookie' => 'true'],
            headers: ['Authorization' => 'Bearer abc', 'X-CSRF-Token' => 'tok'],
            rawBody: '{"email":"A@x.com","password":"secret"}',
            cookies: ['mb-access-token' => 'jwt'],
            ip: '203.0.113.5'
        );

        $this->assertSame('POST', $r->method);
        $this->assertSame('/auth/v1/signup', $r->path);
        $this->assertSame('true', $r->query('cookie'));
        $this->assertSame('A@x.com', $r->input('email'));
        $this->assertSame('Bearer abc', $r->header('Authorization'));
        $this->assertSame('tok', $r->header('x-csrf-token')); // case-insensitive
        $this->assertSame('jwt', $r->cookie('mb-access-token'));
        $this->assertTrue($r->wantsCookies());
        $this->assertSame('abc', $r->bearerToken());
    }
}
```

**Step 2:** Run → FAIL.

**Step 3: Implement** `src/Http/Request.php`:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

final class Request
{
    private array $headersLower;
    private array $body;

    public function __construct(
        public readonly string $method,
        public readonly string $path,
        private array $query = [],
        array $headers = [],
        public readonly string $rawBody = '',
        private array $cookies = [],
        public readonly string $ip = '',
    ) {
        $this->headersLower = [];
        foreach ($headers as $k => $v) {
            $this->headersLower[strtolower($k)] = $v;
        }
        $decoded = json_decode($rawBody, true);
        $this->body = is_array($decoded) ? $decoded : [];
    }

    public static function fromGlobals(): self
    {
        $headers = function_exists('getallheaders') ? getallheaders() : [];
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
        return new self(
            method: $_SERVER['REQUEST_METHOD'] ?? 'GET',
            path: $path,
            query: $_GET,
            headers: $headers,
            rawBody: file_get_contents('php://input') ?: '',
            cookies: $_COOKIE,
            ip: self::clientIp(),
        );
    }

    private static function clientIp(): string
    {
        // Trust X-Forwarded-For only behind a known proxy in prod; here take first hop.
        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff !== '') return trim(explode(',', $xff)[0]);
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    public function query(string $k, ?string $default = null): ?string
    { return isset($this->query[$k]) ? (string) $this->query[$k] : $default; }

    public function input(string $k, mixed $default = null): mixed
    { return $this->body[$k] ?? $default; }

    public function allInput(): array { return $this->body; }

    public function header(string $k, ?string $default = null): ?string
    { return $this->headersLower[strtolower($k)] ?? $default; }

    public function cookie(string $k, ?string $default = null): ?string
    { return $this->cookies[$k] ?? $default; }

    public function bearerToken(): ?string
    {
        $h = $this->header('authorization', '');
        return (stripos($h, 'bearer ') === 0) ? substr($h, 7) : null;
    }

    public function wantsCookies(): bool { return $this->query('cookie') === 'true'; }

    public function isUnsafeMethod(): bool
    { return in_array($this->method, ['POST','PUT','PATCH','DELETE'], true); }
}
```

**Step 4:** Run → PASS.

**Step 5:** Commit:
```bash
git add src/Http/Request.php tests/Unit/Http/RequestTest.php
git commit -m "feat: HTTP Request value object"
```

---

## Task 5: HTTP Response + JSON helpers

**Files:**
- Create: `src/Http/Response.php`
- Test: `tests/Unit/Http/ResponseTest.php`

**Step 1: Failing test:** assert `Response::json(['a'=>1], 201)` yields status 201, `Content-Type: application/json`, body `{"a":1}`; assert `withHeader`, `withCookie`, and `withClearedCookie` accumulate correctly; assert a `redirect($url)` produces 302 + `Location`.

```php
<?php
namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\Response;
use PHPUnit\Framework\TestCase;

final class ResponseTest extends TestCase
{
    public function test_json_response(): void
    {
        $r = Response::json(['a' => 1], 201)->withHeader('X-Test', 'y');
        $this->assertSame(201, $r->status);
        $this->assertSame('{"a":1}', $r->body);
        $this->assertSame('application/json', $r->headers['Content-Type']);
        $this->assertSame('y', $r->headers['X-Test']);
    }

    public function test_cookie_set_and_clear(): void
    {
        $r = Response::json([])
            ->withCookie('mb-access-token', 'jwt', ['httponly' => true, 'path' => '/'])
            ->withClearedCookie('mb-refresh-token', '/auth/v1/token');
        $this->assertCount(2, $r->cookies);
        $this->assertSame('jwt', $r->cookies[0]['value']);
        $this->assertSame('', $r->cookies[1]['value']);
        $this->assertSame(0, $r->cookies[1]['options']['expires']); // cleared
    }
}
```

**Step 2:** Run → FAIL.

**Step 3: Implement** `src/Http/Response.php`:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

final class Response
{
    /** @param array<string,string> $headers */
    public function __construct(
        public int $status = 200,
        public string $body = '',
        public array $headers = [],
        public array $cookies = [],
    ) {}

    public static function json(mixed $data, int $status = 200): self
    {
        return new self(
            status: $status,
            body: json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
            headers: ['Content-Type' => 'application/json'],
        );
    }

    public static function error(string $code, string $message, int $status): self
    {
        return self::json(['error' => $code, 'error_description' => $message], $status);
    }

    public static function redirect(string $url, int $status = 302): self
    {
        return new self(status: $status, headers: ['Location' => $url]);
    }

    public function withHeader(string $k, string $v): self
    {
        $this->headers[$k] = $v;
        return $this;
    }

    public function withCookie(string $name, string $value, array $options = []): self
    {
        $this->cookies[] = ['name' => $name, 'value' => $value, 'options' => $options + [
            'expires' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax', 'secure' => false,
        ]];
        return $this;
    }

    public function withClearedCookie(string $name, string $path = '/'): self
    {
        return $this->withCookie($name, '', ['expires' => 0, 'path' => $path, 'maxage' => -1]);
    }

    /** Pure, unit-testable cookie-expiry resolution (avoids the `??`/`===` precedence trap). */
    public static function resolveCookieExpiry(array $o): int
    {
        $maxage = $o['maxage'] ?? null;
        if ($maxage !== null) {
            return $maxage < 0 ? 1 : time() + $maxage; // <0 => epoch-past => browser deletes
        }
        return $o['expires'] ?? 0; // 0 => session cookie
    }

    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $k => $v) {
            header("$k: $v");
        }
        foreach ($this->cookies as $c) {
            $o = $c['options'];
            setcookie($c['name'], $c['value'], [
                'expires' => self::resolveCookieExpiry($o),
                'path' => $o['path'], 'secure' => $o['secure'], 'httponly' => $o['httponly'],
                'samesite' => $o['samesite'],
            ]);
        }
        echo $this->body;
    }
}
```
> Note: keep `send()` thin; integration tests assert on the `Response` object, not on emitted headers.

**Step 4:** Run → PASS.

**Step 5:** Commit.

---

## Task 6: Router + middleware chain

**Files:**
- Create: `src/Http/Router.php`
- Create: `src/Http/Middleware/MiddlewareInterface.php`
- Test: `tests/Unit/Http/RouterTest.php`

**Step 1: Failing test:** register `GET /health` → handler returning `Response::json(['ok'=>true])`; dispatch a matching Request → 200; dispatch unknown path → 404; assert a middleware can short-circuit (return a Response without calling `$next`) and that path params (`/admin/users/{id}`) are extracted.

```php
<?php
namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\{Router, Request, Response};
use PHPUnit\Framework\TestCase;

final class RouterTest extends TestCase
{
    private function req(string $m, string $p): Request
    { return new Request(method: $m, path: $p); }

    public function test_matches_and_dispatches(): void
    {
        $router = new Router();
        $router->add('GET', '/health', fn(Request $r) => Response::json(['ok' => true]));
        $res = $router->dispatch($this->req('GET', '/health'));
        $this->assertSame(200, $res->status);
    }

    public function test_unknown_route_returns_404(): void
    {
        $res = (new Router())->dispatch($this->req('GET', '/nope'));
        $this->assertSame(404, $res->status);
    }

    public function test_path_params_extracted(): void
    {
        $router = new Router();
        $router->add('GET', '/admin/users/{id}',
            fn(Request $r, array $p) => Response::json(['id' => $p['id']]));
        $res = $router->dispatch($this->req('GET', '/admin/users/42'));
        $this->assertSame('{"id":"42"}', $res->body);
    }

    public function test_middleware_short_circuits(): void
    {
        $router = new Router();
        $router->add('GET', '/x', fn() => Response::json(['reached' => true]));
        $router->middleware(new class implements \Maludb\Auth\Http\Middleware\MiddlewareInterface {
            public function handle(Request $r, callable $next): Response
            { return Response::error('blocked', 'no', 403); }
        });
        $res = $router->dispatch($this->req('GET', '/x'));
        $this->assertSame(403, $res->status);
    }
}
```

**Step 2:** Run → FAIL.

**Step 3: Implement** `src/Http/Middleware/MiddlewareInterface.php`:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Http\Middleware;

use Maludb\Auth\Http\{Request, Response};

interface MiddlewareInterface
{
    public function handle(Request $request, callable $next): Response;
}
```

`src/Http/Router.php`:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

use Maludb\Auth\Http\Middleware\MiddlewareInterface;

final class Router
{
    private array $routes = [];
    /** @var MiddlewareInterface[] */
    private array $middleware = [];

    public function add(string $method, string $path, callable $handler): void
    {
        $pattern = '#^' . preg_replace('#\{(\w+)\}#', '(?P<$1>[^/]+)', $path) . '$#';
        $this->routes[] = compact('method', 'pattern', 'handler');
    }

    public function middleware(MiddlewareInterface $m): void { $this->middleware[] = $m; }

    public function dispatch(Request $request): Response
    {
        $core = function (Request $req): Response {
            foreach ($this->routes as $route) {
                if ($route['method'] !== $req->method) continue;
                if (preg_match($route['pattern'], $req->path, $m)) {
                    $params = array_map('rawurldecode', array_filter($m, 'is_string', ARRAY_FILTER_USE_KEY));
                    return ($route['handler'])($req, $params);
                }
            }
            return Response::error('not_found', 'No route matched.', 404);
        };

        $chain = array_reduce(
            array_reverse($this->middleware),
            fn(callable $next, MiddlewareInterface $mw) =>
                fn(Request $req) => $mw->handle($req, $next),
            $core
        );
        return $chain($request);
    }
}
```

**Step 4:** Run → PASS.

**Step 5:** Commit.

---

## Task 7: PDO database connection

**Files:**
- Create: `src/Support/Database.php`
- Test: `tests/Integration/DatabaseTest.php`
- Create: `tests/Integration/IntegrationTestCase.php`

**Pre-req for the engineer:** create the test database once:
`createdb maludb_auth_test` (or via psql). Ensure `.env` has `TEST_DB_NAME=maludb_auth_test`.

**Step 1:** `tests/Integration/IntegrationTestCase.php` — base class that boots config in testing mode, opens a PDO connection, and wraps each test in a rolled-back transaction:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Support\{Config, Database, Env};
use PHPUnit\Framework\TestCase;
use PDO;

abstract class IntegrationTestCase extends TestCase
{
    protected static PDO $pdo;
    protected Config $config;

    public static function setUpBeforeClass(): void
    {
        $base = dirname(__DIR__, 2);
        Env::load($base);
        $_ENV['APP_ENV'] = 'testing';
        putenv('APP_ENV=testing');
        $config = new Config(require $base . '/config/config.php');
        self::$pdo = (new Database($config))->connection();
    }

    protected function setUp(): void
    {
        $base = dirname(__DIR__, 2);
        $this->config = new Config(require $base . '/config/config.php');
        self::$pdo->beginTransaction();
    }

    protected function tearDown(): void
    {
        if (self::$pdo->inTransaction()) self::$pdo->rollBack();
    }
}
```

**Step 2:** `tests/Integration/DatabaseTest.php`:
```php
<?php
namespace Maludb\Auth\Tests\Integration;

final class DatabaseTest extends IntegrationTestCase
{
    public function test_connection_runs_a_query(): void
    {
        $stmt = self::$pdo->query('SELECT 1 AS one');
        $this->assertSame('1', (string) $stmt->fetchColumn());
    }
}
```

**Step 3:** Run `vendor/bin/phpunit --filter DatabaseTest`. Expected: FAIL (no `Database`).

**Step 4: Implement** `src/Support/Database.php`:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

use PDO;

final class Database
{
    private ?PDO $pdo = null;

    public function __construct(private Config $config) {}

    public function connection(): PDO
    {
        if ($this->pdo instanceof PDO) return $this->pdo;
        $dsn = sprintf(
            'pgsql:host=%s;port=%d;dbname=%s',
            $this->config->get('db.host'),
            $this->config->get('db.port'),
            $this->config->get('db.name'),
        );
        $this->pdo = new PDO($dsn, $this->config->get('db.user'), $this->config->get('db.password'), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        return $this->pdo;
    }
}
```

**Step 5:** Run → PASS. Commit.

---

## Task 8: Migration runner + `schema_migrations`

**Files:**
- Create: `src/Support/Migrator.php`
- Create: `bin/migrate.php`
- Create: `migrations/0001_create_schema_migrations.sql`
- Test: `tests/Integration/MigratorTest.php`

**Step 1:** First migration `migrations/0001_create_schema_migrations.sql`:
```sql
CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE IF NOT EXISTS auth.schema_migrations (
    version     varchar(255) PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
);
```

**Step 2: Failing test** `tests/Integration/MigratorTest.php`: running the migrator applies pending `.sql` files in lexical order, records each in `auth.schema_migrations`, and is idempotent (second run applies nothing). Use a temp migrations dir fixture or assert `0001` recorded.

```php
<?php
namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Support\Migrator;

final class MigratorTest extends IntegrationTestCase
{
    public function test_applies_and_records_migrations_idempotently(): void
    {
        $dir = dirname(__DIR__, 2) . '/migrations';
        $m = new Migrator(self::$pdo, $dir);
        $applied = $m->run();
        $this->assertContains('0001_create_schema_migrations', $applied);

        $count = (int) self::$pdo
            ->query("SELECT count(*) FROM auth.schema_migrations WHERE version='0001_create_schema_migrations'")
            ->fetchColumn();
        $this->assertSame(1, $count);

        $this->assertSame([], $m->run()); // idempotent
    }
}
```
> Note: this test commits outside the rollback (DDL). Override `setUp`/`tearDown` in this test to NOT use the transaction, OR run migrations as a real setup step. Simplest: in this single test class, skip the parent transaction by overriding `setUp()`/`tearDown()` to no-ops, and `DROP SCHEMA auth CASCADE` in setUp for a clean slate. Document this clearly.

**Step 3:** Run → FAIL.

**Step 4: Implement** `src/Support/Migrator.php`:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

use PDO;

final class Migrator
{
    public function __construct(private PDO $pdo, private string $dir) {}

    /** @return string[] versions applied this run */
    public function run(): array
    {
        $this->ensureTable();
        $applied = $this->appliedVersions();
        $newlyApplied = [];
        foreach ($this->files() as $version => $path) {
            if (in_array($version, $applied, true)) continue;
            $sql = file_get_contents($path);
            $this->pdo->exec($sql);
            $stmt = $this->pdo->prepare('INSERT INTO auth.schema_migrations(version) VALUES(:v)');
            $stmt->execute([':v' => $version]);
            $newlyApplied[] = $version;
        }
        return $newlyApplied;
    }

    private function ensureTable(): void
    {
        $this->pdo->exec('CREATE SCHEMA IF NOT EXISTS auth');
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS auth.schema_migrations (
                version varchar(255) PRIMARY KEY,
                applied_at timestamptz NOT NULL DEFAULT now())'
        );
    }

    private function appliedVersions(): array
    {
        return $this->pdo->query('SELECT version FROM auth.schema_migrations')
            ->fetchAll(PDO::FETCH_COLUMN) ?: [];
    }

    /** @return array<string,string> version => path, sorted */
    private function files(): array
    {
        $out = [];
        foreach (glob($this->dir . '/*.sql') as $path) {
            $out[basename($path, '.sql')] = $path;
        }
        ksort($out);
        return $out;
    }
}
```

`bin/migrate.php`:
```php
<?php
require __DIR__ . '/../vendor/autoload.php';
use Maludb\Auth\Support\{Config, Database, Env, Migrator};

Env::load(dirname(__DIR__));
$config = new Config(require dirname(__DIR__) . '/config/config.php');
$pdo = (new Database($config))->connection();
$applied = (new Migrator($pdo, dirname(__DIR__) . '/migrations'))->run();
echo $applied ? "Applied: " . implode(', ', $applied) . "\n" : "Nothing to apply.\n";
```

**Step 5:** Run test → PASS. Run `php bin/migrate.php` against dev DB → "Applied: 0001...". Commit.

---

## Task 9: JWT keypair generation script

**Files:**
- Create: `bin/keygen.php`

**Step 1:** Implement `bin/keygen.php` (no test — one-shot tooling; verify by output):
```php
<?php
require __DIR__ . '/../vendor/autoload.php';
$dir = dirname(__DIR__) . '/keys';
@mkdir($dir, 0700, true);
$res = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
    'private_key_bits' => 2048,
]);
openssl_pkey_export($res, $privPem);
$pubPem = openssl_pkey_get_details($res)['key'];
file_put_contents("$dir/jwt_private.pem", $privPem);
file_put_contents("$dir/jwt_public.pem", $pubPem);
chmod("$dir/jwt_private.pem", 0600);
echo "Wrote keys/jwt_private.pem and keys/jwt_public.pem\n";
```

**Step 2:** Run `php bin/keygen.php`. Expected: files appear in `keys/` (already gitignored). Verify `openssl rsa -in keys/jwt_private.pem -check -noout` says "RSA key ok".

**Step 3:** Commit (only the script; keys are gitignored):
```bash
git add bin/keygen.php
git commit -m "feat: JWT RSA keypair generation script"
```

---

## Task 10: SecurityHeaders + CORS middleware

**Files:**
- Create: `src/Http/Middleware/SecurityHeaders.php`
- Create: `src/Http/Middleware/Cors.php`
- Test: `tests/Unit/Http/SecurityHeadersTest.php`

**Step 1: Failing test:** after dispatch, response carries `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `X-Content-Type-Options: nosniff`.

**Step 2:** Run → FAIL.

**Step 3: Implement** `SecurityHeaders`:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Http\Middleware;

use Maludb\Auth\Http\{Request, Response};

final class SecurityHeaders implements MiddlewareInterface
{
    public function handle(Request $request, callable $next): Response
    {
        return $next($request)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('X-Frame-Options', 'DENY')
            ->withHeader('Referrer-Policy', 'same-origin')
            ->withHeader('X-Content-Type-Options', 'nosniff');
    }
}
```
`Cors` handles `OPTIONS` preflight (short-circuit 204 with allow headers) and echoes an allowed `Origin` (validated against `SITE_URL`/allow-list) on normal responses; allow `Authorization, Content-Type, X-CSRF-Token`; `Access-Control-Allow-Credentials: true`.

**Step 4:** Run → PASS. Commit.

---

## Task 11: Health, Settings, JWKS endpoints + front controller

**Files:**
- Create: `src/Security/Jwks.php`
- Create: `src/Controllers/MetaController.php`
- Create: `public/index.php`
- Create: `src/App.php` (bootstraps container + router)
- Test: `tests/Integration/MetaEndpointsTest.php`

**Step 1: Failing integration test** — boot the app, dispatch `GET /auth/v1/health` (200, `{"name":"maludb-auth","version":...}`), `GET /auth/v1/settings` (200, lists enabled flows), `GET /auth/v1/.well-known/jwks.json` (200, `keys[0].kty === "RSA"`, has `kid`, `n`, `e`).

```php
<?php
namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\App;
use Maludb\Auth\Http\Request;

final class MetaEndpointsTest extends IntegrationTestCase
{
    public function test_health(): void
    {
        $res = App::boot()->handle(new Request(method: 'GET', path: '/auth/v1/health'));
        $this->assertSame(200, $res->status);
    }

    public function test_jwks_exposes_public_key(): void
    {
        $res = App::boot()->handle(new Request(method: 'GET', path: '/auth/v1/.well-known/jwks.json'));
        $body = json_decode($res->body, true);
        $this->assertSame('RSA', $body['keys'][0]['kty']);
        $this->assertArrayHasKey('kid', $body['keys'][0]);
    }
}
```

**Step 2:** Run → FAIL.

**Step 3: Implement.** `Jwks` reads the public PEM and converts to a JWK (RSA → base64url `n`/`e`; reuse `firebase/php-jwt` helpers or compute from `openssl_pkey_get_details`). `MetaController` returns health/settings/jwks. `App` wires Config, Database, Router (registers Phase-0 routes + middleware) and exposes `handle(Request): Response` and static `boot()`. `public/index.php`:
```php
<?php
require __DIR__ . '/../vendor/autoload.php';
use Maludb\Auth\App;
use Maludb\Auth\Http\Request;
App::boot()->handle(Request::fromGlobals())->send();
```

**Step 4:** Run → PASS. Manually: `php -S 127.0.0.1:8080 -t public` then `curl localhost:8080/auth/v1/health`.

**Step 5:** Commit. **Phase 0 complete** — tag it:
```bash
git tag phase-0-skeleton
```

---

# PHASE 1 — CORE AUTH (email + password, dual-mode, sessions)

## Task 12: Core schema migration

**Files:**
- Create: `migrations/0002_core_auth_tables.sql`
- Test: `tests/Integration/CoreSchemaTest.php`

**Step 1: Failing test:** after migrating, `information_schema` shows tables `auth.users`, `auth.identities`, `auth.sessions`, `auth.refresh_tokens`, `auth.audit_log_entries`, `auth.rate_limits`; assert key columns exist (`users.encrypted_password`, `sessions.csrf_token`, `refresh_tokens.parent`, `refresh_tokens.revoked`).

**Step 2:** Run → FAIL.

**Step 3: Implement** `migrations/0002_core_auth_tables.sql`:
```sql
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
```
> Portability note for future clones: `gen_random_uuid()`, `citext`, and the generated `confirmed_at` column are Postgres-specific; the column list/semantics carry over.

**Step 4:** Run → PASS. Run `php bin/migrate.php`. Commit.

---

## Task 13: Password security primitive

**Files:**
- Create: `src/Security/Password.php`
- Test: `tests/Unit/Security/PasswordTest.php`

**Step 1: Failing test:**
```php
<?php
namespace Maludb\Auth\Tests\Unit\Security;

use Maludb\Auth\Security\Password;
use PHPUnit\Framework\TestCase;

final class PasswordTest extends TestCase
{
    public function test_hash_and_verify_roundtrip(): void
    {
        $p = new Password(minLength: 12);
        $hash = $p->hash('correct horse battery');
        $this->assertTrue($p->verify('correct horse battery', $hash));
        $this->assertFalse($p->verify('wrong', $hash));
    }

    public function test_rejects_short_password(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new Password(12))->hash('short');
    }

    public function test_rejects_over_72_bytes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new Password(12))->hash(str_repeat('a', 73));
    }

    public function test_dummy_hash_has_same_cost_and_never_verifies(): void
    {
        $p = new Password(12);
        $dummy = $p->dummyHash();
        $this->assertFalse($p->verify('anything', $dummy));
        $this->assertStringStartsWith('$2y$', $dummy);
    }
}
```

**Step 2:** Run → FAIL.

**Step 3: Implement** `src/Security/Password.php`:
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

final class Password
{
    public function __construct(private int $minLength = 12) {}

    public function hash(string $password): string
    {
        $this->assertValid($password);
        return password_hash($password, PASSWORD_BCRYPT);
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_BCRYPT);
    }

    /** Precomputed-cost dummy for timing-equalized "user not found" paths. */
    public function dummyHash(): string
    {
        // Constant hash at the same cost as PASSWORD_BCRYPT default (cost 10).
        return '$2y$10$usesomesillystringforsalttocreateaValidBcryptHashHash.K';
    }

    private function assertValid(string $password): void
    {
        if (strlen($password) < $this->minLength) {
            throw new \InvalidArgumentException('Password too short.');
        }
        if (strlen($password) > 72) { // bcrypt truncates past 72 bytes
            throw new \InvalidArgumentException('Password too long (max 72 bytes).');
        }
    }
}
```
> The engineer MUST replace `dummyHash()` with a real bcrypt hash generated at the project's actual cost: run `php -r "echo password_hash('x', PASSWORD_BCRYPT);"` and paste the result. Add a test asserting `password_get_info($p->dummyHash())['options']['cost']` equals the default cost so timing matches real hashes.

**Step 4:** Run → PASS. Commit.

---

## Task 14: JWT sign/verify primitive

**Files:**
- Create: `src/Security/Jwt.php`
- Test: `tests/Unit/Security/JwtTest.php`

**Pre-req:** `php bin/keygen.php` has produced `keys/jwt_private.pem` / `keys/jwt_public.pem`. Tests generate an ephemeral keypair in-test to avoid depending on disk.

**Step 1: Failing test:** sign claims with the private key (RS256, `kid` header), verify with the public key → claims round-trip; tampered token → throws; expired token → throws.

```php
<?php
namespace Maludb\Auth\Tests\Unit\Security;

use Maludb\Auth\Security\Jwt;
use PHPUnit\Framework\TestCase;

final class JwtTest extends TestCase
{
    private function keys(): array
    {
        $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_pkey_export($res, $priv);
        $pub = openssl_pkey_get_details($res)['key'];
        return [$priv, $pub];
    }

    public function test_sign_and_verify_roundtrip(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');
        $token = $jwt->issue(['sub' => 'user-uuid', 'role' => 'authenticated'], 3600);
        $claims = $jwt->verify($token);
        $this->assertSame('user-uuid', $claims['sub']);
        $this->assertSame('iss', $claims['iss']);
        $this->assertSame('aud', $claims['aud']);
        $this->assertArrayHasKey('exp', $claims);
        $this->assertArrayHasKey('jti', $claims);
    }

    public function test_tampered_token_is_rejected(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');
        $token = $jwt->issue(['sub' => 'x'], 3600) . 'tamper';
        $this->expectException(\Firebase\JWT\SignatureInvalidException::class);
        $jwt->verify($token);
    }

    public function test_expired_token_is_rejected(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');
        $token = $jwt->issue(['sub' => 'x'], -10); // already expired
        $this->expectException(\Firebase\JWT\ExpiredException::class);
        $jwt->verify($token);
    }
}
```

**Step 2:** Run → FAIL.

**Step 3: Implement** `src/Security/Jwt.php` (wraps `firebase/php-jwt`):
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

use Firebase\JWT\JWT as FirebaseJwt;
use Firebase\JWT\Key;

final class Jwt
{
    public function __construct(
        private string $privateKeyPem,
        private string $publicKeyPem,
        private string $kid,
        private string $issuer,
        private string $audience,
    ) {}

    /** @param array<string,mixed> $claims */
    public function issue(array $claims, int $ttlSeconds): string
    {
        $now = time();
        $payload = array_merge([
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'iat' => $now,
            'exp' => $now + $ttlSeconds,
            'jti' => bin2hex(random_bytes(16)),
        ], $claims);
        return FirebaseJwt::encode($payload, $this->privateKeyPem, 'RS256', $this->kid);
    }

    /** @return array<string,mixed> */
    public function verify(string $token): array
    {
        $decoded = FirebaseJwt::decode($token, new Key($this->publicKeyPem, 'RS256'));
        return json_decode(json_encode($decoded), true);
    }
}
```

**Step 4:** Run → PASS. Commit.

---

## Task 15: CSRF token primitive

**Files:**
- Create: `src/Security/Csrf.php`
- Test: `tests/Unit/Security/CsrfTest.php`

**Step 1: Failing test:** `generate()` returns 64 hex chars; `matches($a, $b)` uses constant-time compare and returns true only on exact match; empty/short tokens never match.

**Step 2:** Run → FAIL.

**Step 3: Implement:**
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

final class Csrf
{
    public function generate(): string
    {
        return bin2hex(random_bytes(32)); // 64 hex chars
    }

    public function matches(string $expected, string $provided): bool
    {
        if ($expected === '' || $provided === '') return false;
        return hash_equals($expected, $provided);
    }
}
```

**Step 4:** Run → PASS. Commit.

---

## Task 16: Opaque token + hashing helper (refresh & one-time tokens)

**Files:**
- Create: `src/Security/TokenHash.php`
- Test: `tests/Unit/Security/TokenHashTest.php`

**Step 1: Failing test:** `random()` returns a long URL-safe string; `hash($t)` is deterministic 64-hex SHA-256; different inputs → different hashes.

**Step 3: Implement:**
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

final class TokenHash
{
    public function random(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    public function hash(string $token): string
    {
        return hash('sha256', $token); // store this; compare incoming by re-hashing
    }
}
```

**Step 4:** Run → PASS. Commit.

---

## Task 17: Rate limiter (token-bucket in Postgres)

**Files:**
- Create: `src/Security/RateLimiter.php`
- Test: `tests/Integration/RateLimiterTest.php`

**Step 1: Failing integration test:** with capacity 3 / refill 0, first 3 `attempt($key)` return true, 4th returns false; distinct keys are independent.

```php
<?php
namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Security\RateLimiter;

final class RateLimiterTest extends IntegrationTestCase
{
    public function test_blocks_after_capacity(): void
    {
        $rl = new RateLimiter(self::$pdo);
        $key = 'login:ip:203.0.113.9';
        $this->assertTrue($rl->attempt($key, capacity: 3, refillPerSecond: 0.0));
        $this->assertTrue($rl->attempt($key, 3, 0.0));
        $this->assertTrue($rl->attempt($key, 3, 0.0));
        $this->assertFalse($rl->attempt($key, 3, 0.0)); // 4th blocked
    }
}
```

**Step 2:** Run → FAIL.

**Step 3: Implement** `src/Security/RateLimiter.php` — atomic upsert with token-bucket math (`tokens = min(capacity, tokens + elapsed*refill) - 1`; allow if result ≥ 0). Use `INSERT ... ON CONFLICT ... DO UPDATE` returning the new token count; one round-trip.
```php
<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

use PDO;

final class RateLimiter
{
    public function __construct(private PDO $pdo) {}

    public function attempt(string $key, int $capacity, float $refillPerSecond): bool
    {
        $sql = <<<SQL
        INSERT INTO auth.rate_limits (bucket_key, tokens, updated_at)
        VALUES (:k, :cap - 1, now())
        ON CONFLICT (bucket_key) DO UPDATE SET
            tokens = LEAST(:cap,
                auth.rate_limits.tokens
                + EXTRACT(EPOCH FROM (now() - auth.rate_limits.updated_at)) * :refill
            ) - 1,
            updated_at = now()
        RETURNING tokens
        SQL;
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':k' => $key, ':cap' => $capacity, ':refill' => $refillPerSecond]);
        return ((float) $stmt->fetchColumn()) >= 0.0;
    }
}
```

**Step 4:** Run → PASS. Commit.

---

## Task 18: User repository

**Files:**
- Create: `src/Repositories/UserRepository.php`
- Create: `src/Support/EmailNormalizer.php`
- Test: `tests/Integration/UserRepositoryTest.php`, `tests/Unit/Support/EmailNormalizerTest.php`

**Step 1 (unit):** `EmailNormalizer::normalize(' User@X.com ') === 'user@x.com'`.
**Implement:**
```php
<?php
declare(strict_types=1);
namespace Maludb\Auth\Support;
final class EmailNormalizer
{
    public static function normalize(string $email): string
    { return strtolower(trim($email)); }
}
```

**Step 2 (integration) Failing test:** `create()` inserts a user (normalized email), returns row with `id`; `findByEmail()` finds it case-insensitively; duplicate email → throws a `DuplicateEmailException` (catch SQLSTATE 23505); `findById()` works; `markEmailConfirmed()` sets timestamp.

**Step 3: Implement** `UserRepository` with prepared statements. Key methods: `create(array $attrs): array`, `findByEmail(string): ?array`, `findById(string): ?array`, `update(string $id, array $attrs): array`, `markEmailConfirmed(string $id): void`, `setLastSignInAt(string $id): void`, `list(int $page, int $perPage): array`, `softDelete(string $id): void`. Wrap insert/update in try/catch for `SQLSTATE[23505]` → throw `Maludb\Auth\Exceptions\DuplicateEmailException`. Always normalize email via `EmailNormalizer` before insert/lookup. Store metadata as JSON (`json_encode`).

**Step 4:** Run → PASS. Commit. (Create `src/Exceptions/DuplicateEmailException.php` extending `\RuntimeException`.)

---

## Task 19: Session + RefreshToken repositories

**Files:**
- Create: `src/Repositories/SessionRepository.php`
- Create: `src/Repositories/RefreshTokenRepository.php`
- Test: `tests/Integration/SessionRepositoryTest.php`

**Step 1: Failing tests:**
- `SessionRepository::create($userId, $csrfToken, $ip, $ua, $notAfter)` inserts and returns the row (with `aal='aal1'`).
- `find($id)`, `touchRefreshedAt($id)`, `updateCsrfToken($id, $new)`, `updateAal($id, 'aal2', $factorId)`, `delete($id)`, `deleteAllForUser($userId)`, `deleteOthersForUser($userId, $keepId)`.
- `RefreshTokenRepository::issue($sessionId, $userId, $tokenHash, $parent=null)` inserts unrevoked; `findByHash($hash)`; `revoke($id)`; `revokeAllForSession($sessionId)`; `findActiveBySession($sessionId)`.

**Step 3: Implement** both repositories with prepared statements (straightforward CRUD; follow the UserRepository pattern). Ensure timestamps comparisons use Postgres `now()`.

**Step 4:** Run → PASS. Commit.

---

## Task 20: Audit repository

**Files:**
- Create: `src/Repositories/AuditRepository.php`
- Test: `tests/Integration/AuditRepositoryTest.php`

**Step 1: Failing test:** `record($action, array $payload, $ip)` inserts a row with `payload->>'action'` equal to action; `recent($limit)` returns it.

**Step 3: Implement:** single `INSERT` with `json_encode(['action' => $action] + $payload)`. Commit after green.

---

## Task 21: TokenService — issue session, access + refresh, rotation, theft detection

**Files:**
- Create: `src/Services/TokenService.php`
- Create: `src/Dto/IssuedTokens.php`
- Test: `tests/Integration/TokenServiceTest.php`

This is the **heart of Phase 1.** Test-drive each behavior separately.

**Step 1a: Failing test — issue a new session:**
```php
public function test_issue_creates_session_access_and_refresh(): void
{
    $svc = $this->tokenService();            // helper builds service with real repos + in-test keypair
    $user = $this->createUser();             // helper inserts a confirmed user
    $issued = $svc->issueForUser($user, ip: '203.0.113.1', userAgent: 'phpunit', aal: 'aal1', amr: ['password']);

    $this->assertNotEmpty($issued->accessToken);
    $this->assertNotEmpty($issued->refreshToken);
    $this->assertNotEmpty($issued->csrfToken);
    $claims = $this->jwt()->verify($issued->accessToken);
    $this->assertSame($user['id'], $claims['sub']);
    $this->assertSame('aal1', $claims['aal']);
    $this->assertSame($issued->sessionId, $claims['session_id']);
}
```

**Step 1b: Failing test — refresh rotates the token (old revoked, new chained):**
```php
public function test_refresh_rotates_and_revokes_old(): void
{
    $svc = $this->tokenService();
    $user = $this->createUser();
    $first = $svc->issueForUser($user, '203.0.113.1', 'ua', 'aal1', ['password']);

    $second = $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');
    $this->assertNotSame($first->refreshToken, $second->refreshToken);

    // old token now revoked → reusing it (outside reuse interval) triggers theft handling
    $this->expectException(\Maludb\Auth\Exceptions\RefreshTokenReuseException::class);
    $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');
}
```

**Step 1c: Failing test — theft detection revokes the whole session family:**
```php
public function test_reuse_revokes_entire_session(): void
{
    $svc = $this->tokenService();
    $user = $this->createUser();
    $first = $svc->issueForUser($user, '203.0.113.1', 'ua', 'aal1', ['password']);
    $second = $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');

    try { $svc->refresh($first->refreshToken, '203.0.113.1', 'ua'); } catch (\Throwable) {}

    // the legitimately-rotated token is now also dead
    $this->expectException(\Maludb\Auth\Exceptions\RefreshTokenReuseException::class);
    $svc->refresh($second->refreshToken, '203.0.113.1', 'ua');
}
```

**Step 2:** Run → FAIL.

**Step 3: Implement** `src/Dto/IssuedTokens.php` (readonly DTO: `accessToken`, `refreshToken`, `csrfToken`, `sessionId`, `expiresIn`, `user`) and `src/Services/TokenService.php`:

Behaviors:
- `issueForUser(array $user, string $ip, string $userAgent, string $aal, array $amr): IssuedTokens`
  1. generate `csrfToken` (Csrf), compute `not_after` from config timebox (or null).
  2. `SessionRepository::create(...)`.
  3. generate refresh token (`TokenHash::random()`), store hash via `RefreshTokenRepository::issue(...)`.
  4. build access-token claims from user + session (`sub`, `email`, `role`, `aud`, `app_metadata`, `user_metadata`, `aal`, `amr`, `session_id`, `is_anonymous`), `Jwt::issue(..., config jwt.exp)`.
  5. return DTO.
- `refresh(string $refreshToken, string $ip, string $ua): IssuedTokens`
  1. `findByHash(hash(token))`; if none → `InvalidRefreshTokenException`.
  2. **if `revoked`**: this is reuse → `RefreshTokenRepository::revokeAllForSession(session_id)`; audit `refresh_token_reuse_detected`; throw `RefreshTokenReuseException`. (Reuse-interval grace: if `updated_at` within `refresh.reuse_interval` seconds AND a newer active token exists for the session, return the current active token instead of throwing — implement after the basic path is green; add a test for the grace window.)
  3. load session; run `SessionService::assertValid(session)` (Task 22). If invalid → revoke session, throw.
  4. rotate: `revoke(old.id)`; new refresh token with `parent = old.token_hash`, same session; `touchRefreshedAt(session)`; re-issue access token; return DTO (csrf stays the session's existing token).
- Inject: `UserRepository` (reload user for claims), `SessionRepository`, `RefreshTokenRepository`, `AuditRepository`, `Jwt`, `Csrf`, `TokenHash`, `Config`.

Create exceptions `InvalidRefreshTokenException`, `RefreshTokenReuseException` under `src/Exceptions/`.

**Step 4:** Run all three tests → PASS. Then add the grace-window test and implement it → PASS.

**Step 5:** Commit.

---

## Task 22: SessionService — validity rules

**Files:**
- Create: `src/Services/SessionService.php`
- Test: `tests/Unit/Services/SessionValidityTest.php`

**Step 1: Failing test (pure logic, pass arrays + a fixed "now"):** returns `SessionValid` normally; `SessionPastNotAfter` when `now > not_after`; `SessionPastTimebox` when `now > created_at + timebox`; `SessionTimedOut` when `now > refreshed_at + inactivity_timeout`; timebox/inactivity of 0 disables those checks.

**Step 3: Implement** an enum `SessionValidity` and `SessionService::checkValidity(array $session, int $now, array $cfg): SessionValidity`. Keep it pure/static-friendly so it's trivially portable. Have `assertValid()` throw `SessionExpiredException` on any non-valid result.

**Step 4:** Run → PASS. Commit.

---

## Task 23: AuthService — signup & password login

**Files:**
- Create: `src/Services/AuthService.php`
- Test: `tests/Integration/AuthServiceTest.php`

**Step 1: Failing tests:**
- `signup(email, password, ip)` creates a user + `email` identity; with `MAILER_AUTOCONFIRM=true` sets `email_confirmed_at`; returns the user. Duplicate email → throws `DuplicateEmailException` (caller maps to a generic response).
- `signup` rejects when `signup.disabled` is true (`SignupDisabledException`).
- `login(email, password, ip, ua)` returns `IssuedTokens` for valid creds (calls `TokenService::issueForUser`, sets `last_sign_in_at`, audits `login`).
- `login` with wrong password → `InvalidCredentialsException`; **and verifies against `Password::dummyHash()` when the user is missing** (timing). Add a test asserting that a missing-user login still calls `password_verify` path (e.g., spy/extend, or simply assert it throws `InvalidCredentialsException` for unknown email).
- `login` for a banned user (`banned_until` in future) → `UserBannedException`.

**Step 3: Implement** `AuthService`:
- ctor: `UserRepository`, `TokenService`, `Password`, `AuditRepository`, `Config`.
- `signup`: check `signup.disabled`; normalize email; `Password::hash`; `UserRepository::create` with `raw_app_meta_data = {provider:'email', providers:['email']}`; create `email` identity; if autoconfirm → `markEmailConfirmed`; audit `signup`. (Email-confirmation sending is Phase 2; until then autoconfirm is on.)
- `login`: normalize; `findByEmail`; `$ok = $password->verify($pw, $user['encrypted_password'] ?? $dummy) && $user && !banned`; if `$user` and `needsRehash` → update hash; on failure throw `InvalidCredentialsException`; on success `issueForUser(user, ip, ua, 'aal1', ['password'])`, `setLastSignInAt`, audit `login`.

**Step 4:** Run → PASS. Commit.

---

## Task 24: AuthContext middleware (resolve Bearer / cookie)

**Files:**
- Create: `src/Http/Middleware/AuthContext.php`
- Create: `src/Http/AuthenticatedUser.php` (carries `userId`, `sessionId`, `role`, `claims`, `viaCookie` flag)
- Test: `tests/Integration/AuthContextTest.php`

**Step 1: Failing test:** a request with a valid `Authorization: Bearer <jwt>` populates the auth context with `viaCookie=false`; a valid access-token **cookie** populates it with `viaCookie=true`; an invalid/expired token leaves context null (does NOT 401 here — handlers/`require auth` decide). Bearer takes precedence over cookie.

> Implementation detail: since `Request` is immutable, attach the resolved `AuthenticatedUser` via a request-scoped container or a mutable holder passed through the chain. Simplest: give `App` a per-request `RequestContext` object the middleware writes to and controllers read from. Define `RequestContext` now (`src/Http/RequestContext.php`) with `?AuthenticatedUser $user`.

**Step 3: Implement** `AuthContext`:
- read `bearerToken()`; else access-token cookie (`mb-access-token`).
- if present, `Jwt::verify()`; on success build `AuthenticatedUser` (from claims `sub`, `session_id`, `role`, `viaCookie` = (token came from cookie)); on failure (expired/invalid) leave null.
- write to `RequestContext`; call `$next`.

**Step 4:** Run → PASS. Commit.

---

## Task 25: CSRF middleware (the dual-mode fork)

**Files:**
- Create: `src/Http/Middleware/CsrfGuard.php`
- Test: `tests/Integration/CsrfGuardTest.php`

**Step 1: Failing tests (the security crux):**
- Cookie-authenticated + unsafe method + **missing** `X-CSRF-Token` → 403.
- Cookie-authenticated + unsafe method + **wrong** token → 403.
- Cookie-authenticated + unsafe method + **correct** token (matches session row) → passes to handler.
- Cookie-authenticated + **safe** method (GET) → passes without token.
- **Bearer**-authenticated + unsafe method + no CSRF token → **passes** (CSRF skipped).
- Unauthenticated public route (e.g. `/token`) → passes (CSRF not applicable; those routes aren't cookie-auth'd).

```php
public function test_cookie_auth_unsafe_without_csrf_is_403(): void { /* ... */ }
public function test_cookie_auth_unsafe_with_valid_csrf_passes(): void { /* ... */ }
public function test_bearer_auth_unsafe_skips_csrf(): void { /* ... */ }
```

**Step 3: Implement** `CsrfGuard`:
- read `RequestContext::user`. If null → `$next` (public/login routes; they don't rely on cookie auth).
- if `user->viaCookie === false` → `$next` (bearer; no ambient credential).
- if `!request->isUnsafeMethod()` → `$next`.
- else: load `session = SessionRepository::find(user->sessionId)`; compare `request->header('X-CSRF-Token')` to `session['csrf_token']` via `Csrf::matches`; mismatch → `Response::error('csrf_failed', 'CSRF validation failed.', 403)`; match → `$next`.

**Step 4:** Run → PASS. Commit. This task + Task 24 are the differentiators from Supabase — review carefully.

---

## Task 26: RateLimit middleware

**Files:**
- Create: `src/Http/Middleware/RateLimit.php`
- Test: `tests/Integration/RateLimitMiddlewareTest.php`

**Step 1: Failing test:** repeated POSTs to `/auth/v1/token?grant_type=password` from one IP beyond capacity → 429 with `Retry-After` header; under capacity → passes.

**Step 3: Implement** a route→limit map (login, refresh, signup, recover categories with `[capacity, refillPerSecond]` from a `config/ratelimits.php`), key = `category:ip:<ip>` (and `category:email:<email>` where the body has an email). On block → 429. Place this middleware *before* AuthContext in the chain.

**Step 4:** Run → PASS. Commit.

---

## Task 27: Cookie/Bearer response shaping helper

**Files:**
- Create: `src/Http/TokenResponder.php`
- Test: `tests/Unit/Http/TokenResponderTest.php`

**Step 1: Failing test:** given `IssuedTokens` and `wantsCookies=false` → JSON body has `access_token`, `refresh_token`, `token_type:"bearer"`, `expires_in`, `user`, and **no** Set-Cookie. Given `wantsCookies=true` → body has `user` + `csrf_token` but **omits** `access_token`/`refresh_token`; response carries `mb-access-token` (httpOnly, path `/`) and `mb-refresh-token` (httpOnly, path `/auth/v1/token`) cookies with correct flags from config.

**Step 3: Implement** `TokenResponder::respond(IssuedTokens $t, bool $wantsCookies, array $cookieCfg): Response`. Cookie mode sets `secure`/`samesite` from config, `httponly=true`, refresh-cookie path-scoped. This centralizes the dual-mode delivery so every controller reuses it.

**Step 4:** Run → PASS. Commit.

---

## Task 28: Controllers — Signup, Token (password + refresh), Logout

**Files:**
- Create: `src/Controllers/SignupController.php`, `src/Controllers/TokenController.php`, `src/Controllers/LogoutController.php`
- Create: `src/Support/Validator.php`
- Test: `tests/Integration/SignupEndpointTest.php`, `tests/Integration/TokenEndpointTest.php`, `tests/Integration/LogoutEndpointTest.php`

**Step 1: Failing endpoint tests (full HTTP stack via `App::boot()->handle(...)`):**
- `POST /auth/v1/signup` `{email,password}` → 200, returns user (and tokens if autoconfirm). Invalid email → 400 generic. Duplicate email → **200 generic** (no enumeration) OR 400 generic per chosen policy — pick **generic 200 with neutral body** and assert no "already exists" leak.
- `POST /auth/v1/token?grant_type=password` valid → 200 with bearer tokens; `?cookie=true` → 200 with cookies + `csrf_token`, no tokens in body. Wrong password → 400 `invalid_grant` generic.
- `POST /auth/v1/token?grant_type=refresh_token` with refresh token in body (bearer mode) or cookie (cookie mode) → rotated tokens. Replayed token → 401/400 and session revoked.
- `POST /auth/v1/logout` (bearer) → 204, session deleted; cookie mode requires CSRF (covered by middleware) and clears cookies. `scope=global` deletes all sessions for the user.

**Step 3: Implement** controllers (thin; delegate to services; use `TokenResponder`). `TokenController` switches on `grant_type` query param. `LogoutController` reads `RequestContext::user`, deletes session(s) per `scope`, returns 204 + cleared cookies. `Validator` does minimal email/password presence + `filter_var(FILTER_VALIDATE_EMAIL)`. Map exceptions → responses centrally (a small `ErrorMapper` or try/catch in `App::handle`): `InvalidCredentialsException`/`RefreshTokenReuseException`→ generic `invalid_grant`; `DuplicateEmailException`→ generic success; `SignupDisabledException`→ 422.

**Step 4:** Run → PASS. Commit.

---

## Task 29: Controllers — User self-service + Reauthenticate + Recover (request only)

**Files:**
- Create: `src/Controllers/UserController.php`, `src/Controllers/RecoverController.php`
- Test: `tests/Integration/UserEndpointTest.php`

**Step 1: Failing tests:**
- `GET /auth/v1/user` (bearer or cookie+nothing-unsafe) → returns current user from `RequestContext`; unauthenticated → 401.
- `PUT /auth/v1/user` updates `user_metadata`, phone; updating **email** or **password** requires a reauth nonce when `UPDATE_PASSWORD_REQUIRE_REAUTHENTICATION` is on — for Phase 1, gate password change behind a present-and-valid current session and (if cookie mode) CSRF; full reauth-nonce email flow can be stubbed to set the value directly with a TODO for Phase 2 email. Changing password rotates CSRF + revokes other sessions.
- `POST /auth/v1/recover` `{email}` → **always 200 generic** (no enumeration). For Phase 1 (no mailer yet) it creates/records a recovery one-time token row is deferred to Phase 2; here just return 200 generic and audit `recover_requested`. Add a TODO referencing Phase 2.
- `POST /auth/v1/reauthenticate` → returns 200; nonce generation/sending deferred to Phase 2 mailer (stub + TODO).

**Step 3: Implement** the controllers; `UserController::update` enforces the app-vs-user metadata boundary (ignore any `app_metadata` in the request body). Password change → `Password::hash`, `SessionRepository::deleteOthersForUser`, rotate CSRF on current session, audit.

**Step 4:** Run → PASS. Commit.

---

## Task 30: Admin user CRUD + service-role guard

**Files:**
- Create: `src/Http/Middleware/RequireAdmin.php` (or per-route check)
- Create: `src/Controllers/AdminUsersController.php`
- Test: `tests/Integration/AdminUsersEndpointTest.php`

**Step 1: Failing tests:**
- Admin endpoints require a **service-role JWT** (claim `role:"service_role"` OR a configured admin API key header `apikey`/`Authorization` for the service role). Non-admin token → 403.
- `GET /auth/v1/admin/users` → paginated list. `POST /admin/users` creates (optionally email-confirmed). `GET/PUT/DELETE /admin/users/{id}` work; DELETE is soft-delete. All audited.

**Step 3: Implement** `RequireAdmin` (reads `RequestContext::user->role === 'service_role'`, or verifies a configured `SERVICE_ROLE_KEY` — add to config/env). `AdminUsersController` delegates to `UserRepository`. Register admin routes with both AuthContext and RequireAdmin.

> Add `SERVICE_ROLE_KEY` and how the service-role JWT is minted (a long-lived JWT signed with our key, `role:service_role`) to `.env.example` and a `bin/issue-service-token.php` helper.

**Step 4:** Run → PASS. Commit.

---

## Task 31: Wire all routes + end-to-end smoke test

**Files:**
- Modify: `src/App.php` (register every Phase-1 route + full middleware chain in order: SecurityHeaders → Cors → RateLimit → AuthContext → CsrfGuard → router)
- Test: `tests/Integration/EndToEndAuthFlowTest.php`

**Step 1: Failing test — the full happy path in both modes:**
```
signup → login(cookie=true) → GET /user with cookie (no CSRF needed, safe) →
PUT /user with cookie + X-CSRF-Token (succeeds) →
PUT /user with cookie + WRONG csrf (403) →
refresh via cookie → logout (with CSRF) → /user now 401.
Then: login(bearer) → GET /user with Bearer → PUT /user with Bearer, no CSRF (succeeds) →
refresh(bearer) → replay old refresh (session revoked).
```

**Step 3:** Fix any wiring gaps until green.

**Step 4:** Commit. **Phase 1 complete** — tag:
```bash
git tag phase-1-core-auth
```

---

## Definition of Done (Phases 0 + 1)

- [ ] `vendor/bin/phpunit` — all unit + integration suites green.
- [ ] `php bin/migrate.php` applies `0001` + `0002` cleanly on a fresh DB.
- [ ] `GET /auth/v1/health`, `/settings`, `/.well-known/jwks.json` return correctly.
- [ ] Email+password **signup** and **login** work in **both** Bearer and cookie+CSRF modes.
- [ ] CSRF enforced on unsafe methods for cookie auth; skipped for Bearer.
- [ ] Refresh-token **rotation** + **theft detection** (family revocation) verified by tests.
- [ ] **Rate limiting** returns 429 past capacity.
- [ ] **Enumeration defense**: generic responses + dummy-hash timing on login.
- [ ] Admin user CRUD behind service-role guard.
- [ ] Every auth event written to `audit_log_entries`.
- [ ] Security headers + secure cookie flags present on responses.

## Deferred to later phases (do NOT build here)
Email/SMS sending (mailer), one-time-token *delivery* for confirm/recover/magiclink, OTP, OAuth providers, PKCE/flow_state, MFA/TOTP, SAML, Web3, anonymous, OAuth-server, captcha, HIBP. (Recovery/reauth endpoints are stubbed with TODOs pointing to Phase 2.)
