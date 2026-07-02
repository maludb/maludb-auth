<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\App;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Security\Jwt;
use Maludb\Auth\Support\Config;
use Maludb\Auth\Support\Database;

/**
 * The Unit 13 finale: drive the REAL router + full middleware chain through
 * App::handle() for both auth modes, proving the composed system enforces its
 * guards over genuine requests (not just controllers in isolation).
 *
 * The app is built from the real config (real RSA keys + issuer/audience) but
 * bound to the rolled-back test PDO, so tokens the app mints verify against its
 * own AuthContext. Each test uses a distinct client IP so the real rate limiter
 * (config/ratelimits.php) can't cross-contaminate — and because rate_limits
 * rows are written inside the harness's per-test transaction, they roll back.
 */
final class EndToEndAuthFlowTest extends IntegrationTestCase
{
    private App $app;
    private string $base;

    protected function setUp(): void
    {
        parent::setUp();
        $this->base = dirname(__DIR__, 2);
        $this->app = App::fromConfig(
            $this->config,
            new Database($this->config),
            self::$pdo,
            $this->base,
        );
    }

    // --- helpers --------------------------------------------------------

    private function req(
        string $method,
        string $path,
        array $query = [],
        array $headers = [],
        array $body = [],
        array $cookies = [],
        string $ip = '203.0.113.1',
    ): Request {
        return new Request(
            method: $method,
            path: $path,
            query: $query,
            headers: $headers + ['User-Agent' => 'phpunit'],
            rawBody: $body === [] ? '' : (string) json_encode($body),
            cookies: $cookies,
            ip: $ip,
        );
    }

    private function json(Response $res): array
    {
        return json_decode($res->body, true) ?? [];
    }

    /** Extract a Set-Cookie value by name from a Response's cookie jar. */
    private function cookieValue(Response $res, string $name): ?string
    {
        foreach ($res->cookies as $c) {
            if ($c['name'] === $name) {
                return $c['value'];
            }
        }
        return null;
    }

    /** Mint a genuine service_role JWT against the app's own key/issuer/aud. */
    private function serviceRoleToken(): string
    {
        $priv = (string) file_get_contents(
            $this->base . '/' . ltrim((string) $this->config->get('jwt.private_key_path'), '/')
        );
        $pub = (string) file_get_contents(
            $this->base . '/' . ltrim((string) $this->config->get('jwt.public_key_path'), '/')
        );
        $jwt = new Jwt(
            $priv,
            $pub,
            (string) $this->config->get('jwt.kid'),
            (string) $this->config->get('jwt.issuer'),
            (string) $this->config->get('jwt.audience', 'authenticated'),
        );

        return $jwt->issue(['sub' => 'svc', 'role' => 'service_role'], 3600);
    }

    private function signup(string $email, string $ip): Response
    {
        return $this->app->handle($this->req(
            'POST', '/auth/v1/signup',
            body: ['email' => $email, 'password' => 'correct horse battery staple'],
            ip: $ip,
        ));
    }

    // === Cookie + CSRF happy path ======================================

    public function test_cookie_csrf_full_lifecycle(): void
    {
        $ip = '198.51.100.10';
        $this->assertSame(200, $this->signup('cookie@example.com', $ip)->status);

        // Login in cookie mode -> sets access + refresh cookies, returns csrf_token.
        $login = $this->app->handle($this->req(
            'POST', '/auth/v1/token',
            query: ['grant_type' => 'password', 'cookie' => 'true'],
            body: ['email' => 'cookie@example.com', 'password' => 'correct horse battery staple'],
            ip: $ip,
        ));
        $this->assertSame(200, $login->status);
        $access = $this->cookieValue($login, 'mb-access-token');
        $refresh = $this->cookieValue($login, 'mb-refresh-token');
        $csrf = $this->json($login)['csrf_token'] ?? null;
        $this->assertNotEmpty($access);
        $this->assertNotEmpty($refresh);
        $this->assertNotEmpty($csrf);

        $accessCookie = ['mb-access-token' => $access];

        // GET /user with access cookie — safe method, no CSRF required.
        $get = $this->app->handle($this->req(
            'GET', '/auth/v1/user', cookies: $accessCookie, ip: $ip,
        ));
        $this->assertSame(200, $get->status);
        $this->assertSame('cookie@example.com', $this->json($get)['email']);

        // PUT /user with cookie + correct CSRF -> 200.
        $putOk = $this->app->handle($this->req(
            'PUT', '/auth/v1/user',
            headers: ['X-CSRF-Token' => $csrf],
            body: ['user_metadata' => ['name' => 'Ada']],
            cookies: $accessCookie,
            ip: $ip,
        ));
        $this->assertSame(200, $putOk->status);

        // PUT /user with cookie + WRONG CSRF -> 403.
        $putBad = $this->app->handle($this->req(
            'PUT', '/auth/v1/user',
            headers: ['X-CSRF-Token' => 'wrong-token'],
            body: ['user_metadata' => ['name' => 'Eve']],
            cookies: $accessCookie,
            ip: $ip,
        ));
        $this->assertSame(403, $putBad->status);
        $this->assertSame('csrf_failed', $this->json($putBad)['error']);

        // Refresh via the refresh cookie (cookie mode) -> rotated new cookies.
        $refreshRes = $this->app->handle($this->req(
            'POST', '/auth/v1/token',
            query: ['grant_type' => 'refresh_token', 'cookie' => 'true'],
            cookies: ['mb-refresh-token' => $refresh],
            ip: $ip,
        ));
        $this->assertSame(200, $refreshRes->status);
        $newAccess = $this->cookieValue($refreshRes, 'mb-access-token');
        $newRefresh = $this->cookieValue($refreshRes, 'mb-refresh-token');
        $this->assertNotEmpty($newAccess);
        $this->assertNotEmpty($newRefresh);
        $this->assertNotSame($refresh, $newRefresh, 'refresh token should rotate');

        // Logout (cookie mode, with CSRF) -> 204.
        $logout = $this->app->handle($this->req(
            'POST', '/auth/v1/logout',
            headers: ['X-CSRF-Token' => $csrf],
            cookies: ['mb-access-token' => $newAccess],
            ip: $ip,
        ));
        $this->assertSame(204, $logout->status);

        // GET /user after logout: the session row is gone. A cookie-borne request
        // is authenticated by JWT (still cryptographically valid until exp), but
        // the account self-endpoint reloads the user and the session is revoked;
        // assert the caller can no longer act — logout cleared server session.
        // The access JWT itself is still unexpired, so /user (which only needs a
        // valid token + existing user) may still resolve; instead prove the
        // refresh credential is dead (session family revoked) -> generic 400.
        $deadRefresh = $this->app->handle($this->req(
            'POST', '/auth/v1/token',
            query: ['grant_type' => 'refresh_token'],
            body: ['refresh_token' => $newRefresh],
            ip: $ip,
        ));
        $this->assertSame(400, $deadRefresh->status);
        $this->assertSame('invalid_grant', $this->json($deadRefresh)['error']);
    }

    // === Bearer happy path =============================================

    public function test_bearer_full_lifecycle_and_refresh_replay(): void
    {
        // Zero the refresh reuse grace window so an immediate replay of the old
        // token is unambiguous theft (outside any grace) rather than a benign
        // client-retry — the case this test asserts.
        $strictConfig = new Config(array_replace_recursive(
            require $this->base . '/config/config.php',
            ['refresh' => ['reuse_interval' => 0]],
        ));
        $app = App::fromConfig($strictConfig, new Database($strictConfig), self::$pdo, $this->base);

        $ip = '198.51.100.20';
        $this->assertSame(200, $app->handle($this->req(
            'POST', '/auth/v1/signup',
            body: ['email' => 'bearer@example.com', 'password' => 'correct horse battery staple'],
            ip: $ip,
        ))->status);

        $login = $app->handle($this->req(
            'POST', '/auth/v1/token',
            query: ['grant_type' => 'password'],
            body: ['email' => 'bearer@example.com', 'password' => 'correct horse battery staple'],
            ip: $ip,
        ));
        $this->assertSame(200, $login->status);
        $body = $this->json($login);
        $access = $body['access_token'];
        $refresh = $body['refresh_token'];
        $this->assertNotEmpty($access);
        $this->assertNotEmpty($refresh);

        $bearer = ['Authorization' => 'Bearer ' . $access];

        // GET /user with Bearer.
        $get = $app->handle($this->req('GET', '/auth/v1/user', headers: $bearer, ip: $ip));
        $this->assertSame(200, $get->status);

        // PUT /user with Bearer and NO CSRF -> 200 (CSRF skipped for bearer).
        $put = $app->handle($this->req(
            'PUT', '/auth/v1/user',
            headers: $bearer,
            body: ['user_metadata' => ['name' => 'Grace']],
            ip: $ip,
        ));
        $this->assertSame(200, $put->status);

        // Refresh (bearer, refresh_token in body).
        $refreshed = $app->handle($this->req(
            'POST', '/auth/v1/token',
            query: ['grant_type' => 'refresh_token'],
            body: ['refresh_token' => $refresh],
            ip: $ip,
        ));
        $this->assertSame(200, $refreshed->status);
        $this->assertNotSame($refresh, $this->json($refreshed)['refresh_token']);

        // Replay the OLD refresh token -> theft detection revokes family ->
        // generic invalid_grant.
        $replay = $app->handle($this->req(
            'POST', '/auth/v1/token',
            query: ['grant_type' => 'refresh_token'],
            body: ['refresh_token' => $refresh],
            ip: $ip,
        ));
        $this->assertSame(400, $replay->status);
        $this->assertSame('invalid_grant', $this->json($replay)['error']);
    }

    // === Guards through the router =====================================

    public function test_admin_route_rejects_normal_user_and_allows_service_role(): void
    {
        $ip = '198.51.100.30';
        $this->signup('normal@example.com', $ip);
        $login = $this->app->handle($this->req(
            'POST', '/auth/v1/token',
            query: ['grant_type' => 'password'],
            body: ['email' => 'normal@example.com', 'password' => 'correct horse battery staple'],
            ip: $ip,
        ));
        $access = $this->json($login)['access_token'];

        // Normal (authenticated) token -> 403 not_admin.
        $denied = $this->app->handle($this->req(
            'POST', '/auth/v1/admin/users',
            headers: ['Authorization' => 'Bearer ' . $access],
            body: ['email' => 'created@example.com', 'password' => 'correct horse battery staple'],
            ip: $ip,
        ));
        $this->assertSame(403, $denied->status);
        $this->assertSame('not_admin', $this->json($denied)['error']);

        // service_role token -> 200.
        $allowed = $this->app->handle($this->req(
            'POST', '/auth/v1/admin/users',
            headers: ['Authorization' => 'Bearer ' . $this->serviceRoleToken()],
            body: ['email' => 'created@example.com', 'password' => 'correct horse battery staple'],
            ip: $ip,
        ));
        $this->assertSame(200, $allowed->status);
        $this->assertSame('created@example.com', $this->json($allowed)['email']);
    }

    public function test_cookie_state_change_without_csrf_header_is_403(): void
    {
        $ip = '198.51.100.40';
        $this->signup('nocsrf@example.com', $ip);
        $login = $this->app->handle($this->req(
            'POST', '/auth/v1/token',
            query: ['grant_type' => 'password', 'cookie' => 'true'],
            body: ['email' => 'nocsrf@example.com', 'password' => 'correct horse battery staple'],
            ip: $ip,
        ));
        $access = $this->cookieValue($login, 'mb-access-token');

        $put = $this->app->handle($this->req(
            'PUT', '/auth/v1/user',
            body: ['user_metadata' => ['x' => 1]],
            cookies: ['mb-access-token' => $access],
            ip: $ip,
        ));
        $this->assertSame(403, $put->status);
        $this->assertSame('csrf_failed', $this->json($put)['error']);
    }

    public function test_cookie_state_change_with_lowercase_method_no_csrf_is_403(): void
    {
        $ip = '198.51.100.50';
        $this->signup('lower@example.com', $ip);
        $login = $this->app->handle($this->req(
            'POST', '/auth/v1/token',
            query: ['grant_type' => 'password', 'cookie' => 'true'],
            body: ['email' => 'lower@example.com', 'password' => 'correct horse battery staple'],
            ip: $ip,
        ));
        $access = $this->cookieValue($login, 'mb-access-token');

        // Lowercase method: Request normalizes to PUT, so CsrfGuard's
        // isUnsafeMethod() still fires (defense-in-depth over normalization).
        $put = $this->app->handle($this->req(
            'put', '/auth/v1/user',
            body: ['user_metadata' => ['x' => 1]],
            cookies: ['mb-access-token' => $access],
            ip: $ip,
        ));
        $this->assertSame(403, $put->status);
        $this->assertSame('csrf_failed', $this->json($put)['error']);
    }

    public function test_login_flood_from_one_ip_is_rate_limited(): void
    {
        $ip = '198.51.100.60';
        // Login capacity is 30 (config/ratelimits.php). Fire past it with a
        // consistent bad login from one IP; the IP bucket must eventually 429.
        $sawRateLimit = false;
        for ($i = 0; $i < 40; $i++) {
            $res = $this->app->handle($this->req(
                'POST', '/auth/v1/token',
                query: ['grant_type' => 'password'],
                body: ['email' => 'flood@example.com', 'password' => 'wrong-password-attempt'],
                ip: $ip,
            ));
            if ($res->status === 429) {
                $sawRateLimit = true;
                $this->assertArrayHasKey('Retry-After', $res->headers);
                $this->assertSame('over_rate_limit', $this->json($res)['error']);
                break;
            }
        }
        $this->assertTrue($sawRateLimit, 'expected a 429 once the login bucket is exhausted');
    }

    // === Error hygiene =================================================

    public function test_unknown_route_is_clean_json_404(): void
    {
        $res = $this->app->handle($this->req('GET', '/auth/v1/does-not-exist', ip: '198.51.100.70'));
        $this->assertSame(404, $res->status);
        $body = $this->json($res);
        $this->assertSame('not_found', $body['error']);
        $this->assertStringNotContainsString('Stack trace', $res->body);
        // SecurityHeaders still applied on the not-found path.
        $this->assertSame('nosniff', $res->headers['X-Content-Type-Options'] ?? null);
    }

    public function test_uncaught_error_becomes_generic_500_with_headers(): void
    {
        // Build an app whose config points at a bogus private key path so signing
        // an access token throws deep inside the token flow — an UNEXPECTED error
        // that must surface as a generic 500, never a stack trace.
        $brokenConfig = new Config(array_replace_recursive(
            require $this->base . '/config/config.php',
            ['jwt' => ['private_key_path' => 'keys/does_not_exist.pem']],
        ));
        $brokenApp = App::fromConfig($brokenConfig, new Database($brokenConfig), self::$pdo, $this->base);

        $ip = '198.51.100.80';
        // Autoconfirm signup mints a session, so the missing signing key throws
        // deep inside token issuance — an unexpected error routed to a generic 500.
        $res = $brokenApp->handle($this->req(
            'POST', '/auth/v1/signup',
            body: ['email' => 'boom@example.com', 'password' => 'correct horse battery staple'],
            ip: $ip,
        ));

        $this->assertSame(500, $res->status);
        $this->assertSame('internal_error', $this->json($res)['error']);
        $this->assertStringNotContainsString('Stack trace', $res->body);
        $this->assertStringNotContainsString('does_not_exist', $res->body);
        // SecurityHeaders still applied on the error path.
        $this->assertSame('nosniff', $res->headers['X-Content-Type-Options'] ?? null);
    }
}
