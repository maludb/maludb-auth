<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\TokenController;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Support\Config;

final class TokenEndpointTest extends ControllerTestCase
{
    private function controller(Config $config): TokenController
    {
        return new TokenController(
            $this->authService($config),
            $this->tokenService($config),
            $this->responder(),
            $config,
        );
    }

    private function seedUser(Config $config, string $email): void
    {
        $this->authService($config)->signup($email, self::PASSWORD, '203.0.113.5');
    }

    private function request(array $query, array $body, array $cookies = []): Request
    {
        return new Request(
            method: 'POST',
            path: '/auth/v1/token',
            query: $query,
            headers: ['User-Agent' => 'phpunit'],
            rawBody: json_encode($body),
            cookies: $cookies,
            ip: '203.0.113.5',
        );
    }

    public function test_password_grant_returns_bearer_tokens(): void
    {
        $config = $this->testConfig();
        $this->seedUser($config, 'pw@example.com');

        $res = $this->controller($config)->handle(
            $this->request(['grant_type' => 'password'], ['email' => 'pw@example.com', 'password' => self::PASSWORD]),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertNotEmpty($body['access_token']);
        $this->assertNotEmpty($body['refresh_token']);
        $this->assertStringNotContainsString('encrypted_password', $res->body);
    }

    public function test_password_grant_cookie_mode(): void
    {
        $config = $this->testConfig();
        $this->seedUser($config, 'pwcookie@example.com');

        $res = $this->controller($config)->handle(
            $this->request(['grant_type' => 'password', 'cookie' => 'true'],
                ['email' => 'pwcookie@example.com', 'password' => self::PASSWORD]),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertArrayNotHasKey('access_token', $body);
        $this->assertNotEmpty($body['csrf_token']);
        $this->assertContains('mb-refresh-token', array_column($res->cookies, 'name'));
    }

    public function test_wrong_password_returns_generic_invalid_grant(): void
    {
        $config = $this->testConfig();
        $this->seedUser($config, 'wrong@example.com');

        $res = $this->controller($config)->handle(
            $this->request(['grant_type' => 'password'], ['email' => 'wrong@example.com', 'password' => 'the wrong password here']),
            new RequestContext(),
        );

        $this->assertSame(400, $res->status);
        $body = json_decode($res->body, true);
        $this->assertSame('invalid_grant', $body['error']);
        $this->assertSame('Invalid login credentials', $body['error_description']);
    }

    public function test_unknown_email_indistinguishable_from_wrong_password(): void
    {
        $config = $this->testConfig();

        $res = $this->controller($config)->handle(
            $this->request(['grant_type' => 'password'], ['email' => 'ghost@example.com', 'password' => self::PASSWORD]),
            new RequestContext(),
        );

        $this->assertSame(400, $res->status);
        $this->assertSame('invalid_grant', json_decode($res->body, true)['error']);
    }

    public function test_refresh_grant_body_rotates_token(): void
    {
        $config = $this->testConfig();
        $issued = $this->authService($config)->signup('r@example.com', self::PASSWORD, '203.0.113.5');
        $login = $this->authService($config)->login('r@example.com', self::PASSWORD, '203.0.113.5', 'ua');

        $res = $this->controller($config)->handle(
            $this->request(['grant_type' => 'refresh_token'], ['refresh_token' => $login->refreshToken]),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertNotEmpty($body['refresh_token']);
        $this->assertNotSame($login->refreshToken, $body['refresh_token']);
    }

    public function test_refresh_grant_cookie_rotates(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('rc@example.com', self::PASSWORD, '203.0.113.5');
        $login = $this->authService($config)->login('rc@example.com', self::PASSWORD, '203.0.113.5', 'ua');

        $res = $this->controller($config)->handle(
            $this->request(['grant_type' => 'refresh_token', 'cookie' => 'true'], [],
                ['mb-refresh-token' => $login->refreshToken]),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $this->assertContains('mb-refresh-token', array_column($res->cookies, 'name'));
    }

    public function test_replayed_refresh_returns_generic_invalid_grant(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('replay@example.com', self::PASSWORD, '203.0.113.5');
        $login = $this->authService($config)->login('replay@example.com', self::PASSWORD, '203.0.113.5', 'ua');
        $controller = $this->controller($config);

        // First rotation consumes the token.
        $controller->handle(
            $this->request(['grant_type' => 'refresh_token'], ['refresh_token' => $login->refreshToken]),
            new RequestContext(),
        );

        // Replaying the now-revoked token → reuse detected → generic invalid_grant.
        $res = $controller->handle(
            $this->request(['grant_type' => 'refresh_token'], ['refresh_token' => $login->refreshToken]),
            new RequestContext(),
        );

        $this->assertSame(400, $res->status);
        $this->assertSame('invalid_grant', json_decode($res->body, true)['error']);
    }

    public function test_unknown_grant_type_returns_400(): void
    {
        $config = $this->testConfig();

        $res = $this->controller($config)->handle(
            $this->request(['grant_type' => 'magic'], []),
            new RequestContext(),
        );

        $this->assertSame(400, $res->status);
        $this->assertSame('unsupported_grant_type', json_decode($res->body, true)['error']);
    }

    public function test_missing_grant_type_returns_400(): void
    {
        $config = $this->testConfig();

        $res = $this->controller($config)->handle(
            $this->request([], []),
            new RequestContext(),
        );

        $this->assertSame(400, $res->status);
        $this->assertSame('unsupported_grant_type', json_decode($res->body, true)['error']);
    }
}
