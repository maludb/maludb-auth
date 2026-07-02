<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\LogoutController;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Support\Config;

final class LogoutEndpointTest extends ControllerTestCase
{
    private function controller(): LogoutController
    {
        return new LogoutController($this->sessions(), $this->audit());
    }

    private function request(array $body = [], array $query = []): Request
    {
        return new Request(
            method: 'POST',
            path: '/auth/v1/logout',
            query: $query,
            headers: ['User-Agent' => 'phpunit'],
            rawBody: json_encode($body),
            ip: '203.0.113.5',
        );
    }

    /** @return array{0:string,1:\Maludb\Auth\Dto\IssuedTokens} email + issued */
    private function loginUser(Config $config, string $email)
    {
        $this->authService($config)->signup($email, self::PASSWORD, '203.0.113.5');

        return $this->authService($config)->login($email, self::PASSWORD, '203.0.113.5', 'ua');
    }

    public function test_unauthenticated_returns_401(): void
    {
        $res = $this->controller()->handle($this->request(), new RequestContext());
        $this->assertSame(401, $res->status);
    }

    public function test_local_logout_deletes_current_session_and_clears_cookies(): void
    {
        $config = $this->testConfig();
        $issued = $this->loginUser($config, 'logout@example.com');
        $ctx = $this->contextFor($issued->accessToken);

        $res = $this->controller()->handle($this->request(), $ctx);

        $this->assertSame(204, $res->status);
        $this->assertNull($this->sessions()->find($issued->sessionId));

        // Cookies cleared (empty value).
        $names = array_column($res->cookies, 'name');
        $this->assertContains('mb-access-token', $names);
        $this->assertContains('mb-refresh-token', $names);
        foreach ($res->cookies as $c) {
            $this->assertSame('', $c['value']);
        }
    }

    public function test_global_logout_deletes_all_sessions(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('multi@example.com', self::PASSWORD, '203.0.113.5');
        $first = $this->authService($config)->login('multi@example.com', self::PASSWORD, '203.0.113.5', 'ua');
        $second = $this->authService($config)->login('multi@example.com', self::PASSWORD, '203.0.113.5', 'ua2');

        $ctx = $this->contextFor($first->accessToken);
        $res = $this->controller()->handle($this->request(['scope' => 'global']), $ctx);

        $this->assertSame(204, $res->status);
        $this->assertNull($this->sessions()->find($first->sessionId));
        $this->assertNull($this->sessions()->find($second->sessionId));
    }

    public function test_others_logout_keeps_current_session(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('others@example.com', self::PASSWORD, '203.0.113.5');
        $current = $this->authService($config)->login('others@example.com', self::PASSWORD, '203.0.113.5', 'ua');
        $other = $this->authService($config)->login('others@example.com', self::PASSWORD, '203.0.113.5', 'ua2');

        $ctx = $this->contextFor($current->accessToken);
        $res = $this->controller()->handle($this->request(['scope' => 'others']), $ctx);

        $this->assertSame(204, $res->status);
        $this->assertNotNull($this->sessions()->find($current->sessionId));
        $this->assertNull($this->sessions()->find($other->sessionId));
    }
}
