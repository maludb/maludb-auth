<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\AdminUsersController;
use Maludb\Auth\Http\Middleware\RequireAdmin;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Security\Password;
use Maludb\Auth\Support\Config;

final class AdminUsersEndpointTest extends ControllerTestCase
{
    private function controller(Config $config): AdminUsersController
    {
        return new AdminUsersController(
            $this->users(),
            $this->audit(),
            new Password((int) $config->get('password.min_length', 12)),
        );
    }

    private function request(string $method, array $body = [], array $query = [], array $headers = []): Request
    {
        return new Request(
            method: $method,
            path: '/auth/v1/admin/users',
            query: $query,
            headers: $headers + ['User-Agent' => 'phpunit'],
            rawBody: json_encode($body),
            ip: '203.0.113.5',
        );
    }

    private function next(): callable
    {
        return static fn (Request $r): Response => Response::json(['reached' => true], 200);
    }

    // --- RequireAdmin guard ---------------------------------------------

    public function test_non_admin_user_is_403(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('user@example.com', self::PASSWORD, '203.0.113.5');
        $issued = $this->authService($config)->login('user@example.com', self::PASSWORD, '203.0.113.5', 'ua');
        $ctx = $this->contextFor($issued->accessToken); // role: authenticated

        $mw = new RequireAdmin($ctx, $config);
        $res = $mw->handle($this->request('GET'), $this->next());

        $this->assertSame(403, $res->status);
        $this->assertSame('not_admin', json_decode($res->body, true)['error']);
    }

    public function test_service_role_user_passes(): void
    {
        $config = $this->testConfig();
        $mw = new RequireAdmin($this->serviceRoleContext(), $config);

        $res = $mw->handle($this->request('GET'), $this->next());

        $this->assertSame(200, $res->status);
        $this->assertTrue(json_decode($res->body, true)['reached']);
    }

    public function test_service_role_key_header_passes(): void
    {
        $config = $this->testConfig(); // service_role.key = 'test-service-role-key'
        $mw = new RequireAdmin(new RequestContext(), $config);

        $res = $mw->handle(
            $this->request('GET', [], [], ['apikey' => 'test-service-role-key']),
            $this->next(),
        );

        $this->assertSame(200, $res->status);
    }

    public function test_wrong_service_role_key_is_403(): void
    {
        $config = $this->testConfig();
        $mw = new RequireAdmin(new RequestContext(), $config);

        $res = $mw->handle(
            $this->request('GET', [], [], ['apikey' => 'nope']),
            $this->next(),
        );

        $this->assertSame(403, $res->status);
    }

    // --- CRUD ------------------------------------------------------------

    public function test_list_returns_public_users(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('l1@example.com', self::PASSWORD, '203.0.113.5');
        $this->authService($config)->signup('l2@example.com', self::PASSWORD, '203.0.113.5');

        $res = $this->controller($config)->list($this->request('GET'));

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertGreaterThanOrEqual(2, count($body['users']));
        $this->assertStringNotContainsString('encrypted_password', $res->body);
    }

    public function test_create_email_confirmed_user(): void
    {
        $config = $this->testConfig();

        $res = $this->controller($config)->create(
            $this->request('POST', ['email' => 'created@example.com', 'password' => self::PASSWORD, 'email_confirm' => true]),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertSame('created@example.com', $body['email']);
        $this->assertNotNull($body['email_confirmed_at']);
        $this->assertArrayNotHasKey('encrypted_password', $body);

        $actions = array_column(array_column($this->audit()->recent(10), 'payload'), 'action');
        $this->assertContains('admin_user_created', $actions);
    }

    public function test_show_get_and_update_and_soft_delete(): void
    {
        $config = $this->testConfig();
        $user = $this->authService($config)->signup('crud@example.com', self::PASSWORD, '203.0.113.5');
        $c = $this->controller($config);

        // show
        $show = $c->show($this->request('GET'), ['id' => $user['id']]);
        $this->assertSame(200, $show->status);
        $this->assertSame('crud@example.com', json_decode($show->body, true)['email']);

        // update (admin may set app_metadata)
        $upd = $c->update(
            new Request(method: 'PUT', path: '/x', rawBody: json_encode([
                'user_metadata' => ['tier' => 'gold'],
                'app_metadata' => ['role' => 'moderator'],
            ]), ip: '203.0.113.5'),
            ['id' => $user['id']],
        );
        $this->assertSame(200, $upd->status);
        $updBody = json_decode($upd->body, true);
        $this->assertSame(['tier' => 'gold'], $updBody['user_metadata']);
        $this->assertSame(['role' => 'moderator'], $updBody['app_metadata']);

        // soft delete
        $del = $c->delete($this->request('DELETE'), ['id' => $user['id']]);
        $this->assertSame(204, $del->status);
        $this->assertNull($this->users()->findById($user['id']));

        $actions = array_column(array_column($this->audit()->recent(20), 'payload'), 'action');
        $this->assertContains('admin_user_updated', $actions);
        $this->assertContains('admin_user_deleted', $actions);
    }

    public function test_show_missing_user_returns_404(): void
    {
        $config = $this->testConfig();
        $res = $this->controller($config)->show(
            $this->request('GET'),
            ['id' => '00000000-0000-0000-0000-000000000000'],
        );
        $this->assertSame(404, $res->status);
    }
}
