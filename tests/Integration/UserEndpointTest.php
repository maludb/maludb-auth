<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\UserController;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Security\Csrf;
use Maludb\Auth\Security\Password;
use Maludb\Auth\Support\Config;

final class UserEndpointTest extends ControllerTestCase
{
    private function controller(Config $config): UserController
    {
        return new UserController(
            $this->users(),
            $this->sessions(),
            $this->audit(),
            new Password((int) $config->get('password.min_length', 12)),
            new Csrf(),
            $this->otpService($config),
            $config,
        );
    }

    private function request(string $method, array $body = []): Request
    {
        return new Request(
            method: $method,
            path: '/auth/v1/user',
            headers: ['User-Agent' => 'phpunit'],
            rawBody: json_encode($body),
            ip: '203.0.113.5',
        );
    }

    private function loginUser(Config $config, string $email)
    {
        $this->authService($config)->signup($email, self::PASSWORD, '203.0.113.5');

        return $this->authService($config)->login($email, self::PASSWORD, '203.0.113.5', 'ua');
    }

    public function test_get_returns_public_user_no_encrypted_password(): void
    {
        $config = $this->testConfig();
        $issued = $this->loginUser($config, 'me@example.com');
        $ctx = $this->contextFor($issued->accessToken);

        $res = $this->controller($config)->show($this->request('GET'), $ctx);

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertSame('me@example.com', $body['email']);
        $this->assertArrayNotHasKey('encrypted_password', $body);
        $this->assertStringNotContainsString('encrypted_password', $res->body);
    }

    public function test_get_unauthenticated_returns_401(): void
    {
        $config = $this->testConfig();
        $res = $this->controller($config)->show($this->request('GET'), new RequestContext());
        $this->assertSame(401, $res->status);
    }

    public function test_put_updates_user_metadata_and_ignores_app_metadata(): void
    {
        $config = $this->testConfig();
        $issued = $this->loginUser($config, 'update@example.com');
        $ctx = $this->contextFor($issued->accessToken);

        $res = $this->controller($config)->update(
            $this->request('PUT', [
                'user_metadata' => ['display_name' => 'Ada'],
                'app_metadata' => ['role' => 'superadmin', 'provider' => 'evil'],
            ]),
            $ctx,
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertSame(['display_name' => 'Ada'], $body['user_metadata']);

        // app_metadata from the body was IGNORED — still server-controlled value.
        $this->assertSame(['provider' => 'email', 'providers' => ['email']], $body['app_metadata']);
        $persisted = $this->users()->findById($ctx->user->userId);
        $this->assertSame(['provider' => 'email', 'providers' => ['email']], $persisted['raw_app_meta_data']);
    }

    public function test_put_password_change_revokes_other_sessions_and_rotates_csrf(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('pwchange@example.com', self::PASSWORD, '203.0.113.5');
        $current = $this->authService($config)->login('pwchange@example.com', self::PASSWORD, '203.0.113.5', 'ua');
        $other = $this->authService($config)->login('pwchange@example.com', self::PASSWORD, '203.0.113.5', 'ua2');

        $ctx = $this->contextFor($current->accessToken);
        $oldCsrf = $this->sessions()->find($current->sessionId)['csrf_token'];

        $res = $this->controller($config)->update(
            $this->request('PUT', ['password' => 'a-brand-new-strong-password']),
            $ctx,
        );

        $this->assertSame(200, $res->status);

        // Other session revoked, current session kept.
        $this->assertNull($this->sessions()->find($other->sessionId));
        $currentSession = $this->sessions()->find($current->sessionId);
        $this->assertNotNull($currentSession);

        // CSRF rotated on the current session.
        $this->assertNotSame($oldCsrf, $currentSession['csrf_token']);

        // New password verifies.
        $persisted = $this->users()->findById($ctx->user->userId);
        $this->assertTrue((new Password(12))->verify('a-brand-new-strong-password', $persisted['encrypted_password']));

        // password_change audited.
        $actions = array_column(array_column($this->audit()->recent(10), 'payload'), 'action');
        $this->assertContains('password_change', $actions);
    }

    public function test_put_unauthenticated_returns_401(): void
    {
        $config = $this->testConfig();
        $res = $this->controller($config)->update($this->request('PUT', ['phone' => '123']), new RequestContext());
        $this->assertSame(401, $res->status);
    }

    // --- reauth-gated password change (Phase 2) ---------------------------

    private function reauthConfig(): Config
    {
        return $this->testConfig([
            'security' => ['update_password_require_reauthentication' => true],
        ]);
    }

    public function test_password_change_without_nonce_is_rejected_when_gate_on(): void
    {
        $config = $this->reauthConfig();
        $controller = $this->controller($config);
        $issued = $this->loginUser($config, 'gate-on@example.com');
        $ctx = $this->contextFor($issued->accessToken);

        $res = $controller->update(
            $this->request('PUT', ['password' => 'a-brand-new-strong-password']),
            $ctx,
        );

        $this->assertSame(400, $res->status);
        $this->assertSame('reauthentication_needed', json_decode($res->body, true)['error']);
        // Old password still verifies — nothing changed.
        $persisted = $this->users()->findById($ctx->user->userId);
        $this->assertTrue((new Password(12))->verify(self::PASSWORD, $persisted['encrypted_password']));
    }

    public function test_password_change_with_valid_nonce_succeeds_and_nonce_is_consumed(): void
    {
        $config = $this->reauthConfig();
        $controller = $this->controller($config);
        $otp = $this->otpService($config); // fresh outbox for the nonce mail
        $issued = $this->loginUser($config, 'gate-nonce@example.com');
        $ctx = $this->contextFor($issued->accessToken);

        $otp->send('reauthentication', 'gate-nonce@example.com', 'ip');
        $nonce = $this->mailedCode();

        $ok = $controller->update(
            $this->request('PUT', ['password' => 'a-brand-new-strong-password', 'nonce' => $nonce]),
            $ctx,
        );
        $this->assertSame(200, $ok->status);
        $persisted = $this->users()->findById($ctx->user->userId);
        $this->assertTrue((new Password(12))->verify('a-brand-new-strong-password', $persisted['encrypted_password']));

        // Consumed: the same nonce cannot authorize a second change.
        $replay = $controller->update(
            $this->request('PUT', ['password' => 'yet-another-strong-password', 'nonce' => $nonce]),
            $ctx,
        );
        $this->assertSame(400, $replay->status);
        $this->assertSame('reauthentication_needed', json_decode($replay->body, true)['error']);
    }

    public function test_weak_password_does_not_burn_the_nonce(): void
    {
        $config = $this->reauthConfig();
        $controller = $this->controller($config);
        $otp = $this->otpService($config);
        $issued = $this->loginUser($config, 'weak-keeps-nonce@example.com');
        $ctx = $this->contextFor($issued->accessToken);

        $otp->send('reauthentication', 'weak-keeps-nonce@example.com', 'ip');
        $nonce = $this->mailedCode();

        // First attempt uses a too-short password -> 400 weak_password.
        $weak = $controller->update(
            $this->request('PUT', ['password' => 'short', 'nonce' => $nonce]),
            $ctx,
        );
        $this->assertSame(400, $weak->status);
        $this->assertSame('weak_password', json_decode($weak->body, true)['error']);

        // The nonce must still be usable for a proper retry.
        $ok = $controller->update(
            $this->request('PUT', ['password' => 'a-brand-new-strong-password', 'nonce' => $nonce]),
            $ctx,
        );
        $this->assertSame(200, $ok->status);
    }

    public function test_password_change_without_nonce_still_works_when_gate_off(): void
    {
        $config = $this->testConfig(); // gate defaults off
        $controller = $this->controller($config);
        $issued = $this->loginUser($config, 'gate-off@example.com');
        $ctx = $this->contextFor($issued->accessToken);

        $res = $controller->update(
            $this->request('PUT', ['password' => 'a-brand-new-strong-password']),
            $ctx,
        );
        $this->assertSame(200, $res->status);
    }
}
