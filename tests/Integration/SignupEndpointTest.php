<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\SignupController;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;

final class SignupEndpointTest extends ControllerTestCase
{
    private function controller(array $configOverrides = []): SignupController
    {
        $config = $this->testConfig($configOverrides);

        return new SignupController(
            $this->authService($config),
            $this->tokenService($config),
            $this->responder(),
            $config,
            $this->otpService($config),
        );
    }

    private function request(array $body, array $query = []): Request
    {
        return new Request(
            method: 'POST',
            path: '/auth/v1/signup',
            query: $query,
            headers: ['User-Agent' => 'phpunit'],
            rawBody: json_encode($body),
            ip: '203.0.113.5',
        );
    }

    public function test_autoconfirm_signup_returns_tokens(): void
    {
        $res = $this->controller()->handle(
            $this->request(['email' => 'new@example.com', 'password' => self::PASSWORD]),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertNotEmpty($body['access_token']);
        $this->assertNotEmpty($body['refresh_token']);
        $this->assertSame('bearer', $body['token_type']);
        $this->assertSame('new@example.com', $body['user']['email']);
        $this->assertStringNotContainsString('encrypted_password', $res->body);
    }

    public function test_autoconfirm_signup_cookie_mode_sets_cookies(): void
    {
        $res = $this->controller()->handle(
            $this->request(['email' => 'cookie@example.com', 'password' => self::PASSWORD], ['cookie' => 'true']),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertArrayNotHasKey('access_token', $body);
        $this->assertNotEmpty($body['csrf_token']);
        $names = array_column($res->cookies, 'name');
        $this->assertContains('mb-access-token', $names);
        $this->assertContains('mb-refresh-token', $names);
    }

    public function test_no_autoconfirm_returns_public_user_no_tokens(): void
    {
        $res = $this->controller(['signup' => ['autoconfirm' => false]])->handle(
            $this->request(['email' => 'pending@example.com', 'password' => self::PASSWORD]),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertArrayNotHasKey('access_token', $body);
        $this->assertSame('pending@example.com', $body['user']['email']);
        $this->assertNull($body['user']['email_confirmed_at']);

        // A confirmation mail with a signup verify link + code went out.
        $this->assertCount(1, $this->mailer->sent);
        $this->assertSame('pending@example.com', $this->mailer->last()['to']);
        $this->assertStringContainsString('type=signup', $this->mailer->last()['text']);
    }

    public function test_confirmation_flow_verify_then_password_login(): void
    {
        $overrides = ['signup' => ['autoconfirm' => false]];
        $config = $this->testConfig($overrides);
        $c = $this->controller($overrides);
        $otp = $this->otpService($config); // shares the DB rows; fresh outbox unused

        $c->handle(
            $this->request(['email' => 'flow@example.com', 'password' => self::PASSWORD]),
            new RequestContext(),
        );

        // Login before confirmation is refused with a distinct (post-credential) error.
        try {
            $this->authService($config)->login('flow@example.com', self::PASSWORD, 'ip', 'ua');
            $this->fail('Expected EmailNotConfirmedException');
        } catch (\Maludb\Auth\Exceptions\EmailNotConfirmedException) {
        }

        // Redeem the mailed code via the OTP machinery -> confirmed + session.
        $row = (new \Maludb\Auth\Repositories\OneTimeTokenRepository(self::$pdo))
            ->findForUser((string) $this->users()->findByEmail('flow@example.com')['id'], 'confirmation');
        $this->assertNotNull($row);
        $issued = $otp->verify('confirmation', null, null, $row['token_hash'], 'ip', 'ua');
        $this->assertNotEmpty($issued->accessToken);

        // Password login now succeeds.
        $login = $this->authService($config)->login('flow@example.com', self::PASSWORD, 'ip', 'ua');
        $this->assertNotEmpty($login->accessToken);
    }

    public function test_wrong_password_on_unconfirmed_account_stays_generic(): void
    {
        $overrides = ['signup' => ['autoconfirm' => false]];
        $config = $this->testConfig($overrides);
        $this->controller($overrides)->handle(
            $this->request(['email' => 'generic@example.com', 'password' => self::PASSWORD]),
            new RequestContext(),
        );

        // Wrong password must NOT reveal the (unconfirmed) account exists.
        $this->expectException(\Maludb\Auth\Exceptions\InvalidCredentialsException::class);
        $this->authService($config)->login('generic@example.com', 'wrong-password-here', 'ip', 'ua');
    }

    public function test_duplicate_email_returns_generic_200_no_leak(): void
    {
        $c = $this->controller(['signup' => ['autoconfirm' => false]]);
        // First signup succeeds.
        $c->handle($this->request(['email' => 'dupe@example.com', 'password' => self::PASSWORD]), new RequestContext());

        // Second signup for the same email must NOT reveal existence.
        $res = $c->handle(
            $this->request(['email' => 'Dupe@Example.com', 'password' => self::PASSWORD]),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertArrayNotHasKey('error', $body);
        $this->assertStringNotContainsStringIgnoringCase('exist', $res->body);
        $this->assertStringNotContainsStringIgnoringCase('already', $res->body);
        // Same shape as a fresh unconfirmed signup: {user: {...}} pending.
        $this->assertArrayHasKey('user', $body);
        $this->assertSame('dupe@example.com', $body['user']['email']);
        $this->assertNull($body['user']['email_confirmed_at']);
    }

    public function test_invalid_email_returns_400(): void
    {
        $res = $this->controller()->handle(
            $this->request(['email' => 'not-an-email', 'password' => self::PASSWORD]),
            new RequestContext(),
        );

        $this->assertSame(400, $res->status);
        $this->assertSame('validation_failed', json_decode($res->body, true)['error']);
    }

    public function test_weak_password_returns_400(): void
    {
        $res = $this->controller()->handle(
            $this->request(['email' => 'weak@example.com', 'password' => 'short']),
            new RequestContext(),
        );

        $this->assertSame(400, $res->status);
        $this->assertSame('weak_password', json_decode($res->body, true)['error']);
    }
}
