<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\OtpController;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Support\Config;

final class OtpEndpointTest extends ControllerTestCase
{
    private function controller(?Config $config = null): OtpController
    {
        return new OtpController($this->otpService($config ?? $this->testConfig()));
    }

    private function request(string $path, array $body): Request
    {
        return new Request(
            method: 'POST',
            path: '/auth/v1' . $path,
            rawBody: json_encode($body),
            ip: '203.0.113.7',
        );
    }

    public function test_otp_creates_user_by_default_and_mails_code(): void
    {
        $res = $this->controller()->otp(
            $this->request('/otp', ['email' => 'otp-new@example.com']),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $this->assertSame('[]', $res->body);
        $this->assertCount(1, $this->mailer->sent);
        $this->assertNotNull($this->users()->findByEmail('otp-new@example.com'));
    }

    public function test_otp_with_create_user_false_is_generic_for_unknown_email(): void
    {
        $res = $this->controller()->otp(
            $this->request('/otp', ['email' => 'ghost@example.com', 'create_user' => false]),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $this->assertSame('[]', $res->body);
        $this->assertSame([], $this->mailer->sent);
        $this->assertNull($this->users()->findByEmail('ghost@example.com'));
    }

    public function test_magiclink_never_creates_users(): void
    {
        $res = $this->controller()->magiclink(
            $this->request('/magiclink', ['email' => 'ml-ghost@example.com']),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $this->assertSame([], $this->mailer->sent);
        $this->assertNull($this->users()->findByEmail('ml-ghost@example.com'));
    }

    public function test_magiclink_mails_existing_user(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('ml@example.com', self::PASSWORD, 'ip');

        $res = $this->controller($config)->magiclink(
            $this->request('/magiclink', ['email' => 'ml@example.com']),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $this->assertCount(1, $this->mailer->sent);
        $this->assertStringContainsString('type=magiclink', $this->mailer->last()['text']);
    }

    public function test_otp_invalid_email_is_400(): void
    {
        $res = $this->controller()->otp(
            $this->request('/otp', ['email' => 'not-an-email']),
            new RequestContext(),
        );
        $this->assertSame(400, $res->status);
    }

    public function test_resend_signup_confirmation_for_unconfirmed_user(): void
    {
        $config = $this->testConfig(['signup' => ['autoconfirm' => false]]);
        $this->authService($config)->signup('pending@example.com', self::PASSWORD, 'ip');

        $res = $this->controller($config)->resend(
            $this->request('/resend', ['type' => 'signup', 'email' => 'pending@example.com']),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $this->assertCount(1, $this->mailer->sent);
        $this->assertStringContainsString('type=signup', $this->mailer->last()['text']);
    }

    public function test_resend_for_confirmed_user_is_generic_and_silent(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('confirmed@example.com', self::PASSWORD, 'ip');

        $res = $this->controller($config)->resend(
            $this->request('/resend', ['type' => 'signup', 'email' => 'confirmed@example.com']),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $this->assertSame('[]', $res->body);
        $this->assertSame([], $this->mailer->sent);
    }

    public function test_resend_rejects_unknown_type(): void
    {
        $res = $this->controller()->resend(
            $this->request('/resend', ['type' => 'nope', 'email' => 'x@example.com']),
            new RequestContext(),
        );
        $this->assertSame(400, $res->status);
    }
}
