<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\RecoverController;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Support\Config;

final class RecoverEndpointTest extends ControllerTestCase
{
    private function controller(?Config $config = null): RecoverController
    {
        return new RecoverController(
            $this->otpService($config ?? $this->testConfig()),
            $this->users(),
        );
    }

    private function request(array $body): Request
    {
        return new Request(
            method: 'POST',
            path: '/auth/v1/recover',
            rawBody: json_encode($body),
            ip: '203.0.113.5',
        );
    }

    public function test_recover_existing_email_returns_generic_200_and_mails_a_code(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('exists@example.com', self::PASSWORD, '203.0.113.5');

        $res = $this->controller($config)->recover($this->request(['email' => 'exists@example.com']), new RequestContext());

        $this->assertSame(200, $res->status);
        $this->assertArrayNotHasKey('error', (array) json_decode($res->body, true));
        $this->assertCount(1, $this->mailer->sent);
        $this->assertSame('exists@example.com', $this->mailer->last()['to']);
        $this->mailedCode(); // asserts a 6-digit code is present
    }

    public function test_recover_nonexistent_email_returns_same_generic_200_and_no_mail(): void
    {
        $res = $this->controller()->recover($this->request(['email' => 'ghost@example.com']), new RequestContext());

        $this->assertSame(200, $res->status);
        // Byte-identical to the existing-email response: no enumeration signal.
        $this->assertSame('[]', $res->body);
        $this->assertSame([], $this->mailer->sent);
    }

    public function test_recover_existing_and_nonexistent_are_indistinguishable(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('present@example.com', self::PASSWORD, '203.0.113.5');

        $a = $this->controller()->recover($this->request(['email' => 'present@example.com']), new RequestContext());
        $b = $this->controller()->recover($this->request(['email' => 'absent@example.com']), new RequestContext());

        $this->assertSame($a->status, $b->status);
        $this->assertSame($a->body, $b->body);
    }

    public function test_recover_invalid_email_returns_400(): void
    {
        $res = $this->controller()->recover($this->request(['email' => 'nope']), new RequestContext());
        $this->assertSame(400, $res->status);
    }

    public function test_reauthenticate_requires_auth(): void
    {
        $res = $this->controller()->reauthenticate($this->request([]), new RequestContext());
        $this->assertSame(401, $res->status);
    }

    public function test_reauthenticate_authenticated_returns_200_and_mails_a_nonce(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('reauth@example.com', self::PASSWORD, '203.0.113.5');
        $issued = $this->authService($config)->login('reauth@example.com', self::PASSWORD, '203.0.113.5', 'ua');
        $ctx = $this->contextFor($issued->accessToken);

        $res = $this->controller($config)->reauthenticate($this->request([]), $ctx);
        $this->assertSame(200, $res->status);
        $this->assertCount(1, $this->mailer->sent);
        // Nonce mails are code-only: no verify link to hijack.
        $this->assertStringNotContainsString('/verify', $this->mailer->last()['text']);
    }
}
