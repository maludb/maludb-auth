<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\AdminActionsController;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Mail\MailComposer;
use Maludb\Auth\Security\TokenHash;
use Maludb\Auth\Support\Config;

final class AdminActionsEndpointTest extends ControllerTestCase
{
    private function controller(?Config $config = null): AdminActionsController
    {
        $config ??= $this->testConfig();

        return new AdminActionsController(
            $this->users(),
            $this->otpService($config),
            new MailComposer(
                (string) $config->get('app.url'),
                $config->get('site.url'),
            ),
            $this->audit(),
        );
    }

    private function request(string $method, string $path, array $body = [], array $query = []): Request
    {
        return new Request(
            method: $method,
            path: '/auth/v1' . $path,
            query: $query,
            rawBody: $body === [] ? '' : json_encode($body),
            ip: '203.0.113.11',
        );
    }

    // --- invite -----------------------------------------------------------

    public function test_invite_creates_passwordless_user_and_mails_invite(): void
    {
        $res = $this->controller()->invite(
            $this->request('POST', '/admin/invite', [
                'email' => 'invitee@example.com',
                'data' => ['team' => 'ops'],
            ]),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertSame('invitee@example.com', $body['email']);

        $user = $this->users()->findByEmail('invitee@example.com');
        $this->assertNotNull($user);
        $this->assertNull($user['encrypted_password']);
        $this->assertSame(['team' => 'ops'], $user['raw_user_meta_data']);

        $this->assertCount(1, $this->mailer->sent);
        $this->assertStringContainsString('type=invite', $this->mailer->last()['text']);
    }

    public function test_invite_confirmed_email_is_409(): void
    {
        $config = $this->testConfig();
        $this->authService($config)->signup('taken@example.com', self::PASSWORD, 'ip');

        $res = $this->controller($config)->invite(
            $this->request('POST', '/admin/invite', ['email' => 'taken@example.com']),
        );

        $this->assertSame(409, $res->status);
        $this->assertSame('email_exists', json_decode($res->body, true)['error']);
        $this->assertSame([], $this->mailer->sent);
    }

    public function test_invite_unconfirmed_existing_user_is_reinvited(): void
    {
        $config = $this->testConfig(['signup' => ['autoconfirm' => false]]);
        $this->authService($config)->signup('pending-inv@example.com', self::PASSWORD, 'ip');

        $res = $this->controller($config)->invite(
            $this->request('POST', '/admin/invite', ['email' => 'pending-inv@example.com']),
        );

        $this->assertSame(200, $res->status);
        $this->assertCount(1, $this->mailer->sent);
    }

    // --- generate_link ------------------------------------------------------

    public function test_generate_link_returns_redeemable_material_without_mailing(): void
    {
        $config = $this->testConfig();
        $c = $this->controller($config);
        $this->authService($config)->signup('linked@example.com', self::PASSWORD, 'ip');
        $otp = $this->otpService($config); // for redemption below

        $res = $c->generateLink(
            $this->request('POST', '/admin/generate_link', [
                'type' => 'recovery',
                'email' => 'linked@example.com',
                'redirect_to' => 'http://localhost:3000/reset',
            ]),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertSame('recovery', $body['verification_type']);
        $this->assertMatchesRegularExpression('/^[0-9]{6}$/', $body['email_otp']);
        $this->assertSame((new TokenHash())->hash($body['email_otp']), $body['hashed_token']);
        $this->assertStringContainsString('/auth/v1/verify?token_hash=' . $body['hashed_token'], $body['action_link']);
        $this->assertStringContainsString('type=recovery', $body['action_link']);

        // Nothing was mailed — that is the point of generate_link.
        $this->assertSame([], $this->mailer->sent);

        // The returned material actually redeems.
        $issued = $otp->verify('recovery', null, null, $body['hashed_token'], 'ip', 'ua');
        $this->assertNotEmpty($issued->accessToken);
    }

    public function test_generate_link_unknown_user_404_except_invite_creates(): void
    {
        $c = $this->controller();

        $miss = $c->generateLink($this->request('POST', '/admin/generate_link', [
            'type' => 'recovery', 'email' => 'nobody@example.com',
        ]));
        $this->assertSame(404, $miss->status);

        $invite = $c->generateLink($this->request('POST', '/admin/generate_link', [
            'type' => 'invite', 'email' => 'fresh-link@example.com',
        ]));
        $this->assertSame(200, $invite->status);
        $this->assertNotNull($this->users()->findByEmail('fresh-link@example.com'));
    }

    public function test_generate_link_rejects_unknown_type(): void
    {
        $res = $this->controller()->generateLink(
            $this->request('POST', '/admin/generate_link', ['type' => 'nope', 'email' => 'x@example.com']),
        );
        $this->assertSame(400, $res->status);
    }

    // --- audit --------------------------------------------------------------

    public function test_audit_log_lists_newest_first_with_pagination(): void
    {
        $audit = $this->audit();
        $audit->record('first_event', ['n' => 1], '1.1.1.1');
        $audit->record('second_event', ['n' => 2], '1.1.1.1');

        $res = $this->controller()->auditLog(
            $this->request('GET', '/admin/audit', [], ['per_page' => '1']),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertCount(1, $body['entries']);
        $this->assertSame('second_event', $body['entries'][0]['payload']['action']);

        $page2 = $this->controller()->auditLog(
            $this->request('GET', '/admin/audit', [], ['per_page' => '1', 'page' => '2']),
        );
        $entries2 = json_decode($page2->body, true)['entries'];
        $this->assertSame('first_event', $entries2[0]['payload']['action']);
    }
}
