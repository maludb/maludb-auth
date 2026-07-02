<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\App;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Mail\ArrayMailer;
use Maludb\Auth\Support\Database;

/**
 * Phase 2 finale: the passwordless journeys through the REAL router + full
 * middleware chain (App::handle), with mail captured by an injected
 * ArrayMailer. Mirrors EndToEndAuthFlowTest's harness: real config + keys,
 * bound to the rolled-back test PDO; distinct IPs per test so the real rate
 * limiter can't cross-contaminate.
 */
final class EndToEndPasswordlessFlowTest extends IntegrationTestCase
{
    private App $app;
    private ArrayMailer $mailer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->mailer = new ArrayMailer();
        $this->app = App::fromConfig(
            $this->config,
            new Database($this->config),
            self::$pdo,
            dirname(__DIR__, 2),
            $this->mailer,
        );
    }

    private function req(
        string $method,
        string $path,
        array $query = [],
        array $headers = [],
        array $body = [],
        string $ip = '203.0.113.30',
    ): Request {
        return new Request(
            method: $method,
            path: '/auth/v1' . $path,
            query: $query,
            headers: $headers + ['User-Agent' => 'phpunit'],
            rawBody: $body === [] ? '' : (string) json_encode($body),
            cookies: [],
            ip: $ip,
        );
    }

    private function json(Response $res): array
    {
        return json_decode($res->body, true) ?? [];
    }

    private function mailedCode(): string
    {
        $last = $this->mailer->last();
        $this->assertNotNull($last, 'Expected a captured mail.');
        preg_match('/code: ([0-9]{6})/', $last['text'], $m);
        $this->assertNotEmpty($m);

        return $m[1];
    }

    private function mailedTokenHash(): string
    {
        $last = $this->mailer->last();
        $this->assertNotNull($last, 'Expected a captured mail.');
        preg_match('/token_hash=([0-9a-f]{64})/', $last['text'], $m);
        $this->assertNotEmpty($m);

        return $m[1];
    }

    public function test_full_otp_signup_verify_recover_and_password_set_journey(): void
    {
        $ip = '203.0.113.31';
        $email = 'journey@example.com';

        // 1. POST /otp for a brand-new email → generic 200, user created, mail sent.
        $res = $this->app->handle($this->req('POST', '/otp', body: ['email' => $email], ip: $ip));
        $this->assertSame(200, $res->status);
        $this->assertSame('[]', $res->body);
        $this->assertCount(1, $this->mailer->sent);

        // 2. POST /verify with the mailed code → session tokens.
        $code = $this->mailedCode();
        $verify = $this->app->handle($this->req('POST', '/verify', body: [
            'type' => 'magiclink', 'email' => $email, 'token' => $code,
        ], ip: $ip));
        $this->assertSame(200, $verify->status);
        $tokens = $this->json($verify);
        $this->assertNotEmpty($tokens['access_token']);

        // 3. The session works against GET /user.
        $me = $this->app->handle($this->req('GET', '/user', headers: [
            'Authorization' => 'Bearer ' . $tokens['access_token'],
        ], ip: $ip));
        $this->assertSame(200, $me->status);
        $this->assertSame($email, $this->json($me)['email']);

        // 4. Replaying the consumed code fails with the generic OTP error.
        $replay = $this->app->handle($this->req('POST', '/verify', body: [
            'type' => 'magiclink', 'email' => $email, 'token' => $code,
        ], ip: $ip));
        $this->assertSame(401, $replay->status);
        $this->assertSame('otp_expired', $this->json($replay)['error']);

        // 5. POST /recover → recovery mail; GET /verify link redirects with
        //    tokens in the fragment to an allow-listed target.
        $recover = $this->app->handle($this->req('POST', '/recover', body: ['email' => $email], ip: $ip));
        $this->assertSame(200, $recover->status);
        $hash = $this->mailedTokenHash();

        $link = $this->app->handle($this->req('GET', '/verify', query: [
            'token_hash' => $hash,
            'type' => 'recovery',
            'redirect_to' => 'http://localhost:3000/reset',
        ], ip: $ip));
        $this->assertSame(302, $link->status);
        $location = $link->headers['Location'];
        $this->assertStringStartsWith('http://localhost:3000/reset#', $location);
        parse_str(explode('#', $location, 2)[1], $frag);
        $this->assertArrayHasKey('access_token', $frag);

        // 6. That recovery session sets a first password via PUT /user (Bearer
        //    mode: no CSRF needed)...
        $put = $this->app->handle($this->req('PUT', '/user', headers: [
            'Authorization' => 'Bearer ' . $frag['access_token'],
        ], body: ['password' => 'a-brand-new-strong-password'], ip: $ip));
        $this->assertSame(200, $put->status);

        // 7. ...and password login now succeeds for the once-passwordless user.
        $login = $this->app->handle($this->req('POST', '/token', query: ['grant_type' => 'password'], body: [
            'email' => $email, 'password' => 'a-brand-new-strong-password',
        ], ip: $ip));
        $this->assertSame(200, $login->status);
        $this->assertNotEmpty($this->json($login)['access_token']);
    }

    public function test_get_verify_with_foreign_redirect_falls_back_to_site_url(): void
    {
        $ip = '203.0.113.32';
        $email = 'fallback@example.com';
        $this->app->handle($this->req('POST', '/otp', body: ['email' => $email], ip: $ip));
        $hash = $this->mailedTokenHash();

        $res = $this->app->handle($this->req('GET', '/verify', query: [
            'token_hash' => $hash,
            'type' => 'magiclink',
            'redirect_to' => 'https://evil.example/phish',
        ], ip: $ip));

        $this->assertSame(302, $res->status);
        $siteUrl = (string) $this->config->get('site.url');
        $this->assertStringStartsWith($siteUrl . '#', $res->headers['Location']);
    }

    public function test_otp_endpoint_is_rate_limited(): void
    {
        $ip = '203.0.113.33';
        // Capacity for the otp category is 10 (config/ratelimits.php); the
        // email varies so only the IP bucket is under test.
        $status = null;
        for ($i = 0; $i < 11; $i++) {
            $res = $this->app->handle($this->req('POST', '/otp', body: [
                'email' => "burst{$i}@example.com",
            ], ip: $ip));
            $status = $res->status;
        }

        $this->assertSame(429, $status);
    }

    public function test_settings_reports_otp_ttl(): void
    {
        $res = $this->app->handle($this->req('GET', '/settings'));
        $this->assertSame(200, $res->status);
        $this->assertArrayHasKey('mailer_otp_exp', $this->json($res));
    }
}
