<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\VerifyController;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Security\RedirectValidator;
use Maludb\Auth\Services\OtpService;
use Maludb\Auth\Support\Config;

final class VerifyEndpointTest extends ControllerTestCase
{
    private OtpService $otp;

    private function controller(?Config $config = null): VerifyController
    {
        $config ??= $this->testConfig();
        $this->otp = $this->otpService($config);

        return new VerifyController(
            $this->otp,
            $this->responder(),
            new RedirectValidator(
                (string) $config->get('site.url'),
                (array) $config->get('site.uri_allow_list', []),
            ),
            $config,
        );
    }

    private function post(array $body, array $query = []): Request
    {
        return new Request(
            method: 'POST',
            path: '/auth/v1/verify',
            query: $query,
            rawBody: json_encode($body),
            ip: '203.0.113.9',
        );
    }

    private function get(array $query): Request
    {
        return new Request(
            method: 'GET',
            path: '/auth/v1/verify',
            query: $query,
            ip: '203.0.113.9',
        );
    }

    /** Signup + send a recovery mail; returns the mailed 6-digit code. */
    private function recoveryCodeFor(string $email, Config $config): string
    {
        $this->authService($config)->signup($email, self::PASSWORD, 'ip');
        $this->otp->send('recovery', $email, 'ip');

        return $this->mailedCode();
    }

    public function test_post_verify_code_form_returns_bearer_tokens(): void
    {
        $config = $this->testConfig();
        $c = $this->controller($config);
        $code = $this->recoveryCodeFor('post-code@example.com', $config);

        $res = $c->post($this->post([
            'type' => 'recovery', 'email' => 'post-code@example.com', 'token' => $code,
        ]), new RequestContext());

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertArrayHasKey('access_token', $body);
        $this->assertArrayHasKey('refresh_token', $body);
        $this->assertSame('bearer', $body['token_type']);
    }

    public function test_post_verify_token_hash_form_and_cookie_mode(): void
    {
        $config = $this->testConfig();
        $c = $this->controller($config);
        $this->recoveryCodeFor('post-hash@example.com', $config);
        $hash = $this->mailedTokenHash();

        $res = $c->post(
            $this->post(['type' => 'recovery', 'token_hash' => $hash], ['cookie' => 'true']),
            new RequestContext(),
        );

        $this->assertSame(200, $res->status);
        $body = json_decode($res->body, true);
        $this->assertArrayNotHasKey('access_token', $body);
        $names = array_column($res->cookies, 'name');
        $this->assertContains('mb-access-token', $names);
        $this->assertContains('mb-refresh-token', $names);
    }

    public function test_post_verify_replay_is_generic_401(): void
    {
        $config = $this->testConfig();
        $c = $this->controller($config);
        $code = $this->recoveryCodeFor('replay@example.com', $config);

        $first = $c->post($this->post([
            'type' => 'recovery', 'email' => 'replay@example.com', 'token' => $code,
        ]), new RequestContext());
        $this->assertSame(200, $first->status);

        $second = $c->post($this->post([
            'type' => 'recovery', 'email' => 'replay@example.com', 'token' => $code,
        ]), new RequestContext());
        $this->assertSame(401, $second->status);
        $this->assertSame('otp_expired', json_decode($second->body, true)['error']);
    }

    public function test_post_verify_unknown_type_is_400(): void
    {
        $c = $this->controller();
        $res = $c->post($this->post(['type' => 'weird', 'token_hash' => 'x']), new RequestContext());
        $this->assertSame(400, $res->status);
    }

    public function test_get_verify_redirects_with_tokens_in_fragment_only(): void
    {
        $config = $this->testConfig();
        $c = $this->controller($config);
        $this->recoveryCodeFor('get-happy@example.com', $config);
        $hash = $this->mailedTokenHash();

        $res = $c->get($this->get([
            'token_hash' => $hash,
            'type' => 'recovery',
            'redirect_to' => 'http://localhost:3000/reset',
        ]), new RequestContext());

        $this->assertSame(302, $res->status);
        $location = $res->headers['Location'];
        $this->assertStringStartsWith('http://localhost:3000/reset#', $location);

        [$beforeFragment, $fragment] = explode('#', $location, 2);
        $this->assertStringNotContainsString('access_token', $beforeFragment);
        parse_str($fragment, $params);
        $this->assertArrayHasKey('access_token', $params);
        $this->assertArrayHasKey('refresh_token', $params);
        $this->assertSame('bearer', $params['token_type']);
        $this->assertSame('recovery', $params['type']);
        $this->assertSame([], $res->cookies);
    }

    public function test_get_verify_appends_to_existing_hash_router_fragment(): void
    {
        $config = $this->testConfig();
        $c = $this->controller($config);
        $this->recoveryCodeFor('hashrouter@example.com', $config);
        $hash = $this->mailedTokenHash();

        $res = $c->get($this->get([
            'token_hash' => $hash,
            'type' => 'recovery',
            'redirect_to' => 'http://localhost:3000/#/auth/callback',
        ]), new RequestContext());

        $this->assertSame(302, $res->status);
        $location = $res->headers['Location'];
        // Exactly ONE '#': the SPA route stays intact and tokens join with '&'.
        $this->assertSame(1, substr_count($location, '#'));
        $this->assertStringStartsWith('http://localhost:3000/#/auth/callback&', $location);
        parse_str(explode('#', $location, 2)[1], $frag);
        // '/auth/callback' is the first key; access_token must still be parseable.
        $this->assertArrayHasKey('access_token', $frag);
    }

    public function test_get_verify_disallowed_redirect_falls_back_to_site_url(): void
    {
        $config = $this->testConfig();
        $c = $this->controller($config);
        $this->recoveryCodeFor('get-evil@example.com', $config);
        $hash = $this->mailedTokenHash();

        $res = $c->get($this->get([
            'token_hash' => $hash,
            'type' => 'recovery',
            'redirect_to' => 'https://evil.example/phish',
        ]), new RequestContext());

        $this->assertSame(302, $res->status);
        $this->assertStringStartsWith('http://localhost:3000#', $res->headers['Location']);
    }

    public function test_get_verify_failure_redirects_with_generic_error_fragment(): void
    {
        $c = $this->controller();

        $res = $c->get($this->get([
            'token_hash' => str_repeat('f', 64),
            'type' => 'recovery',
            'redirect_to' => 'http://localhost:3000/reset',
        ]), new RequestContext());

        $this->assertSame(302, $res->status);
        $location = $res->headers['Location'];
        $this->assertStringStartsWith('http://localhost:3000/reset#', $location);
        parse_str(explode('#', $location, 2)[1], $params);
        $this->assertSame('access_denied', $params['error']);
        $this->assertSame('otp_expired', $params['error_code']);
        $this->assertArrayNotHasKey('access_token', $params);
    }
}
