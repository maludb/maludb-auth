<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\App;
use Maludb\Auth\Http\Request;

final class MetaEndpointsTest extends IntegrationTestCase
{
    public function test_health(): void
    {
        $res = App::boot()->handle(new Request(method: 'GET', path: '/auth/v1/health'));
        $this->assertSame(200, $res->status);

        $body = json_decode($res->body, true);
        $this->assertSame('maludb-auth', $body['name']);
        $this->assertArrayHasKey('version', $body);
    }

    public function test_settings_lists_enabled_flows(): void
    {
        $res = App::boot()->handle(new Request(method: 'GET', path: '/auth/v1/settings'));
        $this->assertSame(200, $res->status);

        $body = json_decode($res->body, true);
        $this->assertArrayHasKey('disable_signup', $body);
        $this->assertArrayHasKey('mailer_autoconfirm', $body);
    }

    public function test_security_headers_present(): void
    {
        $res = App::boot()->handle(new Request(method: 'GET', path: '/auth/v1/health'));
        $this->assertSame('no-store', $res->headers['Cache-Control']);
        $this->assertSame('nosniff', $res->headers['X-Content-Type-Options']);
    }

    public function test_jwks_exposes_public_key(): void
    {
        $res = App::boot()->handle(new Request(method: 'GET', path: '/auth/v1/.well-known/jwks.json'));
        $this->assertSame(200, $res->status);

        $body = json_decode($res->body, true);
        $key = $body['keys'][0];
        $this->assertSame('RSA', $key['kty']);
        $this->assertSame('sig', $key['use']);
        $this->assertSame('RS256', $key['alg']);
        $this->assertArrayHasKey('kid', $key);
        $this->assertArrayHasKey('n', $key);
        $this->assertArrayHasKey('e', $key);
        // base64url, no padding
        $this->assertDoesNotMatchRegularExpression('/[+\/=]/', $key['n']);
        $this->assertDoesNotMatchRegularExpression('/[+\/=]/', $key['e']);
    }

    public function test_jwks_n_and_e_match_public_key(): void
    {
        $res = App::boot()->handle(new Request(method: 'GET', path: '/auth/v1/.well-known/jwks.json'));
        $key = json_decode($res->body, true)['keys'][0];

        $base = dirname(__DIR__, 2);
        $pem = file_get_contents($base . '/keys/jwt_public.pem');
        $details = openssl_pkey_get_details(openssl_pkey_get_public($pem));

        $b64url = static fn(string $bin): string =>
            rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');

        $this->assertSame($b64url($details['rsa']['n']), $key['n']);
        $this->assertSame($b64url($details['rsa']['e']), $key['e']);
    }
}
