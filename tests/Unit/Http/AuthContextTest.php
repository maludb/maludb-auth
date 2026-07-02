<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\Middleware\AuthContext;
use Maludb\Auth\Http\{Request, RequestContext, Response};
use Maludb\Auth\Security\Jwt;
use PHPUnit\Framework\TestCase;

final class AuthContextTest extends TestCase
{
    private Jwt $jwt;

    protected function setUp(): void
    {
        $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_pkey_export($res, $priv);
        $pub = openssl_pkey_get_details($res)['key'];
        $this->jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');
    }

    private function next(): callable
    {
        return fn(Request $r): Response => Response::json(['ok' => true]);
    }

    private function token(array $claims = ['sub' => 'user-1', 'session_id' => 'sess-1', 'role' => 'authenticated']): string
    {
        return $this->jwt->issue($claims, 3600);
    }

    public function test_valid_bearer_sets_user_not_via_cookie(): void
    {
        $ctx = new RequestContext();
        $mw = new AuthContext($this->jwt, $ctx);
        $req = new Request(method: 'GET', path: '/x', headers: ['Authorization' => 'Bearer ' . $this->token()]);

        $mw->handle($req, $this->next());

        $this->assertNotNull($ctx->user);
        $this->assertSame('user-1', $ctx->user->userId);
        $this->assertSame('sess-1', $ctx->user->sessionId);
        $this->assertSame('authenticated', $ctx->user->role);
        $this->assertFalse($ctx->user->viaCookie);
    }

    public function test_valid_cookie_sets_user_via_cookie(): void
    {
        $ctx = new RequestContext();
        $mw = new AuthContext($this->jwt, $ctx);
        $req = new Request(
            method: 'GET',
            path: '/x',
            cookies: [AuthContext::ACCESS_TOKEN_COOKIE => $this->token()],
        );

        $mw->handle($req, $this->next());

        $this->assertNotNull($ctx->user);
        $this->assertSame('user-1', $ctx->user->userId);
        $this->assertTrue($ctx->user->viaCookie);
    }

    public function test_invalid_token_leaves_user_null(): void
    {
        $ctx = new RequestContext();
        $mw = new AuthContext($this->jwt, $ctx);
        $req = new Request(method: 'GET', path: '/x', headers: ['Authorization' => 'Bearer not-a-jwt']);

        $mw->handle($req, $this->next());

        $this->assertNull($ctx->user);
    }

    public function test_expired_token_leaves_user_null(): void
    {
        $expired = $this->jwt->issue(['sub' => 'user-1'], -3600); // already expired, beyond leeway
        $ctx = new RequestContext();
        $mw = new AuthContext($this->jwt, $ctx);
        $req = new Request(method: 'GET', path: '/x', headers: ['Authorization' => 'Bearer ' . $expired]);

        $mw->handle($req, $this->next());

        $this->assertNull($ctx->user);
    }

    public function test_no_token_leaves_user_null(): void
    {
        $ctx = new RequestContext();
        $mw = new AuthContext($this->jwt, $ctx);
        $req = new Request(method: 'GET', path: '/x');

        $mw->handle($req, $this->next());

        $this->assertNull($ctx->user);
    }

    public function test_bearer_takes_precedence_over_cookie(): void
    {
        $bearer = $this->token(['sub' => 'bearer-user', 'session_id' => 's-b']);
        $cookie = $this->token(['sub' => 'cookie-user', 'session_id' => 's-c']);
        $ctx = new RequestContext();
        $mw = new AuthContext($this->jwt, $ctx);
        $req = new Request(
            method: 'GET',
            path: '/x',
            headers: ['Authorization' => 'Bearer ' . $bearer],
            cookies: [AuthContext::ACCESS_TOKEN_COOKIE => $cookie],
        );

        $mw->handle($req, $this->next());

        $this->assertNotNull($ctx->user);
        $this->assertSame('bearer-user', $ctx->user->userId);
        $this->assertFalse($ctx->user->viaCookie);
    }

    public function test_calls_next(): void
    {
        $ctx = new RequestContext();
        $mw = new AuthContext($this->jwt, $ctx);
        $req = new Request(method: 'GET', path: '/x');

        $res = $mw->handle($req, $this->next());

        $this->assertSame(200, $res->status);
    }
}
