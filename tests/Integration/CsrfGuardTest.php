<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Http\Middleware\CsrfGuard;
use Maludb\Auth\Http\{AuthenticatedUser, Request, RequestContext, Response};
use Maludb\Auth\Repositories\SessionRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Security\Csrf;

final class CsrfGuardTest extends IntegrationTestCase
{
    private const CSRF = 'the-known-good-csrf-token-value';

    private function sessions(): SessionRepository
    {
        return new SessionRepository(self::$pdo);
    }

    /** @return array{0:CsrfGuard,1:RequestContext} */
    private function guardWith(?AuthenticatedUser $user): array
    {
        $ctx = new RequestContext();
        $ctx->user = $user;
        return [new CsrfGuard($ctx, $this->sessions(), new Csrf()), $ctx];
    }

    private function next(): callable
    {
        return fn(Request $r): Response => Response::json(['reached' => true]);
    }

    private function makeSession(): string
    {
        $userId = (new UserRepository(self::$pdo))->create(['email' => 'csrf@example.com'])['id'];
        return $this->sessions()->create($userId, self::CSRF, '1.2.3.4', 'ua', null)['id'];
    }

    private function cookieUser(string $sessionId): AuthenticatedUser
    {
        return new AuthenticatedUser(
            userId: 'u', sessionId: $sessionId, role: 'authenticated', claims: [], viaCookie: true,
        );
    }

    public function test_cookie_auth_unsafe_missing_token_is_403(): void
    {
        $sid = $this->makeSession();
        [$guard] = $this->guardWith($this->cookieUser($sid));
        $req = new Request(method: 'POST', path: '/x'); // no X-CSRF-Token

        $res = $guard->handle($req, $this->next());

        $this->assertSame(403, $res->status);
        $this->assertStringContainsString('csrf_failed', $res->body);
    }

    public function test_cookie_auth_lowercase_unsafe_method_still_enforces_csrf(): void
    {
        // A lowercase `post` must not be treated as a safe method. If method
        // normalization regresses, isUnsafeMethod() returns false and CsrfGuard
        // skips the check entirely — a silent bypass. This asserts 403.
        $sid = $this->makeSession();
        [$guard] = $this->guardWith($this->cookieUser($sid));
        $req = new Request(method: 'post', path: '/x'); // lowercase, no X-CSRF-Token

        $res = $guard->handle($req, $this->next());

        $this->assertSame(403, $res->status);
    }

    public function test_cookie_auth_unsafe_wrong_token_is_403(): void
    {
        $sid = $this->makeSession();
        [$guard] = $this->guardWith($this->cookieUser($sid));
        $req = new Request(method: 'POST', path: '/x', headers: ['X-CSRF-Token' => 'wrong']);

        $res = $guard->handle($req, $this->next());

        $this->assertSame(403, $res->status);
    }

    public function test_cookie_auth_unsafe_correct_token_passes(): void
    {
        $sid = $this->makeSession();
        [$guard] = $this->guardWith($this->cookieUser($sid));
        $req = new Request(method: 'POST', path: '/x', headers: ['X-CSRF-Token' => self::CSRF]);

        $res = $guard->handle($req, $this->next());

        $this->assertSame(200, $res->status);
        $this->assertStringContainsString('reached', $res->body);
    }

    public function test_cookie_auth_safe_method_passes_without_token(): void
    {
        $sid = $this->makeSession();
        [$guard] = $this->guardWith($this->cookieUser($sid));
        $req = new Request(method: 'GET', path: '/x'); // safe, no token

        $res = $guard->handle($req, $this->next());

        $this->assertSame(200, $res->status);
    }

    public function test_bearer_auth_unsafe_skips_csrf(): void
    {
        $bearerUser = new AuthenticatedUser(
            userId: 'u', sessionId: 'sess', role: 'authenticated', claims: [], viaCookie: false,
        );
        [$guard] = $this->guardWith($bearerUser);
        $req = new Request(method: 'POST', path: '/x'); // no token, but bearer => skipped

        $res = $guard->handle($req, $this->next());

        $this->assertSame(200, $res->status);
    }

    public function test_unauthenticated_passes(): void
    {
        [$guard] = $this->guardWith(null);
        $req = new Request(method: 'POST', path: '/token');

        $res = $guard->handle($req, $this->next());

        $this->assertSame(200, $res->status);
    }

    public function test_cookie_auth_unsafe_missing_session_row_is_403(): void
    {
        $ghost = $this->cookieUser('00000000-0000-0000-0000-000000000000');
        [$guard] = $this->guardWith($ghost);
        $req = new Request(method: 'POST', path: '/x', headers: ['X-CSRF-Token' => self::CSRF]);

        $res = $guard->handle($req, $this->next());

        $this->assertSame(403, $res->status);
    }
}
