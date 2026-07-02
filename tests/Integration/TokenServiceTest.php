<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Exceptions\InvalidRefreshTokenException;
use Maludb\Auth\Exceptions\RefreshTokenReuseException;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\RefreshTokenRepository;
use Maludb\Auth\Repositories\SessionRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Security\Csrf;
use Maludb\Auth\Security\Jwt;
use Maludb\Auth\Security\TokenHash;
use Maludb\Auth\Services\SessionService;
use Maludb\Auth\Services\TokenService;
use Maludb\Auth\Support\Config;

final class TokenServiceTest extends IntegrationTestCase
{
    private static ?string $priv = null;
    private static ?string $pub = null;

    private function keys(): array
    {
        if (self::$priv === null) {
            $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
            openssl_pkey_export($res, $priv);
            self::$priv = $priv;
            self::$pub = openssl_pkey_get_details($res)['key'];
        }

        return [self::$priv, self::$pub];
    }

    private function jwt(): Jwt
    {
        [$priv, $pub] = $this->keys();

        return new Jwt($priv, $pub, 'key-1', 'test-iss', 'authenticated');
    }

    /** @param array<string,mixed> $configOverrides */
    private function tokenService(array $configOverrides = []): TokenService
    {
        // Merge nested overrides deeply so callers can tweak a single sub-key.
        // Default reuse_interval is 0 (grace window off) so the theft-detection
        // tests exercise the strict path; the grace-window test opts in explicitly.
        $config = new Config(array_replace_recursive([
            'jwt' => ['exp' => 3600, 'audience' => 'authenticated'],
            'session' => ['timebox' => 0, 'inactivity_timeout' => 0],
            'refresh' => ['reuse_interval' => 0],
        ], $configOverrides));

        return new TokenService(
            new UserRepository(self::$pdo),
            new SessionRepository(self::$pdo),
            new RefreshTokenRepository(self::$pdo),
            new AuditRepository(self::$pdo),
            $this->jwt(),
            new Csrf(),
            new TokenHash(),
            new SessionService(),
            $config,
            self::$pdo,
        );
    }

    /** @return array<string,mixed> */
    private function createUser(string $email = 'token@example.com'): array
    {
        return (new UserRepository(self::$pdo))->create([
            'email' => $email,
            'email_confirmed_at' => '2026-01-01 00:00:00+00',
            'raw_app_meta_data' => ['provider' => 'email', 'providers' => ['email']],
            'raw_user_meta_data' => ['display_name' => 'Tokey'],
        ]);
    }

    // --- 1a: issue -------------------------------------------------------

    public function test_issue_creates_session_access_and_refresh(): void
    {
        $svc = $this->tokenService();
        $user = $this->createUser();

        $issued = $svc->issueForUser($user, '203.0.113.1', 'phpunit', 'aal1', ['password']);

        $this->assertNotEmpty($issued->accessToken);
        $this->assertNotEmpty($issued->refreshToken);
        $this->assertNotEmpty($issued->csrfToken);
        $this->assertSame(3600, $issued->expiresIn);

        // A session row exists.
        $session = (new SessionRepository(self::$pdo))->find($issued->sessionId);
        $this->assertNotNull($session);
        $this->assertSame($issued->csrfToken, $session['csrf_token']);
        $this->assertSame('aal1', $session['aal']);

        // The refresh token is stored HASHED, never raw.
        $tokens = new RefreshTokenRepository(self::$pdo);
        $this->assertNull($tokens->findByHash($issued->refreshToken)); // raw not in DB
        $hashed = (new TokenHash())->hash($issued->refreshToken);
        $this->assertNotNull($tokens->findByHash($hashed));

        // Access token claims round-trip and reflect user + session.
        $claims = $this->jwt()->verify($issued->accessToken);
        $this->assertSame($user['id'], $claims['sub']);
        $this->assertSame('token@example.com', $claims['email']);
        $this->assertSame('authenticated', $claims['role']);
        $this->assertSame('aal1', $claims['aal']);
        $this->assertSame($issued->sessionId, $claims['session_id']);
        $this->assertFalse($claims['is_anonymous']);
        $this->assertSame(['provider' => 'email', 'providers' => ['email']], $claims['app_metadata']);
        $this->assertSame(['display_name' => 'Tokey'], $claims['user_metadata']);
        $this->assertSame('password', $claims['amr'][0]['method']);
        $this->assertArrayHasKey('timestamp', $claims['amr'][0]);
    }

    public function test_issue_with_aal2_sets_session_aal(): void
    {
        $svc = $this->tokenService();
        $user = $this->createUser();

        $issued = $svc->issueForUser($user, '203.0.113.1', 'phpunit', 'aal2', ['password', 'totp']);

        $session = (new SessionRepository(self::$pdo))->find($issued->sessionId);
        $this->assertSame('aal2', $session['aal']);
        $claims = $this->jwt()->verify($issued->accessToken);
        $this->assertSame('aal2', $claims['aal']);
        $this->assertCount(2, $claims['amr']);
    }

    public function test_issue_sets_not_after_when_timebox_enabled(): void
    {
        $svc = $this->tokenService(['session' => ['timebox' => 7200]]);
        $user = $this->createUser();

        $issued = $svc->issueForUser($user, '203.0.113.1', 'phpunit', 'aal1', ['password']);
        $session = (new SessionRepository(self::$pdo))->find($issued->sessionId);
        $this->assertNotNull($session['not_after']);
    }

    // --- 1b: rotation ----------------------------------------------------

    public function test_refresh_rotates_and_revokes_old(): void
    {
        $svc = $this->tokenService();
        $user = $this->createUser();
        $first = $svc->issueForUser($user, '203.0.113.1', 'ua', 'aal1', ['password']);

        $second = $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');
        $this->assertNotSame($first->refreshToken, $second->refreshToken);
        $this->assertSame($first->sessionId, $second->sessionId);
        // CSRF is stable across a refresh (same session).
        $this->assertSame($first->csrfToken, $second->csrfToken);

        // New token chains to the old one's hash.
        $tokens = new RefreshTokenRepository(self::$pdo);
        $newRow = $tokens->findByHash((new TokenHash())->hash($second->refreshToken));
        $this->assertSame((new TokenHash())->hash($first->refreshToken), $newRow['parent']);

        // Old token is revoked; reusing it (outside reuse interval) => theft.
        $oldRow = $tokens->findByHash((new TokenHash())->hash($first->refreshToken));
        $this->assertTrue((bool) $oldRow['revoked']);

        $this->expectException(RefreshTokenReuseException::class);
        $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');
    }

    public function test_refresh_reissues_working_access_token(): void
    {
        $svc = $this->tokenService();
        $user = $this->createUser();
        $first = $svc->issueForUser($user, '203.0.113.1', 'ua', 'aal1', ['password']);
        $second = $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');

        $claims = $this->jwt()->verify($second->accessToken);
        $this->assertSame($user['id'], $claims['sub']);
        $this->assertSame($first->sessionId, $claims['session_id']);
    }

    public function test_refresh_unknown_token_throws_invalid(): void
    {
        $svc = $this->tokenService();
        $this->expectException(InvalidRefreshTokenException::class);
        $svc->refresh('not-a-real-token', '203.0.113.1', 'ua');
    }

    // --- 1c: theft revokes the whole family ------------------------------

    public function test_reuse_revokes_entire_session(): void
    {
        $svc = $this->tokenService();
        $user = $this->createUser();
        $first = $svc->issueForUser($user, '203.0.113.1', 'ua', 'aal1', ['password']);
        $second = $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');

        // Reuse of the old (revoked) token triggers theft handling.
        try {
            $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');
        } catch (RefreshTokenReuseException) {
            // expected
        }

        // The legitimately-rotated token is now also dead.
        $this->expectException(RefreshTokenReuseException::class);
        $svc->refresh($second->refreshToken, '203.0.113.1', 'ua');
    }

    // --- grace window: tolerate a client retry ---------------------------

    public function test_reuse_within_grace_window_returns_active_session(): void
    {
        // Wide reuse interval so the just-revoked token is "recent".
        $svc = $this->tokenService(['refresh' => ['reuse_interval' => 3600]]);
        $user = $this->createUser();
        $first = $svc->issueForUser($user, '203.0.113.1', 'ua', 'aal1', ['password']);
        $second = $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');

        // Replaying the just-rotated token within the grace window must NOT throw;
        // it returns fresh access for the still-active session (client retry).
        $retry = $svc->refresh($first->refreshToken, '203.0.113.1', 'ua');
        $this->assertSame($first->sessionId, $retry->sessionId);
        $this->assertNotEmpty($retry->accessToken);

        // The active token from the real rotation still works afterward.
        $claims = $this->jwt()->verify($retry->accessToken);
        $this->assertSame($user['id'], $claims['sub']);

        // And the session family was NOT revoked by the grace-window retry.
        $tokens = new RefreshTokenRepository(self::$pdo);
        $activeRow = $tokens->findByHash((new TokenHash())->hash($second->refreshToken));
        $this->assertFalse((bool) $activeRow['revoked']);
    }
}
