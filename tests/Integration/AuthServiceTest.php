<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Dto\IssuedTokens;
use Maludb\Auth\Exceptions\DuplicateEmailException;
use Maludb\Auth\Exceptions\InvalidCredentialsException;
use Maludb\Auth\Exceptions\SignupDisabledException;
use Maludb\Auth\Exceptions\UserBannedException;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\IdentityRepository;
use Maludb\Auth\Repositories\RefreshTokenRepository;
use Maludb\Auth\Repositories\SessionRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Security\Csrf;
use Maludb\Auth\Security\Jwt;
use Maludb\Auth\Security\Password;
use Maludb\Auth\Security\TokenHash;
use Maludb\Auth\Services\AuthService;
use Maludb\Auth\Services\SessionService;
use Maludb\Auth\Services\TokenService;
use Maludb\Auth\Support\Config;

final class AuthServiceTest extends IntegrationTestCase
{
    private static ?string $priv = null;
    private static ?string $pub = null;

    private const PASSWORD = 'correct horse battery staple';

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
    private function authService(array $configOverrides = []): AuthService
    {
        $config = new Config(array_replace_recursive([
            'jwt' => ['exp' => 3600, 'audience' => 'authenticated'],
            'session' => ['timebox' => 0, 'inactivity_timeout' => 0],
            'refresh' => ['reuse_interval' => 0],
            'password' => ['min_length' => 12],
            'signup' => ['disabled' => false, 'autoconfirm' => true],
        ], $configOverrides));

        $users = new UserRepository(self::$pdo);
        $tokenService = new TokenService(
            $users,
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

        return new AuthService(
            $users,
            $tokenService,
            new Password((int) $config->get('password.min_length', 12)),
            new AuditRepository(self::$pdo),
            new IdentityRepository(self::$pdo),
            $config,
        );
    }

    // --- signup ----------------------------------------------------------

    public function test_signup_creates_user_and_email_identity_autoconfirmed(): void
    {
        $svc = $this->authService();

        $user = $svc->signup('New.User@Example.com', self::PASSWORD, '203.0.113.9');

        // User row created with normalized email and server-controlled app metadata.
        $this->assertNotEmpty($user['id']);
        $this->assertSame('new.user@example.com', $user['email']);
        $this->assertSame(['provider' => 'email', 'providers' => ['email']], $user['raw_app_meta_data']);
        // Autoconfirm on: email_confirmed_at is set and reflected in the return value.
        $this->assertNotNull($user['email_confirmed_at']);

        // Persisted user confirms the same.
        $persisted = (new UserRepository(self::$pdo))->findById($user['id']);
        $this->assertNotNull($persisted['email_confirmed_at']);

        // An email identity was created.
        $identities = (new IdentityRepository(self::$pdo))->findByUserId($user['id']);
        $this->assertCount(1, $identities);
        $identity = $identities[0];
        $this->assertSame('email', $identity['provider']);
        $this->assertSame($user['id'], $identity['provider_id']);
        $this->assertSame('new.user@example.com', $identity['email']);
        $this->assertSame($user['id'], $identity['identity_data']['sub']);
        $this->assertSame('new.user@example.com', $identity['identity_data']['email']);
        $this->assertTrue($identity['identity_data']['email_verified']);
        $this->assertSame('email', $identity['identity_data']['provider']);

        // Audit 'signup' recorded.
        $recent = (new AuditRepository(self::$pdo))->recent(5);
        $this->assertSame('signup', $recent[0]['payload']['action']);
        $this->assertSame($user['id'], $recent[0]['payload']['user_id']);
    }

    public function test_signup_without_autoconfirm_leaves_email_unconfirmed(): void
    {
        $svc = $this->authService(['signup' => ['autoconfirm' => false]]);

        $user = $svc->signup('noconfirm@example.com', self::PASSWORD, '203.0.113.9');

        $this->assertNull($user['email_confirmed_at']);
        $identities = (new IdentityRepository(self::$pdo))->findByUserId($user['id']);
        $this->assertFalse($identities[0]['identity_data']['email_verified']);
    }

    public function test_signup_disabled_throws(): void
    {
        $svc = $this->authService(['signup' => ['disabled' => true]]);

        $this->expectException(SignupDisabledException::class);
        $svc->signup('nope@example.com', self::PASSWORD, '203.0.113.9');
    }

    public function test_signup_duplicate_email_throws(): void
    {
        $svc = $this->authService();
        $svc->signup('dupe@example.com', self::PASSWORD, '203.0.113.9');

        $this->expectException(DuplicateEmailException::class);
        // Different casing/whitespace must still collide (normalized on both paths).
        $svc->signup('  Dupe@Example.com  ', self::PASSWORD, '203.0.113.9');
    }

    public function test_signup_short_password_throws(): void
    {
        $svc = $this->authService();

        $this->expectException(\InvalidArgumentException::class);
        $svc->signup('short@example.com', 'tiny', '203.0.113.9');
    }

    public function test_signup_password_is_hashed_not_stored_plaintext(): void
    {
        $svc = $this->authService();
        $user = $svc->signup('hash@example.com', self::PASSWORD, '203.0.113.9');

        $persisted = (new UserRepository(self::$pdo))->findById($user['id']);
        $this->assertNotSame(self::PASSWORD, $persisted['encrypted_password']);
        $this->assertTrue((new Password(12))->verify(self::PASSWORD, $persisted['encrypted_password']));
    }

    // --- login -----------------------------------------------------------

    public function test_login_valid_credentials_returns_tokens(): void
    {
        $svc = $this->authService();
        $svc->signup('login@example.com', self::PASSWORD, '203.0.113.9');

        $issued = $svc->login('Login@Example.com', self::PASSWORD, '203.0.113.9', 'phpunit-ua');

        $this->assertInstanceOf(IssuedTokens::class, $issued);
        $this->assertNotEmpty($issued->accessToken);
        $this->assertNotEmpty($issued->refreshToken);

        // Access token verifies and carries the user's subject.
        $claims = $this->jwt()->verify($issued->accessToken);
        $this->assertSame($issued->user['id'], $claims['sub']);

        // A session exists.
        $session = (new SessionRepository(self::$pdo))->find($issued->sessionId);
        $this->assertNotNull($session);

        // last_sign_in_at set.
        $persisted = (new UserRepository(self::$pdo))->findById($issued->user['id']);
        $this->assertNotNull($persisted['last_sign_in_at']);

        // Audit 'login' recorded.
        $recent = (new AuditRepository(self::$pdo))->recent(5);
        $actions = array_column(array_column($recent, 'payload'), 'action');
        $this->assertContains('login', $actions);
    }

    public function test_login_wrong_password_throws_invalid_credentials(): void
    {
        $svc = $this->authService();
        $svc->signup('wrongpw@example.com', self::PASSWORD, '203.0.113.9');

        $this->expectException(InvalidCredentialsException::class);
        $svc->login('wrongpw@example.com', 'this is the wrong password', '203.0.113.9', 'ua');
    }

    public function test_login_unknown_email_throws_invalid_credentials(): void
    {
        $svc = $this->authService();

        // Routes through Password::verify against dummyHash() so no timing leak.
        $this->expectException(InvalidCredentialsException::class);
        $svc->login('ghost@example.com', self::PASSWORD, '203.0.113.9', 'ua');
    }

    public function test_login_banned_user_throws(): void
    {
        $svc = $this->authService();
        $user = $svc->signup('banned@example.com', self::PASSWORD, '203.0.113.9');

        self::$pdo->prepare(
            "UPDATE auth.users SET banned_until = now() + interval '1 hour' WHERE id = :id"
        )->execute([':id' => $user['id']]);

        $this->expectException(UserBannedException::class);
        $svc->login('banned@example.com', self::PASSWORD, '203.0.113.9', 'ua');
    }

    public function test_login_expired_ban_still_succeeds(): void
    {
        $svc = $this->authService();
        $user = $svc->signup('unbanned@example.com', self::PASSWORD, '203.0.113.9');

        self::$pdo->prepare(
            "UPDATE auth.users SET banned_until = now() - interval '1 hour' WHERE id = :id"
        )->execute([':id' => $user['id']]);

        $issued = $svc->login('unbanned@example.com', self::PASSWORD, '203.0.113.9', 'ua');
        $this->assertNotEmpty($issued->accessToken);
    }
}
