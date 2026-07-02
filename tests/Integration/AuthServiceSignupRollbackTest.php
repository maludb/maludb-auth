<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

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

/**
 * Proves signup is atomic in PRODUCTION conditions — i.e. when AuthService owns
 * its own transaction (no outer harness transaction). If the identity insert
 * throws mid-signup, the user insert must roll back so no orphaned user row is
 * left holding the unique email and blocking a retry.
 *
 * This test therefore runs OUTSIDE the harness's rolled-back transaction: setUp
 * and tearDown are overridden so no wrapping transaction is started, and any
 * seeded row is cleaned up manually.
 */
final class AuthServiceSignupRollbackTest extends IntegrationTestCase
{
    private const EMAIL = 'signup-rollback@example.com';
    private const PASSWORD = 'correct horse battery staple';

    protected function setUp(): void
    {
        // Intentionally NOT starting a transaction: we need real commits/rollbacks
        // so AuthService can own its own transaction and we can observe the
        // persisted result across that boundary. Clean any leftover from a prior run.
        $this->cleanup();
    }

    protected function tearDown(): void
    {
        if (self::$pdo->inTransaction()) {
            self::$pdo->rollBack();
        }
        $this->cleanup();
    }

    private function cleanup(): void
    {
        // Deleting the user cascades to identities/sessions/refresh_tokens.
        self::$pdo->prepare('DELETE FROM auth.users WHERE email = :email')
            ->execute([':email' => self::EMAIL]);
    }

    private function jwt(): Jwt
    {
        $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_pkey_export($res, $priv);
        $pub = openssl_pkey_get_details($res)['key'];

        return new Jwt($priv, $pub, 'key-1', 'test-iss', 'authenticated');
    }

    public function test_identity_failure_rolls_back_user_no_orphan(): void
    {
        $users = new UserRepository(self::$pdo);

        // An IdentityRepository whose create() always throws — everything else real.
        $faultyIdentities = new class(self::$pdo) extends IdentityRepository {
            public function create(array $attrs): array
            {
                throw new \RuntimeException('simulated identity create failure');
            }
        };

        $config = new Config([
            'jwt' => ['exp' => 3600, 'audience' => 'authenticated'],
            'session' => ['timebox' => 0, 'inactivity_timeout' => 0],
            'refresh' => ['reuse_interval' => 0],
            'password' => ['min_length' => 12],
            'signup' => ['disabled' => false, 'autoconfirm' => true],
        ]);

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

        $svc = new AuthService(
            $users,
            $tokenService,
            new Password(12),
            new AuditRepository(self::$pdo),
            $faultyIdentities,
            $config,
            self::$pdo,
        );

        // Signup must fail because the identity insert throws.
        try {
            $svc->signup(self::EMAIL, self::PASSWORD, '203.0.113.9');
            $this->fail('Expected the simulated identity create failure to propagate.');
        } catch (\RuntimeException $e) {
            $this->assertSame('simulated identity create failure', $e->getMessage());
        }

        // The user insert must have rolled back: no orphan holding the unique email.
        $this->assertNull(
            $users->findByEmail(self::EMAIL),
            'User insert must roll back when the identity insert fails (no orphan).',
        );
    }
}
