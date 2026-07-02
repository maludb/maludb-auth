<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

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

/**
 * Proves the rotation is atomic in PRODUCTION conditions — i.e. when TokenService
 * owns its own transaction (no outer harness transaction). If issue() throws mid
 * rotation, the revoke of the old token must roll back so the old token stays
 * usable.
 *
 * This test therefore runs OUTSIDE the harness's rolled-back transaction: setUp
 * and tearDown are overridden to no-ops for the transaction, and seeded rows are
 * cleaned up manually (deleting the user cascades to sessions + refresh_tokens).
 */
final class TokenServiceRollbackTest extends IntegrationTestCase
{
    private string $userId = '';

    protected function setUp(): void
    {
        // Intentionally NOT starting a transaction: we need real commits so the
        // service can begin/commit/rollback its own transaction and we can observe
        // the persisted result across that boundary.
    }

    protected function tearDown(): void
    {
        if (self::$pdo->inTransaction()) {
            self::$pdo->rollBack();
        }
        if ($this->userId !== '') {
            self::$pdo->prepare('DELETE FROM auth.users WHERE id = :id')
                ->execute([':id' => $this->userId]);
        }
    }

    private function jwt(): Jwt
    {
        $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_pkey_export($res, $priv);
        $pub = openssl_pkey_get_details($res)['key'];

        return new Jwt($priv, $pub, 'key-1', 'test-iss', 'authenticated');
    }

    public function test_issue_failure_mid_rotation_rolls_back_revoke(): void
    {
        $hash = new TokenHash();

        $users = new UserRepository(self::$pdo);
        $sessions = new SessionRepository(self::$pdo);
        $realTokens = new RefreshTokenRepository(self::$pdo);

        // Seed a committed user + session + active refresh token via REAL repos.
        $user = $users->create([
            'email' => 'rollback@example.com',
            'email_confirmed_at' => '2026-01-01 00:00:00+00',
        ]);
        $this->userId = $user['id'];
        $session = $sessions->create($user['id'], 'csrf-rollback', '203.0.113.1', 'ua', null);

        $raw = $hash->random();
        $realTokens->issue($session['id'], $user['id'], $hash->hash($raw), null);

        // A refresh-token repo whose issue() ALWAYS throws — everything else real
        // (revokeIfActive, findByHash, findActiveBySession all use the parent).
        $faultyTokens = new class(self::$pdo) extends RefreshTokenRepository {
            public function issue(
                string $sessionId,
                string $userId,
                string $tokenHash,
                ?string $parent = null,
            ): array {
                throw new \RuntimeException('simulated issue() failure');
            }
        };

        $config = new Config([
            'jwt' => ['exp' => 3600, 'audience' => 'authenticated'],
            'session' => ['timebox' => 0, 'inactivity_timeout' => 0],
            'refresh' => ['reuse_interval' => 0],
        ]);

        $svc = new TokenService(
            $users,
            $sessions,
            $faultyTokens,
            new AuditRepository(self::$pdo),
            $this->jwt(),
            new Csrf(),
            $hash,
            new SessionService(),
            $config,
            self::$pdo,
        );

        // Rotation must fail because issue() throws.
        try {
            $svc->refresh($raw, '203.0.113.1', 'ua');
            $this->fail('Expected the simulated issue() failure to propagate.');
        } catch (\RuntimeException $e) {
            $this->assertSame('simulated issue() failure', $e->getMessage());
        }

        // The revoke of the old token must have rolled back: it is STILL usable.
        $row = $realTokens->findByHash($hash->hash($raw));
        $this->assertNotNull($row);
        $this->assertFalse((bool) $row['revoked'], 'Old token must survive a failed rotation (rollback).');

        // And no new/forked token was persisted for the session.
        $active = $realTokens->findActiveBySession($session['id']);
        $this->assertCount(1, $active);
        $this->assertSame($hash->hash($raw), $active[0]['token_hash']);
    }
}
