<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Exceptions\InvalidOtpException;
use Maludb\Auth\Exceptions\UserBannedException;
use Maludb\Auth\Mail\ArrayMailer;
use Maludb\Auth\Mail\MailComposer;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\IdentityRepository;
use Maludb\Auth\Repositories\OneTimeTokenRepository;
use Maludb\Auth\Repositories\RefreshTokenRepository;
use Maludb\Auth\Repositories\SessionRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Security\Csrf;
use Maludb\Auth\Security\Jwt;
use Maludb\Auth\Security\TokenHash;
use Maludb\Auth\Services\OtpService;
use Maludb\Auth\Services\SessionService;
use Maludb\Auth\Services\TokenService;
use Maludb\Auth\Support\Config;

final class OtpServiceTest extends IntegrationTestCase
{
    private static ?string $priv = null;
    private static ?string $pub = null;

    private ArrayMailer $mailer;

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
    private function otpService(array $configOverrides = []): OtpService
    {
        $config = new Config(array_replace_recursive([
            'jwt' => ['exp' => 3600, 'audience' => 'authenticated'],
            'session' => ['timebox' => 0, 'inactivity_timeout' => 0],
            'refresh' => ['reuse_interval' => 0],
            'signup' => ['disabled' => false, 'autoconfirm' => true],
            'otp' => ['ttl' => 3600],
            'app' => ['url' => 'http://localhost:8080'],
            'site' => ['url' => 'http://localhost:3000'],
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

        $this->mailer = new ArrayMailer();

        return new OtpService(
            $users,
            new IdentityRepository(self::$pdo),
            new OneTimeTokenRepository(self::$pdo),
            $tokenService,
            new AuditRepository(self::$pdo),
            $this->mailer,
            new MailComposer('http://localhost:8080', 'http://localhost:3000'),
            new TokenHash(),
            $config,
            self::$pdo,
        );
    }

    /** @return array<string,mixed> */
    private function createUser(string $email, bool $confirmed = true): array
    {
        $users = new UserRepository(self::$pdo);
        $user = $users->create(['email' => $email]);
        if ($confirmed) {
            $users->markEmailConfirmed($user['id']);
            $user = $users->findById($user['id']);
        }

        return $user;
    }

    /** Pull the 6-digit code out of the last captured mail. */
    private function mailedCode(): string
    {
        $text = (string) $this->mailer->last()['text'];
        $this->assertMatchesRegularExpression('/code: ([0-9]{6})/', $text);
        preg_match('/code: ([0-9]{6})/', $text, $m);

        return $m[1];
    }

    private function backdateToken(string $userId, string $type, int $seconds): void
    {
        $stmt = self::$pdo->prepare(
            "UPDATE auth.one_time_tokens
             SET created_at = now() - make_interval(secs => :s)
             WHERE user_id = :u AND token_type = :t"
        );
        $stmt->execute([':s' => $seconds, ':u' => $userId, ':t' => $type]);
    }

    // --- send --------------------------------------------------------------

    public function test_send_recovery_mints_row_and_mails_the_code(): void
    {
        $svc = $this->otpService();
        $user = $this->createUser('rec@example.com');

        $svc->send('recovery', 'rec@example.com', '203.0.113.1');

        $this->assertCount(1, $this->mailer->sent);
        $this->assertSame('rec@example.com', $this->mailer->last()['to']);

        $code = $this->mailedCode();
        $hash = (new TokenHash())->hash($code);
        $row = (new OneTimeTokenRepository(self::$pdo))->findByHash($hash);
        $this->assertNotNull($row);
        $this->assertSame($user['id'], $row['user_id']);
        $this->assertSame('recovery', $row['token_type']);
    }

    public function test_send_recovery_for_unknown_email_is_silent(): void
    {
        $svc = $this->otpService();
        $svc->send('recovery', 'ghost@example.com', '203.0.113.1');

        $this->assertSame([], $this->mailer->sent);
    }

    public function test_send_twice_leaves_single_live_token_and_old_code_dead(): void
    {
        $svc = $this->otpService();
        $user = $this->createUser('twice@example.com');

        $svc->send('recovery', 'twice@example.com', '203.0.113.1');
        $firstCode = $this->mailedCode();
        $svc->send('recovery', 'twice@example.com', '203.0.113.1');

        $count = (int) self::$pdo->query(
            "SELECT count(*) FROM auth.one_time_tokens WHERE token_type = 'recovery'"
        )->fetchColumn();
        $this->assertSame(1, $count);

        // Old code no longer verifies (unless both draws collide, which the
        // second assert tolerates by only running when they differ).
        $secondCode = $this->mailedCode();
        if ($firstCode !== $secondCode) {
            $this->expectException(InvalidOtpException::class);
            $svc->verify('recovery', 'twice@example.com', $firstCode, null, 'ip', 'ua');
        } else {
            $this->addToAssertionCount(1);
        }
    }

    public function test_send_magiclink_creates_passwordless_user_when_asked(): void
    {
        $svc = $this->otpService();

        $svc->send('magiclink', 'new-via-otp@example.com', '203.0.113.1', createUser: true);

        $user = (new UserRepository(self::$pdo))->findByEmail('new-via-otp@example.com');
        $this->assertNotNull($user);
        $this->assertNull($user['encrypted_password']);
        $this->assertCount(1, $this->mailer->sent);

        $identities = (new IdentityRepository(self::$pdo))->findByUserId($user['id']);
        $this->assertCount(1, $identities);
        $this->assertSame('email', $identities[0]['provider']);
    }

    public function test_send_magiclink_unknown_email_without_create_user_is_silent(): void
    {
        $svc = $this->otpService();
        $svc->send('magiclink', 'nobody@example.com', '203.0.113.1', createUser: false);

        $this->assertSame([], $this->mailer->sent);
        $this->assertNull((new UserRepository(self::$pdo))->findByEmail('nobody@example.com'));
    }

    public function test_send_magiclink_create_user_respects_disabled_signup(): void
    {
        $svc = $this->otpService(['signup' => ['disabled' => true]]);
        $svc->send('magiclink', 'blocked@example.com', '203.0.113.1', createUser: true);

        $this->assertSame([], $this->mailer->sent);
        $this->assertNull((new UserRepository(self::$pdo))->findByEmail('blocked@example.com'));
    }

    public function test_send_confirmation_to_already_confirmed_user_is_silent(): void
    {
        $svc = $this->otpService();
        $this->createUser('done@example.com', confirmed: true);

        $svc->send('confirmation', 'done@example.com', '203.0.113.1');

        $this->assertSame([], $this->mailer->sent);
    }

    // --- verify ------------------------------------------------------------

    public function test_verify_recovery_by_code_issues_session_and_consumes(): void
    {
        $svc = $this->otpService();
        $user = $this->createUser('verify@example.com');
        $svc->send('recovery', 'verify@example.com', '203.0.113.1');
        $code = $this->mailedCode();

        $issued = $svc->verify('recovery', 'verify@example.com', $code, null, '203.0.113.1', 'ua');

        $claims = $this->jwt()->verify($issued->accessToken);
        $this->assertSame($user['id'], $claims['sub']);
        $this->assertSame('otp', $claims['amr'][0]['method']);

        // Consumed: replay fails.
        $this->expectException(InvalidOtpException::class);
        $svc->verify('recovery', 'verify@example.com', $code, null, '203.0.113.1', 'ua');
    }

    public function test_verify_by_token_hash_link_form(): void
    {
        $svc = $this->otpService();
        $user = $this->createUser('link@example.com');
        $svc->send('recovery', 'link@example.com', '203.0.113.1');
        $hash = (new TokenHash())->hash($this->mailedCode());

        $issued = $svc->verify('recovery', null, null, $hash, '203.0.113.1', 'ua');
        $this->assertSame($user['id'], $this->jwt()->verify($issued->accessToken)['sub']);
    }

    public function test_verify_expired_token_throws_and_deletes_row(): void
    {
        $svc = $this->otpService(['otp' => ['ttl' => 60]]);
        $user = $this->createUser('stale@example.com');
        $svc->send('recovery', 'stale@example.com', '203.0.113.1');
        $code = $this->mailedCode();
        $this->backdateToken($user['id'], 'recovery', 120);

        try {
            $svc->verify('recovery', 'stale@example.com', $code, null, 'ip', 'ua');
            $this->fail('Expected InvalidOtpException');
        } catch (InvalidOtpException) {
        }

        $this->assertNull(
            (new OneTimeTokenRepository(self::$pdo))->findForUser($user['id'], 'recovery'),
        );
    }

    public function test_verify_wrong_type_fails(): void
    {
        $svc = $this->otpService();
        $this->createUser('type@example.com');
        $svc->send('recovery', 'type@example.com', '203.0.113.1');
        $code = $this->mailedCode();

        $this->expectException(InvalidOtpException::class);
        $svc->verify('magiclink', 'type@example.com', $code, null, 'ip', 'ua');
    }

    public function test_verify_code_with_mismatched_email_fails(): void
    {
        $svc = $this->otpService();
        $this->createUser('owner@example.com');
        $this->createUser('other@example.com');
        $svc->send('recovery', 'owner@example.com', '203.0.113.1');
        $code = $this->mailedCode();

        $this->expectException(InvalidOtpException::class);
        $svc->verify('recovery', 'other@example.com', $code, null, 'ip', 'ua');
    }

    public function test_verify_confirmation_sets_email_confirmed_and_issues_session(): void
    {
        $svc = $this->otpService();
        $user = $this->createUser('fresh@example.com', confirmed: false);
        $svc->send('confirmation', 'fresh@example.com', '203.0.113.1');
        $code = $this->mailedCode();

        $issued = $svc->verify('confirmation', 'fresh@example.com', $code, null, 'ip', 'ua');

        $this->assertNotEmpty($issued->accessToken);
        $refreshed = (new UserRepository(self::$pdo))->findById($user['id']);
        $this->assertNotNull($refreshed['email_confirmed_at']);
    }

    public function test_verify_magiclink_confirms_unconfirmed_user(): void
    {
        $svc = $this->otpService();
        $user = $this->createUser('inbox-proof@example.com', confirmed: false);
        $svc->send('magiclink', 'inbox-proof@example.com', '203.0.113.1');
        $code = $this->mailedCode();

        $svc->verify('magiclink', 'inbox-proof@example.com', $code, null, 'ip', 'ua');

        $refreshed = (new UserRepository(self::$pdo))->findById($user['id']);
        $this->assertNotNull($refreshed['email_confirmed_at']);
    }

    public function test_verify_for_banned_user_throws_user_banned(): void
    {
        $svc = $this->otpService();
        $user = $this->createUser('banned@example.com');
        $svc->send('recovery', 'banned@example.com', '203.0.113.1');
        $code = $this->mailedCode();

        $stmt = self::$pdo->prepare(
            "UPDATE auth.users SET banned_until = now() + interval '1 hour' WHERE id = :id"
        );
        $stmt->execute([':id' => $user['id']]);

        $this->expectException(UserBannedException::class);
        $svc->verify('recovery', 'banned@example.com', $code, null, 'ip', 'ua');
    }

    // --- reauthentication ----------------------------------------------------

    public function test_reauthentication_nonce_consumes_once(): void
    {
        $svc = $this->otpService();
        $user = $this->createUser('reauth@example.com');
        $svc->send('reauthentication', 'reauth@example.com', '203.0.113.1');
        $code = $this->mailedCode();

        $this->assertTrue($svc->consumeReauthentication($user['id'], $code));
        $this->assertFalse($svc->consumeReauthentication($user['id'], $code));
    }

    public function test_reauthentication_nonce_rejects_wrong_user(): void
    {
        $svc = $this->otpService();
        $this->createUser('me@example.com');
        $other = $this->createUser('them@example.com');
        $svc->send('reauthentication', 'me@example.com', '203.0.113.1');
        $code = $this->mailedCode();

        $this->assertFalse($svc->consumeReauthentication($other['id'], $code));
    }
}
