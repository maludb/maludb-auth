<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Http\AuthenticatedUser;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\TokenResponder;
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
use Maludb\Auth\Security\Password;
use Maludb\Auth\Security\TokenHash;
use Maludb\Auth\Services\AuthService;
use Maludb\Auth\Services\OtpService;
use Maludb\Auth\Services\SessionService;
use Maludb\Auth\Services\TokenService;
use Maludb\Auth\Support\Config;

/**
 * Base for endpoint tests that drive controllers directly with real services,
 * real repositories (against the rolled-back test DB), a test Config, and an
 * in-test RSA keypair — mirroring AuthServiceTest/TokenServiceTest wiring. No
 * router/middleware here; controllers are constructed and invoked directly.
 */
abstract class ControllerTestCase extends IntegrationTestCase
{
    private static ?string $priv = null;
    private static ?string $pub = null;

    protected const PASSWORD = 'correct horse battery staple';

    /** Outbox of the most recent otpService() instance. */
    protected ArrayMailer $mailer;

    /** @return array{0:string,1:string} */
    protected function keys(): array
    {
        if (self::$priv === null) {
            $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
            openssl_pkey_export($res, $priv);
            self::$priv = $priv;
            self::$pub = openssl_pkey_get_details($res)['key'];
        }

        return [self::$priv, self::$pub];
    }

    protected function jwt(): Jwt
    {
        [$priv, $pub] = $this->keys();

        return new Jwt($priv, $pub, 'key-1', 'test-iss', 'authenticated');
    }

    /** @param array<string,mixed> $overrides */
    protected function testConfig(array $overrides = []): Config
    {
        return new Config(array_replace_recursive([
            'jwt' => ['exp' => 3600, 'audience' => 'authenticated'],
            'session' => ['timebox' => 0, 'inactivity_timeout' => 0],
            'refresh' => ['reuse_interval' => 0],
            'password' => ['min_length' => 12],
            'signup' => ['disabled' => false, 'autoconfirm' => true],
            'cookie' => ['secure' => false, 'samesite' => 'Lax'],
            'service_role' => ['key' => 'test-service-role-key'],
            'otp' => ['ttl' => 3600],
            'app' => ['url' => 'http://localhost:8080'],
            'site' => [
                'url' => 'http://localhost:3000',
                'uri_allow_list' => ['http://localhost:3000/*'],
            ],
        ], $overrides));
    }

    protected function users(): UserRepository
    {
        return new UserRepository(self::$pdo);
    }

    protected function sessions(): SessionRepository
    {
        return new SessionRepository(self::$pdo);
    }

    protected function audit(): AuditRepository
    {
        return new AuditRepository(self::$pdo);
    }

    protected function tokenService(Config $config): TokenService
    {
        return new TokenService(
            $this->users(),
            $this->sessions(),
            new RefreshTokenRepository(self::$pdo),
            $this->audit(),
            $this->jwt(),
            new Csrf(),
            new TokenHash(),
            new SessionService(),
            $config,
            self::$pdo,
        );
    }

    protected function authService(Config $config): AuthService
    {
        return new AuthService(
            $this->users(),
            $this->tokenService($config),
            new Password((int) $config->get('password.min_length', 12)),
            $this->audit(),
            new IdentityRepository(self::$pdo),
            $config,
            self::$pdo,
        );
    }

    protected function responder(): TokenResponder
    {
        return new TokenResponder();
    }

    /**
     * OtpService over the shared test PDO. Captured mail lands in
     * $this->mailer->sent; the mailer is (re)created here so each service
     * instance starts with an empty outbox.
     */
    protected function otpService(Config $config): OtpService
    {
        $this->mailer = new ArrayMailer();

        return new OtpService(
            $this->users(),
            new IdentityRepository(self::$pdo),
            new OneTimeTokenRepository(self::$pdo),
            $this->tokenService($config),
            $this->audit(),
            $this->mailer,
            new MailComposer(
                (string) $config->get('app.url', 'http://localhost:8080'),
                $config->get('site.url', 'http://localhost:3000'),
            ),
            new TokenHash(),
            $config,
            self::$pdo,
        );
    }

    /** Pull the 6-digit code out of the last captured mail. */
    protected function mailedCode(): string
    {
        $last = $this->mailer->last();
        $this->assertNotNull($last, 'Expected a captured mail.');
        preg_match('/code: ([0-9]{6})/', $last['text'], $m);
        $this->assertNotEmpty($m, 'Expected a 6-digit code in the mail body.');

        return $m[1];
    }

    /**
     * Pull the (user-salted) token_hash out of the verify link in the last
     * captured mail — mirrors what a user clicking the link actually sends,
     * and avoids recomputing the hash (which the salt makes non-trivial).
     */
    protected function mailedTokenHash(): string
    {
        $last = $this->mailer->last();
        $this->assertNotNull($last, 'Expected a captured mail.');
        preg_match('/token_hash=([0-9a-f]{64})/', $last['text'], $m);
        $this->assertNotEmpty($m, 'Expected a token_hash link in the mail body.');

        return $m[1];
    }

    /**
     * Build a RequestContext whose user was resolved from a genuinely-issued
     * access token (so sessionId/role match a real session row).
     */
    protected function contextFor(string $accessToken, bool $viaCookie = false): RequestContext
    {
        $claims = $this->jwt()->verify($accessToken);
        $ctx = new RequestContext();
        $ctx->user = new AuthenticatedUser(
            userId: (string) $claims['sub'],
            sessionId: $claims['session_id'] ?? null,
            role: (string) ($claims['role'] ?? 'authenticated'),
            claims: $claims,
            viaCookie: $viaCookie,
        );

        return $ctx;
    }

    /** Build a service_role context (for admin tests). */
    protected function serviceRoleContext(): RequestContext
    {
        $ctx = new RequestContext();
        $ctx->user = new AuthenticatedUser(
            userId: 'service',
            sessionId: null,
            role: 'service_role',
            claims: ['role' => 'service_role'],
            viaCookie: false,
        );

        return $ctx;
    }
}
