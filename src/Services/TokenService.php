<?php
declare(strict_types=1);

namespace Maludb\Auth\Services;

use Maludb\Auth\Dto\IssuedTokens;
use Maludb\Auth\Exceptions\InvalidRefreshTokenException;
use Maludb\Auth\Exceptions\RefreshTokenReuseException;
use Maludb\Auth\Exceptions\SessionExpiredException;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\RefreshTokenRepository;
use Maludb\Auth\Repositories\SessionRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Security\Csrf;
use Maludb\Auth\Security\Jwt;
use Maludb\Auth\Security\TokenHash;
use Maludb\Auth\Support\Config;
use PDO;

/**
 * Issues sessions and access/refresh tokens, and rotates refresh tokens with
 * theft detection. This is the security heart of Phase 1.
 *
 * Correctness invariants:
 *  - Refresh tokens are stored HASHED (TokenHash::hash); the raw token is returned
 *    to the caller exactly once inside IssuedTokens and never persisted.
 *  - Reuse of a revoked token is treated as theft: the ENTIRE session family is
 *    revoked (revokeAllForSession), not just the presented token, and the event
 *    is audited.
 *  - Rotation (revoke old + issue new) runs inside a transaction so a failure can
 *    never leave the old token revoked with no replacement issued. Integration
 *    tests already run inside an outer transaction; we therefore only begin/commit
 *    when not already in one (a nested beginTransaction() would throw), otherwise
 *    we let the outer transaction own atomicity.
 */
final class TokenService
{
    public function __construct(
        private UserRepository $users,
        private SessionRepository $sessions,
        private RefreshTokenRepository $refreshTokens,
        private AuditRepository $audit,
        private Jwt $jwt,
        private Csrf $csrf,
        private TokenHash $tokenHash,
        private SessionService $sessionService,
        private Config $config,
        private PDO $pdo,
    ) {}

    /**
     * Create a brand-new session and issue its first access + refresh token pair.
     *
     * @param array<string,mixed> $user The user row (must contain id/email/role/etc.).
     * @param string[] $amr Authentication methods used, e.g. ['password'] or ['password','totp'].
     */
    public function issueForUser(
        array $user,
        string $ip,
        string $userAgent,
        string $aal,
        array $amr,
    ): IssuedTokens {
        $csrfToken = $this->csrf->generate();
        $notAfter = $this->computeNotAfter();

        $session = $this->sessions->create($user['id'], $csrfToken, $ip, $userAgent, $notAfter);
        $sessionId = $session['id'];

        // SessionRepository::create always defaults aal to 'aal1'; bump it when needed.
        if ($aal !== 'aal1') {
            $this->sessions->updateAal($sessionId, $aal, null);
        }

        // Issue the first refresh token (root of the rotation chain: parent = null).
        $rawRefresh = $this->tokenHash->random();
        $this->refreshTokens->issue($sessionId, $user['id'], $this->tokenHash->hash($rawRefresh), null);

        $accessToken = $this->issueAccessToken($user, $sessionId, $aal, $amr);

        return new IssuedTokens(
            accessToken: $accessToken,
            refreshToken: $rawRefresh,
            csrfToken: $csrfToken,
            sessionId: $sessionId,
            expiresIn: (int) $this->config->get('jwt.exp', 3600),
            user: $user,
        );
    }

    /**
     * Rotate a refresh token: verify it, run theft detection, validate the session,
     * revoke the presented token and issue a chained replacement.
     *
     * @throws InvalidRefreshTokenException if the token is unknown.
     * @throws RefreshTokenReuseException on detected reuse of a revoked token.
     * @throws SessionExpiredException if the underlying session is no longer valid.
     */
    public function refresh(string $refreshToken, string $ip, string $userAgent): IssuedTokens
    {
        $row = $this->refreshTokens->findByHash($this->tokenHash->hash($refreshToken));
        if ($row === null) {
            throw new InvalidRefreshTokenException('Unknown refresh token.');
        }

        $sessionId = $row['session_id'];

        if ((bool) $row['revoked'] === true) {
            return $this->handleReuse($row, $sessionId, $ip);
        }

        // Session must still exist and be valid; otherwise revoke the family and reject.
        $session = $this->sessions->find($sessionId);
        if ($session === null) {
            $this->refreshTokens->revokeAllForSession($sessionId);
            throw new SessionExpiredException('Session no longer exists.');
        }
        try {
            $this->sessionService->assertValid($session, time(), $this->sessionCfg());
        } catch (SessionExpiredException $e) {
            $this->refreshTokens->revokeAllForSession($sessionId);
            throw $e;
        }

        // Reload the user so re-issued claims reflect current state.
        $user = $this->users->findById($row['user_id']);
        if ($user === null) {
            $this->refreshTokens->revokeAllForSession($sessionId);
            throw new InvalidRefreshTokenException('Token user no longer exists.');
        }

        return $this->rotate($row, $session, $user);
    }

    /**
     * Reuse of a revoked token. Normally this is theft — revoke the whole family
     * and audit. But if the revoked token was rotated very recently (within
     * refresh.reuse_interval) AND a newer active token still exists for the
     * session, treat it as a benign client retry: hand back fresh access for the
     * still-active session without revoking anything.
     *
     * Note: the grace path cannot return a usable raw refresh token (only the hash
     * is stored). The client keeps using the token it already holds; refreshToken
     * is intentionally empty in that response.
     *
     * @param array<string,mixed> $row The revoked refresh-token row.
     * @return IssuedTokens (grace-window path only; the theft path throws)
     */
    private function handleReuse(array $row, string $sessionId, string $ip): IssuedTokens
    {
        $reuseInterval = (int) $this->config->get('refresh.reuse_interval', 0);
        $active = $this->refreshTokens->findActiveBySession($sessionId);
        $revokedAt = strtotime((string) ($row['updated_at'] ?? ''));

        if ($reuseInterval > 0 && $active !== [] && $revokedAt !== false
            && (time() - $revokedAt) <= $reuseInterval) {
            $session = $this->sessions->find($sessionId);
            $user = $this->users->findById($row['user_id']);
            if ($session !== null && $user !== null) {
                $accessToken = $this->issueAccessToken(
                    $user,
                    $sessionId,
                    (string) $session['aal'],
                    $this->amrMethods($session),
                );

                return new IssuedTokens(
                    accessToken: $accessToken,
                    refreshToken: '',
                    csrfToken: (string) $session['csrf_token'],
                    sessionId: $sessionId,
                    expiresIn: (int) $this->config->get('jwt.exp', 3600),
                    user: $user,
                );
            }
        }

        // Theft: revoke the entire session family and audit.
        $this->refreshTokens->revokeAllForSession($sessionId);
        $this->audit->record('refresh_token_reuse_detected', [
            'session_id' => $sessionId,
            'user_id' => $row['user_id'],
        ], $ip);

        throw new RefreshTokenReuseException('Refresh token reuse detected; session revoked.');
    }

    /**
     * Perform the atomic revoke-old + issue-new rotation.
     *
     * @param array<string,mixed> $old The presented (active) refresh-token row.
     * @param array<string,mixed> $session
     * @param array<string,mixed> $user
     */
    private function rotate(array $old, array $session, array $user): IssuedTokens
    {
        $sessionId = $session['id'];
        $owns = $this->beginIfPossible();

        try {
            $this->refreshTokens->revoke((int) $old['id']);

            $rawRefresh = $this->tokenHash->random();
            $this->refreshTokens->issue(
                $sessionId,
                $user['id'],
                $this->tokenHash->hash($rawRefresh),
                $old['token_hash'], // chain parent = the hash we just revoked
            );

            $this->sessions->touchRefreshedAt($sessionId);

            if ($owns) {
                $this->pdo->commit();
            }
        } catch (\Throwable $e) {
            if ($owns && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        $accessToken = $this->issueAccessToken(
            $user,
            $sessionId,
            (string) $session['aal'],
            $this->amrMethods($session),
        );

        return new IssuedTokens(
            accessToken: $accessToken,
            refreshToken: $rawRefresh,
            csrfToken: (string) $session['csrf_token'], // CSRF stays stable across refresh
            sessionId: $sessionId,
            expiresIn: (int) $this->config->get('jwt.exp', 3600),
            user: $user,
        );
    }

    /**
     * Build and sign the access token from user + session context.
     *
     * @param array<string,mixed> $user
     * @param string[] $amr
     */
    private function issueAccessToken(array $user, string $sessionId, string $aal, array $amr): string
    {
        $claims = [
            'sub' => $user['id'],
            'email' => $user['email'] ?? null,
            'phone' => $user['phone'] ?? null,
            'role' => $user['role'] ?? 'authenticated',
            'aal' => $aal,
            'amr' => $this->buildAmr($amr),
            'session_id' => $sessionId,
            'is_anonymous' => (bool) ($user['is_anonymous'] ?? false),
            'app_metadata' => $user['raw_app_meta_data'] ?? [],
            'user_metadata' => $user['raw_user_meta_data'] ?? [],
        ];

        // Only set aud when it matches the Jwt's configured audience; otherwise the
        // Jwt's own iss/aud enforcement would reject the token it just signed. The
        // user's aud defaults to 'authenticated', which matches jwt.audience.
        $userAud = $user['aud'] ?? null;
        $configAud = $this->config->get('jwt.audience');
        if ($userAud !== null && ($configAud === null || $userAud === $configAud)) {
            $claims['aud'] = $userAud;
        }

        return $this->jwt->issue($claims, (int) $this->config->get('jwt.exp', 3600));
    }

    /**
     * @param string[] $methods
     * @return array<int,array{method:string,timestamp:int}>
     */
    private function buildAmr(array $methods): array
    {
        $now = time();

        return array_map(
            static fn (string $m): array => ['method' => $m, 'timestamp' => $now],
            array_values($methods),
        );
    }

    /**
     * On a refresh we don't persist the original amr methods, so we default to
     * ['password']. (Full amr history persistence is out of scope for Phase 1.)
     *
     * @param array<string,mixed> $session
     * @return string[]
     */
    private function amrMethods(array $session): array
    {
        return ['password'];
    }

    private function computeNotAfter(): ?string
    {
        $timebox = (int) $this->config->get('session.timebox', 0);
        if ($timebox <= 0) {
            return null;
        }

        return gmdate('Y-m-d H:i:sP', time() + $timebox);
    }

    /** @return array<string,mixed> */
    private function sessionCfg(): array
    {
        return [
            'timebox' => (int) $this->config->get('session.timebox', 0),
            'inactivity_timeout' => (int) $this->config->get('session.inactivity_timeout', 0),
        ];
    }

    /**
     * Begin a transaction only if one isn't already active. Returns true if this
     * call owns the transaction (and is therefore responsible for commit/rollback).
     */
    private function beginIfPossible(): bool
    {
        if ($this->pdo->inTransaction()) {
            return false;
        }
        $this->pdo->beginTransaction();

        return true;
    }
}
