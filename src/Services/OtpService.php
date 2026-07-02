<?php
declare(strict_types=1);

namespace Maludb\Auth\Services;

use Maludb\Auth\Dto\IssuedTokens;
use Maludb\Auth\Exceptions\InvalidOtpException;
use Maludb\Auth\Exceptions\UserBannedException;
use Maludb\Auth\Mail\MailComposer;
use Maludb\Auth\Mail\MailerInterface;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\IdentityRepository;
use Maludb\Auth\Repositories\OneTimeTokenRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Security\TokenHash;
use Maludb\Auth\Support\Config;
use Maludb\Auth\Support\EmailNormalizer;
use PDO;

/**
 * One-time-token flows: minting + mailing OTP codes / verify links, and
 * redeeming them for sessions.
 *
 * Security posture:
 *  - send() NEVER discloses whether the email has an account: every "don't
 *    send" branch (unknown user, disabled signup, already confirmed, banned)
 *    returns silently, and the controllers answer the same generic 200.
 *  - Tokens are stored hashed; minting replaces any previous live token of the
 *    same type; redemption consumes the row in the same transaction that
 *    applies its effect, so a code can never be redeemed twice.
 *  - verify() failures all throw the SAME InvalidOtpException regardless of
 *    cause. Expired rows are deleted on the failed attempt.
 */
final class OtpService
{
    private const SESSION_TYPES = ['confirmation', 'recovery', 'magiclink', 'invite'];

    public function __construct(
        private UserRepository $users,
        private IdentityRepository $identities,
        private OneTimeTokenRepository $oneTimeTokens,
        private TokenService $tokens,
        private AuditRepository $audit,
        private MailerInterface $mailer,
        private MailComposer $composer,
        private TokenHash $tokenHash,
        private Config $config,
        private PDO $pdo,
    ) {}

    /**
     * Mint a token of $type for $email's account and mail it. Silent no-op on
     * every branch that must not leak account existence.
     */
    public function send(
        string $type,
        string $email,
        string $ip,
        bool $createUser = false,
        string $redirectTo = '',
    ): void {
        $normalized = EmailNormalizer::normalize($email);
        $user = $this->users->findByEmail($normalized);

        if ($user === null) {
            if (!$createUser || (bool) $this->config->get('signup.disabled', false)) {
                return; // No enumeration signal.
            }
            $user = $this->createPasswordlessUser($normalized);
        }

        if ($this->isBanned($user)) {
            return; // Never mail live login material to a banned account.
        }
        if ($type === 'confirmation' && ($user['email_confirmed_at'] ?? null) !== null) {
            return; // Nothing to confirm.
        }

        $minted = $this->mint($user, $type);
        $mail = $this->composer->compose($type, $normalized, $minted['token'], $minted['hash'], $redirectTo);
        $this->mailer->send($normalized, $mail['subject'], $mail['text']);

        $this->audit->record("{$type}_sent", ['user_id' => $user['id']], $ip);
    }

    /**
     * Mint (replace) a live token of $type for $user WITHOUT mailing it — the
     * building block for send() and for admin generate_link.
     *
     * @param array<string,mixed> $user
     * @return array{token:string,hash:string}
     */
    public function mint(array $user, string $type): array
    {
        $token = $this->tokenHash->otp();
        $hash = $this->tokenHash->hash($token);
        $this->oneTimeTokens->replace((string) $user['id'], $type, $hash, (string) ($user['email'] ?? ''));

        return ['token' => $token, 'hash' => $hash];
    }

    /**
     * Redeem a token for a session. Accepts the code form (email + 6-digit
     * token) or the link form (token_hash). Consumes the row.
     *
     * @throws InvalidOtpException on ANY redemption failure (generic).
     * @throws UserBannedException when the account is banned.
     */
    public function verify(
        string $type,
        ?string $email,
        ?string $token,
        ?string $tokenHash,
        string $ip,
        string $userAgent,
    ): IssuedTokens {
        if (!in_array($type, self::SESSION_TYPES, true)) {
            throw new InvalidOtpException('Token is invalid or has expired.');
        }

        $row = $this->resolveRow($type, $email, $token, $tokenHash);
        $user = $this->users->findById((string) $row['user_id']);
        if ($user === null) {
            $this->oneTimeTokens->delete((string) $row['id']);
            throw new InvalidOtpException('Token is invalid or has expired.');
        }
        if ($this->isBanned($user)) {
            throw new UserBannedException('This account is banned.');
        }

        // Consume + apply effect + issue session atomically (nested-safe, same
        // pattern as AuthService::signup).
        $owns = $this->beginIfPossible();
        try {
            $this->oneTimeTokens->delete((string) $row['id']);

            if (($user['email_confirmed_at'] ?? null) === null) {
                // Redeeming ANY emailed token is proof of inbox control.
                $this->users->markEmailConfirmed((string) $user['id']);
                $refreshed = $this->users->findById((string) $user['id']);
                if ($refreshed !== null) {
                    $user = $refreshed;
                }
                $this->audit->record('user_confirmed', ['user_id' => $user['id']], $ip);
            }

            $issued = $this->tokens->issueForUser($user, $ip, $userAgent, 'aal1', ['otp']);
            $this->users->setLastSignInAt((string) $user['id']);

            if ($owns) {
                $this->pdo->commit();
            }
        } catch (\Throwable $e) {
            if ($owns && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        $this->audit->record('otp_verified', ['user_id' => $user['id'], 'otp_type' => $type], $ip);

        return $issued;
    }

    /**
     * Consume a live reauthentication nonce for $userId. Returns false (never
     * throws) on unknown/expired/foreign nonce so callers can map it to their
     * own generic error.
     */
    public function consumeReauthentication(string $userId, string $nonce): bool
    {
        $row = $this->oneTimeTokens->findByHash($this->tokenHash->hash($nonce));
        if ($row === null
            || $row['token_type'] !== 'reauthentication'
            || (string) $row['user_id'] !== $userId) {
            return false;
        }
        if ($this->isExpired($row)) {
            $this->oneTimeTokens->delete((string) $row['id']);
            return false;
        }

        $this->oneTimeTokens->delete((string) $row['id']);

        return true;
    }

    /** @return array<string,mixed> The live, unexpired token row. */
    private function resolveRow(string $type, ?string $email, ?string $token, ?string $tokenHash): array
    {
        if ($tokenHash !== null && $tokenHash !== '') {
            $row = $this->oneTimeTokens->findByHash($tokenHash);
        } elseif ($token !== null && $token !== '' && $email !== null && $email !== '') {
            $row = $this->oneTimeTokens->findByHash($this->tokenHash->hash($token));
            if ($row !== null
                && !hash_equals(EmailNormalizer::normalize((string) $row['relates_to']), EmailNormalizer::normalize($email))) {
                $row = null;
            }
        } else {
            $row = null;
        }

        if ($row === null || $row['token_type'] !== $type) {
            throw new InvalidOtpException('Token is invalid or has expired.');
        }
        if ($this->isExpired($row)) {
            $this->oneTimeTokens->delete((string) $row['id']);
            throw new InvalidOtpException('Token is invalid or has expired.');
        }

        return $row;
    }

    /** @param array<string,mixed> $row */
    private function isExpired(array $row): bool
    {
        $ttl = (int) $this->config->get('otp.ttl', 3600);
        $created = strtotime((string) $row['created_at']);

        return $created === false || ($created + $ttl) < time();
    }

    /** @return array<string,mixed> */
    private function createPasswordlessUser(string $normalizedEmail): array
    {
        $owns = $this->beginIfPossible();
        try {
            $user = $this->users->create([
                'email' => $normalizedEmail,
                'raw_app_meta_data' => ['provider' => 'email', 'providers' => ['email']],
            ]);
            $this->identities->create([
                'user_id' => $user['id'],
                'provider' => 'email',
                'provider_id' => $user['id'],
                'identity_data' => [
                    'sub' => $user['id'],
                    'email' => $normalizedEmail,
                    'email_verified' => false,
                    'provider' => 'email',
                ],
                'email' => $normalizedEmail,
            ]);
            if ($owns) {
                $this->pdo->commit();
            }
        } catch (\Throwable $e) {
            if ($owns && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        return $user;
    }

    private function beginIfPossible(): bool
    {
        if ($this->pdo->inTransaction()) {
            return false;
        }
        $this->pdo->beginTransaction();

        return true;
    }

    /** @param array<string,mixed> $user */
    private function isBanned(array $user): bool
    {
        $bannedUntil = $user['banned_until'] ?? null;
        if ($bannedUntil === null || $bannedUntil === '') {
            return false;
        }
        $ts = strtotime((string) $bannedUntil);

        return $ts !== false && $ts > time();
    }
}
