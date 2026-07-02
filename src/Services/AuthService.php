<?php
declare(strict_types=1);

namespace Maludb\Auth\Services;

use Maludb\Auth\Dto\IssuedTokens;
use Maludb\Auth\Exceptions\InvalidCredentialsException;
use Maludb\Auth\Exceptions\SignupDisabledException;
use Maludb\Auth\Exceptions\UserBannedException;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\IdentityRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Security\Password;
use Maludb\Auth\Support\Config;
use Maludb\Auth\Support\EmailNormalizer;
use PDO;

/**
 * Orchestrates email+password signup and login over the repositories and
 * TokenService. This is the boundary where security controls live:
 *
 *  - Email is normalized before BOTH create and lookup, so casing/whitespace
 *    variants cannot open duplicate accounts or bypass the unique index.
 *  - app_metadata (provider/providers) is server-controlled and never taken from
 *    caller input, so a signup request cannot escalate its own metadata.
 *  - login equalizes timing: Password::verify always runs, against the user's
 *    real hash when present or Password::dummyHash() when the user is missing or
 *    has no password (OAuth-only). This prevents user enumeration by response
 *    time. The existence + verify checks are combined AFTER verify has run.
 *  - Failures surface as a single generic InvalidCredentialsException so the
 *    outside cannot distinguish "no such user" from "wrong password".
 *  - signup's three writes (create user + create identity + mark confirmed) are
 *    atomic: they run in a single transaction so a mid-way failure cannot leave
 *    an orphaned user row holding the unique email and blocking a retry.
 */
final class AuthService
{
    public function __construct(
        private UserRepository $users,
        private TokenService $tokens,
        private Password $password,
        private AuditRepository $audit,
        private IdentityRepository $identities,
        private Config $config,
        private PDO $pdo,
    ) {}

    /**
     * Register a new email+password user.
     *
     * @param array<string,mixed> $profile Optional user metadata (raw_user_meta_data).
     * @return array<string,mixed> The created user row (metadata as arrays).
     *
     * @throws SignupDisabledException when signups are turned off.
     * @throws \InvalidArgumentException when the password fails Password's policy.
     * @throws \Maludb\Auth\Exceptions\DuplicateEmailException on a taken email.
     */
    public function signup(string $email, string $password, string $ip, array $profile = []): array
    {
        if ((bool) $this->config->get('signup.disabled', false) === true) {
            throw new SignupDisabledException('Signups are currently disabled.');
        }

        $normalizedEmail = EmailNormalizer::normalize($email);

        // Hash first: this also enforces the min-length / max-72-byte policy and
        // throws InvalidArgumentException, which the caller maps to a validation
        // error. Doing it before create() avoids a wasted INSERT on a bad password.
        $hash = $this->password->hash($password);

        $autoconfirm = (bool) $this->config->get('signup.autoconfirm', true);

        // Atomicity: create-user + create-identity + mark-confirmed must all commit
        // together or not at all, else a failed identity insert would leave an
        // orphaned user holding the unique email. Own the transaction only when one
        // isn't already active (mirrors TokenService::rotate/beginIfPossible); under
        // the integration harness's outer transaction we run inline and let it own
        // atomicity.
        $owns = $this->beginIfPossible();

        try {
            $user = $this->users->create([
                'email' => $normalizedEmail,
                'encrypted_password' => $hash,
                // Server-controlled: never sourced from caller input.
                'raw_app_meta_data' => ['provider' => 'email', 'providers' => ['email']],
                'raw_user_meta_data' => $profile,
            ]);

            // Supabase uses the user id as the email-provider subject (provider_id).
            $this->identities->create([
                'user_id' => $user['id'],
                'provider' => 'email',
                'provider_id' => $user['id'],
                'identity_data' => [
                    'sub' => $user['id'],
                    'email' => $normalizedEmail,
                    'email_verified' => $autoconfirm,
                    'provider' => 'email',
                ],
                'email' => $normalizedEmail,
            ]);

            if ($autoconfirm) {
                $this->users->markEmailConfirmed($user['id']);
                // Reload so the returned user reflects the confirmation timestamp
                // (and the generated confirmed_at column) rather than the pre-confirm row.
                $refreshed = $this->users->findById($user['id']);
                if ($refreshed !== null) {
                    $user = $refreshed;
                }
            }

            if ($owns) {
                $this->pdo->commit();
            }
        } catch (\Throwable $e) {
            if ($owns && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        // Audit outside the transaction: the signup itself has committed, and the
        // audit row should survive even if this specific write hiccups.
        $this->audit->record('signup', ['user_id' => $user['id']], $ip);

        return $user;
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

    /**
     * Authenticate an email+password login and issue a fresh session.
     *
     * @throws InvalidCredentialsException on unknown email or wrong password.
     * @throws UserBannedException when the account is banned and the ban is active.
     */
    public function login(string $email, string $password, string $ip, string $userAgent): IssuedTokens
    {
        $normalizedEmail = EmailNormalizer::normalize($email);
        $user = $this->users->findByEmail($normalizedEmail);

        // Timing equalization: always run a bcrypt verify. When the user is missing
        // (or is OAuth-only with a NULL password) we verify against dummyHash() so
        // the "no such user" path costs the same as the "wrong password" path.
        $hash = ($user['encrypted_password'] ?? null) ?: $this->password->dummyHash();
        $ok = $this->password->verify($password, $hash);

        if ($user === null || $ok !== true) {
            throw new InvalidCredentialsException('Invalid email or password.');
        }

        if ($this->isBanned($user)) {
            throw new UserBannedException('This account is banned.');
        }

        // Opportunistic rehash if the stored hash's parameters are out of date.
        if ($this->password->needsRehash((string) $user['encrypted_password'])) {
            $this->users->update($user['id'], [
                'encrypted_password' => $this->password->hash($password),
            ]);
        }

        $issued = $this->tokens->issueForUser($user, $ip, $userAgent, 'aal1', ['password']);

        $this->users->setLastSignInAt($user['id']);
        $this->audit->record('login', ['user_id' => $user['id']], $ip);

        return $issued;
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
