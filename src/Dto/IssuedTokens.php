<?php
declare(strict_types=1);

namespace Maludb\Auth\Dto;

/**
 * Result of issuing or refreshing a session.
 *
 * refreshToken is the RAW (unhashed) token — the caller returns it to the client
 * exactly once; the database only ever stores its SHA-256 hash. It is null when
 * no new refresh token was minted (grace-window retry or a lost rotation race);
 * downstream must then leave the client's existing refresh credential untouched.
 */
final class IssuedTokens
{
    /** @param array<string,mixed> $user */
    public function __construct(
        public readonly string $accessToken,
        public readonly ?string $refreshToken,
        public readonly string $csrfToken,
        public readonly string $sessionId,
        public readonly int $expiresIn,
        public readonly array $user,
    ) {}
}
