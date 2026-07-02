<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

/**
 * The identity resolved from a validated access token for the current request.
 *
 * `viaCookie` records whether the token arrived as an ambient cookie credential
 * (true) or as an explicit `Authorization: Bearer` header (false). The CSRF
 * guard forks on this flag: cookie-borne credentials are subject to CSRF checks
 * on unsafe methods; bearer credentials are not (no ambient authority to abuse).
 */
final class AuthenticatedUser
{
    /** @param array<string,mixed> $claims */
    public function __construct(
        public readonly string $userId,
        public readonly ?string $sessionId,
        public readonly string $role,
        public readonly array $claims,
        public readonly bool $viaCookie,
    ) {}
}
