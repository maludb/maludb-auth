<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

/**
 * Contract for the token-bucket rate limiter. Extracted so middleware can depend
 * on the abstraction and tests can inject doubles (notably a failing double to
 * assert the FAIL-CLOSED contract).
 */
interface RateLimiterInterface
{
    /**
     * Consume one token from the bucket identified by $key.
     *
     * @return bool true if allowed (a token was available), false if exhausted.
     * @throws \PDOException on datastore failure. Callers MUST fail CLOSED.
     */
    public function attempt(string $key, int $capacity, float $refillPerSecond): bool;
}
