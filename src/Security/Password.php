<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

final class Password
{
    public function __construct(private int $minLength = 12) {}

    public function hash(string $password): string
    {
        $this->assertValid($password);
        return password_hash($password, PASSWORD_BCRYPT);
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_BCRYPT);
    }

    /** Precomputed-cost dummy for timing-equalized "user not found" paths. */
    public function dummyHash(): string
    {
        // A real bcrypt hash generated at PASSWORD_BCRYPT's default cost (10) via
        // password_hash('maludb-dummy-password', PASSWORD_BCRYPT). Verifying any
        // input against it costs the same as verifying a real user's hash, so the
        // "user not found" path cannot be distinguished by timing.
        return '$2y$10$YEciY4omWpIPxN.dM8AGI.irKrtAnpMWDoeEY3HiQ088HCu45rXP.';
    }

    private function assertValid(string $password): void
    {
        // strlen() is intentionally byte-based: bcrypt operates on and truncates
        // at 72 *bytes*, and the min-length floor is likewise a byte count.
        if (strlen($password) < $this->minLength) {
            throw new \InvalidArgumentException('Password too short.');
        }
        if (strlen($password) > 72) { // bcrypt truncates past 72 bytes
            throw new \InvalidArgumentException('Password too long (max 72 bytes).');
        }
    }
}
