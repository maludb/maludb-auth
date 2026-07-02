<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

/**
 * Single source of truth for "is this account currently banned?" — shared by
 * AuthService (login) and OtpService (token redemption) so the ban-window
 * semantics can never drift between the two flows.
 */
final class BanCheck
{
    /** @param array<string,mixed> $user */
    public static function isBanned(array $user): bool
    {
        $bannedUntil = $user['banned_until'] ?? null;
        if ($bannedUntil === null || $bannedUntil === '') {
            return false;
        }
        $ts = strtotime((string) $bannedUntil);

        return $ts !== false && $ts > time();
    }
}
