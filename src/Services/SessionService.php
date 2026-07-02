<?php
declare(strict_types=1);

namespace Maludb\Auth\Services;

use Maludb\Auth\Enums\SessionValidity;
use Maludb\Auth\Exceptions\SessionExpiredException;

/**
 * Session validity rules.
 *
 * checkValidity is a PURE function of (session row, now, config): it does no I/O
 * and reads no ambient clock, so it is trivially unit-testable and portable.
 * Timestamp columns arrive as Postgres timestamptz strings; we normalize them to
 * epoch seconds via strtotime (which understands both ISO strings and '@epoch').
 */
final class SessionService
{
    /**
     * @param array<string,mixed> $session Row from auth.sessions (not_after, created_at, refreshed_at).
     * @param int $now Current time as epoch seconds.
     * @param array<string,mixed> $cfg Keys: timebox, inactivity_timeout (seconds; 0 disables).
     */
    public function checkValidity(array $session, int $now, array $cfg): SessionValidity
    {
        $timebox = (int) ($cfg['timebox'] ?? 0);
        $inactivity = (int) ($cfg['inactivity_timeout'] ?? 0);

        $notAfter = $this->toEpoch($session['not_after'] ?? null);
        if ($notAfter !== null && $now > $notAfter) {
            return SessionValidity::PastNotAfter;
        }

        if ($timebox > 0) {
            $createdAt = $this->toEpoch($session['created_at'] ?? null);
            if ($createdAt !== null && $now > $createdAt + $timebox) {
                return SessionValidity::PastTimebox;
            }
        }

        if ($inactivity > 0) {
            // Inactivity is measured from the last refresh; sessions that have never
            // been refreshed fall back to their creation time.
            $last = $this->toEpoch($session['refreshed_at'] ?? null)
                ?? $this->toEpoch($session['created_at'] ?? null);
            if ($last !== null && $now > $last + $inactivity) {
                return SessionValidity::TimedOut;
            }
        }

        return SessionValidity::Valid;
    }

    /**
     * @param array<string,mixed> $session
     * @param array<string,mixed> $cfg Keys: timebox, inactivity_timeout.
     * @throws SessionExpiredException on any non-Valid result.
     */
    public function assertValid(array $session, ?int $now = null, array $cfg = []): void
    {
        $now ??= time();
        $result = $this->checkValidity($session, $now, $cfg);
        if ($result !== SessionValidity::Valid) {
            throw new SessionExpiredException('Session is no longer valid: ' . $result->name);
        }
    }

    private function toEpoch(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_int($value)) {
            return $value;
        }
        $ts = strtotime((string) $value);
        return $ts === false ? null : $ts;
    }
}
