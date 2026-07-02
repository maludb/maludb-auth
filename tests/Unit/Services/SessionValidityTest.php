<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Services;

use Maludb\Auth\Enums\SessionValidity;
use Maludb\Auth\Exceptions\SessionExpiredException;
use Maludb\Auth\Services\SessionService;
use PHPUnit\Framework\TestCase;

/**
 * Pure-logic tests for SessionService::checkValidity. No DB, no clock:
 * timestamps and "now" are passed in explicitly so every branch is deterministic.
 */
final class SessionValidityTest extends TestCase
{
    private const CREATED = 1_000_000; // fixed epoch baseline for created_at

    /** @param array<string,mixed> $session @param array<string,mixed> $cfg */
    private function check(array $session, int $now, array $cfg = []): SessionValidity
    {
        return (new SessionService())->checkValidity(
            $session,
            $now,
            $cfg + ['timebox' => 0, 'inactivity_timeout' => 0],
        );
    }

    /** @return array<string,mixed> */
    private function session(array $overrides = []): array
    {
        return $overrides + [
            'not_after' => null,
            'created_at' => '@' . self::CREATED,
            'refreshed_at' => null,
        ];
    }

    public function test_valid_session(): void
    {
        $result = $this->check($this->session(), self::CREATED + 60);
        $this->assertSame(SessionValidity::Valid, $result);
    }

    public function test_past_not_after(): void
    {
        $session = $this->session(['not_after' => '@' . (self::CREATED + 100)]);
        $this->assertSame(SessionValidity::PastNotAfter, $this->check($session, self::CREATED + 101));
    }

    public function test_not_after_not_yet_reached_is_valid(): void
    {
        $session = $this->session(['not_after' => '@' . (self::CREATED + 100)]);
        $this->assertSame(SessionValidity::Valid, $this->check($session, self::CREATED + 50));
    }

    public function test_past_timebox(): void
    {
        $result = $this->check($this->session(), self::CREATED + 3601, ['timebox' => 3600]);
        $this->assertSame(SessionValidity::PastTimebox, $result);
    }

    public function test_timebox_zero_disables_check(): void
    {
        // Far past created_at + any window, but timebox=0 means "never expire on timebox".
        $result = $this->check($this->session(), self::CREATED + 10_000_000, ['timebox' => 0]);
        $this->assertSame(SessionValidity::Valid, $result);
    }

    public function test_timed_out_uses_refreshed_at(): void
    {
        $session = $this->session(['refreshed_at' => '@' . (self::CREATED + 500)]);
        // now is 601s after refreshed_at, inactivity window is 600.
        $result = $this->check($session, self::CREATED + 1101, ['inactivity_timeout' => 600]);
        $this->assertSame(SessionValidity::TimedOut, $result);
    }

    public function test_timed_out_falls_back_to_created_at_when_never_refreshed(): void
    {
        $session = $this->session(['refreshed_at' => null]);
        $result = $this->check($session, self::CREATED + 601, ['inactivity_timeout' => 600]);
        $this->assertSame(SessionValidity::TimedOut, $result);
    }

    public function test_inactivity_within_window_is_valid(): void
    {
        $session = $this->session(['refreshed_at' => '@' . (self::CREATED + 500)]);
        $result = $this->check($session, self::CREATED + 900, ['inactivity_timeout' => 600]);
        $this->assertSame(SessionValidity::Valid, $result);
    }

    public function test_inactivity_zero_disables_check(): void
    {
        $result = $this->check($this->session(), self::CREATED + 10_000_000, ['inactivity_timeout' => 0]);
        $this->assertSame(SessionValidity::Valid, $result);
    }

    public function test_assert_valid_throws_on_expired(): void
    {
        $session = $this->session(['not_after' => '@' . (self::CREATED + 100)]);
        $this->expectException(SessionExpiredException::class);
        (new SessionService())->assertValid(
            $session,
            self::CREATED + 200,
            ['timebox' => 0, 'inactivity_timeout' => 0],
        );
    }

    public function test_assert_valid_passes_when_valid(): void
    {
        (new SessionService())->assertValid(
            $this->session(),
            self::CREATED + 60,
            ['timebox' => 0, 'inactivity_timeout' => 0],
        );
        $this->addToAssertionCount(1); // no exception thrown
    }
}
