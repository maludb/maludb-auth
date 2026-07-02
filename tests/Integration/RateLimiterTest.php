<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Security\RateLimiter;

final class RateLimiterTest extends IntegrationTestCase
{
    public function test_blocks_after_capacity(): void
    {
        $rl = new RateLimiter(self::$pdo);
        $key = 'login:ip:203.0.113.9';
        $this->assertTrue($rl->attempt($key, capacity: 3, refillPerSecond: 0.0));
        $this->assertTrue($rl->attempt($key, 3, 0.0));
        $this->assertTrue($rl->attempt($key, 3, 0.0));
        $this->assertFalse($rl->attempt($key, 3, 0.0)); // 4th blocked
    }

    public function test_distinct_keys_are_independent(): void
    {
        $rl = new RateLimiter(self::$pdo);
        $a = 'login:ip:198.51.100.1';
        $b = 'login:ip:198.51.100.2';

        // Exhaust bucket A (capacity 1).
        $this->assertTrue($rl->attempt($a, 1, 0.0));
        $this->assertFalse($rl->attempt($a, 1, 0.0));

        // Bucket B is unaffected.
        $this->assertTrue($rl->attempt($b, 1, 0.0));
        $this->assertFalse($rl->attempt($b, 1, 0.0));
    }

    public function test_bucket_refills_over_time(): void
    {
        $rl = new RateLimiter(self::$pdo);
        $key = 'login:ip:192.0.2.50';

        // Capacity 1, refill 1 token/sec. First attempt allowed, immediate
        // second blocked (no time elapsed to refill).
        $this->assertTrue($rl->attempt($key, 1, 1.0));
        $this->assertFalse($rl->attempt($key, 1, 1.0));

        // Deterministically simulate elapsed wall-clock time by back-dating the
        // row's updated_at by 2 seconds. With refill 1.0/sec the bucket regains
        // ~2 tokens (clamped to capacity 1), so the next attempt succeeds.
        self::$pdo->prepare(
            "UPDATE auth.rate_limits
             SET updated_at = now() - interval '2 seconds'
             WHERE bucket_key = :k"
        )->execute([':k' => $key]);

        $this->assertTrue($rl->attempt($key, 1, 1.0));
        // And it is immediately exhausted again.
        $this->assertFalse($rl->attempt($key, 1, 1.0));
    }
}
