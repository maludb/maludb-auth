<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Http\Middleware\RateLimit;
use Maludb\Auth\Http\{Request, Response};
use Maludb\Auth\Security\RateLimiter;
use Maludb\Auth\Security\RateLimiterInterface;
use PDOException;

final class RateLimitMiddlewareTest extends IntegrationTestCase
{
    /** Tiny capacity + negligible refill so we can exhaust the bucket deterministically. */
    private const LIMITS = [
        'login'  => ['capacity' => 3, 'refillPerSecond' => 0.0001],
        'signup' => ['capacity' => 3, 'refillPerSecond' => 0.0001],
    ];

    private function next(): callable
    {
        return fn(Request $r): Response => Response::json(['reached' => true]);
    }

    private function loginRequest(string $ip = '198.51.100.7', ?string $email = null): Request
    {
        $body = $email !== null ? json_encode(['email' => $email]) : '';
        return new Request(
            method: 'POST',
            path: '/auth/v1/token',
            query: ['grant_type' => 'password'],
            rawBody: $body,
            ip: $ip,
        );
    }

    public function test_under_capacity_passes(): void
    {
        $mw = new RateLimit(new RateLimiter(self::$pdo), self::LIMITS);
        $res = $mw->handle($this->loginRequest(), $this->next());
        $this->assertSame(200, $res->status);
    }

    public function test_beyond_capacity_returns_429_with_retry_after(): void
    {
        $mw = new RateLimit(new RateLimiter(self::$pdo), self::LIMITS);
        $ip = '198.51.100.42';

        // capacity 3: first three consume tokens (allowed), fourth is blocked.
        for ($i = 0; $i < 3; $i++) {
            $this->assertSame(200, $mw->handle($this->loginRequest($ip), $this->next())->status);
        }

        $res = $mw->handle($this->loginRequest($ip), $this->next());
        $this->assertSame(429, $res->status);
        $this->assertArrayHasKey('Retry-After', $res->headers);
        $this->assertStringContainsString('over_rate_limit', $res->body);
    }

    public function test_email_bucket_enforced_independently_of_ip(): void
    {
        $mw = new RateLimit(new RateLimiter(self::$pdo), self::LIMITS);
        $email = 'target@example.com';

        // Same email, different IPs each time: IP bucket never exhausts, but the
        // shared email bucket (capacity 3) does.
        for ($i = 0; $i < 3; $i++) {
            $ip = '203.0.113.' . $i;
            $this->assertSame(200, $mw->handle($this->loginRequest($ip, $email), $this->next())->status);
        }

        $res = $mw->handle($this->loginRequest('203.0.113.99', $email), $this->next());
        $this->assertSame(429, $res->status);
    }

    public function test_unmatched_request_passes_unthrottled(): void
    {
        $mw = new RateLimit(new RateLimiter(self::$pdo), self::LIMITS);
        // GET is a safe method; not a rate-limited category.
        $req = new Request(method: 'GET', path: '/auth/v1/health', ip: '1.2.3.4');
        for ($i = 0; $i < 20; $i++) {
            $this->assertSame(200, $mw->handle($req, $this->next())->status);
        }
    }

    public function test_fails_closed_when_limiter_throws(): void
    {
        $throwing = new class implements RateLimiterInterface {
            public function attempt(string $key, int $capacity, float $refillPerSecond): bool
            {
                throw new PDOException('datastore down');
            }
        };
        $mw = new RateLimit($throwing, self::LIMITS);

        $res = $mw->handle($this->loginRequest(), $this->next());

        // Must DENY (never fall through to 200) when the limiter errors.
        $this->assertContains($res->status, [429, 503]);
        $this->assertNotSame(200, $res->status);
        $this->assertArrayHasKey('Retry-After', $res->headers);
    }
}
