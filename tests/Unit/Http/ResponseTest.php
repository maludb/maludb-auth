<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\Response;
use PHPUnit\Framework\TestCase;

final class ResponseTest extends TestCase
{
    public function test_json_response(): void
    {
        $r = Response::json(['a' => 1], 201)->withHeader('X-Test', 'y');
        $this->assertSame(201, $r->status);
        $this->assertSame('{"a":1}', $r->body);
        $this->assertSame('application/json', $r->headers['Content-Type']);
        $this->assertSame('y', $r->headers['X-Test']);
    }

    public function test_cookie_set_and_clear(): void
    {
        $r = Response::json([])
            ->withCookie('mb-access-token', 'jwt', ['httponly' => true, 'path' => '/'])
            ->withClearedCookie('mb-refresh-token', '/auth/v1/token');
        $this->assertCount(2, $r->cookies);
        $this->assertSame('jwt', $r->cookies[0]['value']);
        $this->assertSame('', $r->cookies[1]['value']);
        $this->assertSame(0, $r->cookies[1]['options']['expires']); // cleared
    }

    public function test_resolve_cookie_expiry_deletes_on_negative_maxage(): void
    {
        // withClearedCookie sets maxage=-1 → must resolve to an epoch-past value.
        $this->assertSame(1, Response::resolveCookieExpiry(['maxage' => -1]));
    }

    public function test_resolve_cookie_expiry_future_on_positive_maxage(): void
    {
        $this->assertGreaterThan(time(), Response::resolveCookieExpiry(['maxage' => 3600]));
    }

    public function test_resolve_cookie_expiry_session_cookie_when_no_maxage(): void
    {
        $this->assertSame(0, Response::resolveCookieExpiry([]));
    }

    public function test_json_throws_on_invalid_utf8(): void
    {
        $this->expectException(\JsonException::class);
        Response::json(['bad' => "\xB1\x31"]);
    }
}
