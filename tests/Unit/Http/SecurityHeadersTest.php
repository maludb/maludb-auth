<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\Middleware\SecurityHeaders;
use Maludb\Auth\Http\{Request, Response};
use PHPUnit\Framework\TestCase;

final class SecurityHeadersTest extends TestCase
{
    public function test_adds_hardening_headers_to_response(): void
    {
        $mw = new SecurityHeaders();
        $res = $mw->handle(
            new Request(method: 'GET', path: '/auth/v1/health'),
            fn(Request $r) => Response::json(['ok' => true])
        );

        $this->assertSame('no-store', $res->headers['Cache-Control']);
        $this->assertSame('DENY', $res->headers['X-Frame-Options']);
        $this->assertSame('same-origin', $res->headers['Referrer-Policy']);
        $this->assertSame('nosniff', $res->headers['X-Content-Type-Options']);
    }
}
