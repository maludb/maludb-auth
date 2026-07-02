<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\Request;
use PHPUnit\Framework\TestCase;

final class RequestTest extends TestCase
{
    public function test_parses_method_path_query_json_body_headers(): void
    {
        $r = new Request(
            method: 'POST',
            path: '/auth/v1/signup',
            query: ['cookie' => 'true'],
            headers: ['Authorization' => 'Bearer abc', 'X-CSRF-Token' => 'tok'],
            rawBody: '{"email":"A@x.com","password":"secret"}',
            cookies: ['mb-access-token' => 'jwt'],
            ip: '203.0.113.5'
        );

        $this->assertSame('POST', $r->method);
        $this->assertSame('/auth/v1/signup', $r->path);
        $this->assertSame('true', $r->query('cookie'));
        $this->assertSame('A@x.com', $r->input('email'));
        $this->assertSame('Bearer abc', $r->header('Authorization'));
        $this->assertSame('tok', $r->header('x-csrf-token')); // case-insensitive
        $this->assertSame('jwt', $r->cookie('mb-access-token'));
        $this->assertTrue($r->wantsCookies());
        $this->assertSame('abc', $r->bearerToken());
    }
}
