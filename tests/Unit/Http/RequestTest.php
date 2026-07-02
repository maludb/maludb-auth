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

    /**
     * The method must be canonicalized to uppercase at the edge. Storing it
     * verbatim would let a lowercase `post` slip past isUnsafeMethod() (which
     * compares against uppercase literals) and bypass CSRF/rate-limit handling.
     */
    public function test_method_is_normalized_to_uppercase(): void
    {
        $this->assertSame('POST', (new Request(method: 'post', path: '/x'))->method);
        $this->assertTrue((new Request(method: 'post', path: '/x'))->isUnsafeMethod());
        $this->assertSame('DELETE', (new Request(method: ' Delete ', path: '/x'))->method);
        $this->assertTrue((new Request(method: 'Delete', path: '/x'))->isUnsafeMethod());
        // Idempotent for already-canonical input.
        $this->assertSame('GET', (new Request(method: 'GET', path: '/x'))->method);
        $this->assertFalse((new Request(method: 'GET', path: '/x'))->isUnsafeMethod());
    }

    /**
     * bearerToken() must read ONLY the real Authorization header. An attacker
     * must not be able to promote to bearer precedence (which skips CSRF) via a
     * query param or body field named access_token.
     */
    public function test_bearer_token_reads_only_authorization_header(): void
    {
        $r = new Request(
            method: 'GET',
            path: '/x',
            query: ['access_token' => 'query-token'],
            rawBody: '{"access_token":"body-token"}',
        );

        $this->assertNull($r->bearerToken());
    }
}
