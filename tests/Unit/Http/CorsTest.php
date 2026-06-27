<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\Middleware\Cors;
use Maludb\Auth\Http\{Request, Response};
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CorsTest extends TestCase
{
    private function cors(): Cors
    {
        return new Cors('http://localhost:3000', ['http://localhost:3000/*']);
    }

    private function request(?string $origin, string $method = 'GET'): Request
    {
        $headers = $origin === null ? [] : ['Origin' => $origin];
        return new Request(method: $method, path: '/auth/v1/health', headers: $headers);
    }

    private function next(): callable
    {
        return fn(Request $r) => Response::json(['ok' => true]);
    }

    public function test_exact_allowed_origin_is_reflected_with_credentials(): void
    {
        $res = $this->cors()->handle($this->request('http://localhost:3000'), $this->next());

        $this->assertSame('http://localhost:3000', $res->headers['Access-Control-Allow-Origin']);
        $this->assertSame('true', $res->headers['Access-Control-Allow-Credentials']);
        $this->assertSame('Origin', $res->headers['Vary']);
    }

    /** @return array<string, array{string}> */
    public static function bypassOrigins(): array
    {
        return [
            'suffix host'     => ['http://localhost:3000.evil.com'],
            'longer port'     => ['http://localhost:30000'],
            'userinfo at'     => ['http://localhost:3000@evil.com'],
            'different host'  => ['https://evil.com'],
        ];
    }

    #[DataProvider('bypassOrigins')]
    public function test_disallowed_origin_is_not_reflected_but_still_varies(string $origin): void
    {
        $res = $this->cors()->handle($this->request($origin), $this->next());

        $this->assertArrayNotHasKey('Access-Control-Allow-Origin', $res->headers);
        $this->assertArrayNotHasKey('Access-Control-Allow-Credentials', $res->headers);
        $this->assertSame('Origin', $res->headers['Vary']);
    }

    public function test_missing_origin_is_not_reflected_but_still_varies(): void
    {
        $res = $this->cors()->handle($this->request(null), $this->next());

        $this->assertArrayNotHasKey('Access-Control-Allow-Origin', $res->headers);
        $this->assertSame('Origin', $res->headers['Vary']);
    }

    public function test_preflight_short_circuits_without_calling_next(): void
    {
        $called = false;
        $next = function (Request $r) use (&$called): Response {
            $called = true;
            return Response::json(['reached' => true]);
        };

        $res = $this->cors()->handle($this->request('http://localhost:3000', 'OPTIONS'), $next);

        $this->assertSame(204, $res->status);
        $this->assertFalse($called, 'downstream handler must not be invoked for preflight');
        $this->assertSame('http://localhost:3000', $res->headers['Access-Control-Allow-Origin']);
        $this->assertSame('Origin', $res->headers['Vary']);
    }
}
