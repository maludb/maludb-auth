<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\{Router, Request, Response};
use PHPUnit\Framework\TestCase;

final class RouterTest extends TestCase
{
    private function req(string $m, string $p): Request
    { return new Request(method: $m, path: $p); }

    public function test_matches_and_dispatches(): void
    {
        $router = new Router();
        $router->add('GET', '/health', fn(Request $r) => Response::json(['ok' => true]));
        $res = $router->dispatch($this->req('GET', '/health'));
        $this->assertSame(200, $res->status);
    }

    public function test_unknown_route_returns_404(): void
    {
        $res = (new Router())->dispatch($this->req('GET', '/nope'));
        $this->assertSame(404, $res->status);
    }

    public function test_path_params_extracted(): void
    {
        $router = new Router();
        $router->add('GET', '/admin/users/{id}',
            fn(Request $r, array $p) => Response::json(['id' => $p['id']]));
        $res = $router->dispatch($this->req('GET', '/admin/users/42'));
        $this->assertSame('{"id":"42"}', $res->body);
    }

    public function test_middleware_short_circuits(): void
    {
        $router = new Router();
        $router->add('GET', '/x', fn() => Response::json(['reached' => true]));
        $router->middleware(new class implements \Maludb\Auth\Http\Middleware\MiddlewareInterface {
            public function handle(Request $r, callable $next): Response
            { return Response::error('blocked', 'no', 403); }
        });
        $res = $router->dispatch($this->req('GET', '/x'));
        $this->assertSame(403, $res->status);
    }
}
