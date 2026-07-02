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

    public function test_path_params_are_url_decoded(): void
    {
        $router = new Router();
        $router->add('GET', '/admin/users/{id}',
            fn(Request $r, array $p) => Response::json(['id' => $p['id']]));
        $res = $router->dispatch($this->req('GET', '/admin/users/a%20b'));
        $this->assertSame('{"id":"a b"}', $res->body);
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

    private function tagging(string $tag): \Maludb\Auth\Http\Middleware\MiddlewareInterface
    {
        return new class($tag) implements \Maludb\Auth\Http\Middleware\MiddlewareInterface {
            public function __construct(private string $tag) {}
            public function handle(Request $r, callable $next): Response
            {
                return $next($r)->withHeader('X-Ran-' . $this->tag, '1');
            }
        };
    }

    private function blocking(): \Maludb\Auth\Http\Middleware\MiddlewareInterface
    {
        return new class implements \Maludb\Auth\Http\Middleware\MiddlewareInterface {
            public function handle(Request $r, callable $next): Response
            { return Response::error('blocked', 'no', 403); }
        };
    }

    public function test_route_middleware_runs_only_for_its_route(): void
    {
        $router = new Router();
        $router->add('GET', '/guarded', fn() => Response::json(['ok' => true]), [$this->tagging('Guard')]);
        $router->add('GET', '/open', fn() => Response::json(['ok' => true]));

        $guarded = $router->dispatch($this->req('GET', '/guarded'));
        $this->assertArrayHasKey('X-Ran-Guard', $guarded->headers);

        $open = $router->dispatch($this->req('GET', '/open'));
        $this->assertArrayNotHasKey('X-Ran-Guard', $open->headers);
    }

    public function test_route_middleware_can_short_circuit(): void
    {
        $router = new Router();
        $router->add('POST', '/admin', fn() => Response::json(['reached' => true]), [$this->blocking()]);

        $res = $router->dispatch($this->req('POST', '/admin'));
        $this->assertSame(403, $res->status);
        $this->assertStringContainsString('blocked', $res->body);
    }

    public function test_route_middleware_runs_after_global_chain(): void
    {
        $router = new Router();
        $router->middleware($this->tagging('Global'));
        $router->add('GET', '/r', fn() => Response::json(['ok' => true]), [$this->tagging('Route')]);

        $res = $router->dispatch($this->req('GET', '/r'));
        $this->assertArrayHasKey('X-Ran-Global', $res->headers);
        $this->assertArrayHasKey('X-Ran-Route', $res->headers);
    }
}
