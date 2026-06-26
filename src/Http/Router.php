<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

use Maludb\Auth\Http\Middleware\MiddlewareInterface;

final class Router
{
    private array $routes = [];
    /** @var MiddlewareInterface[] */
    private array $middleware = [];

    public function add(string $method, string $path, callable $handler): void
    {
        $pattern = '#^' . preg_replace('#\{(\w+)\}#', '(?P<$1>[^/]+)', $path) . '$#';
        $this->routes[] = compact('method', 'pattern', 'handler');
    }

    public function middleware(MiddlewareInterface $m): void { $this->middleware[] = $m; }

    public function dispatch(Request $request): Response
    {
        $core = function (Request $req): Response {
            foreach ($this->routes as $route) {
                if ($route['method'] !== $req->method) continue;
                if (preg_match($route['pattern'], $req->path, $m)) {
                    $params = array_filter($m, 'is_string', ARRAY_FILTER_USE_KEY);
                    return ($route['handler'])($req, $params);
                }
            }
            return Response::error('not_found', 'No route matched.', 404);
        };

        $chain = array_reduce(
            array_reverse($this->middleware),
            fn(callable $next, MiddlewareInterface $mw) =>
                fn(Request $req) => $mw->handle($req, $next),
            $core
        );
        return $chain($request);
    }
}
