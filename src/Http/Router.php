<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

use Maludb\Auth\Http\Middleware\MiddlewareInterface;

final class Router
{
    private array $routes = [];
    /** @var MiddlewareInterface[] */
    private array $middleware = [];

    /**
     * @param MiddlewareInterface[] $routeMiddleware Per-route middleware run,
     *        onion-style, AFTER the global chain and BEFORE the handler. Applies
     *        to this route only (e.g. RequireAdmin on /admin/* routes).
     */
    public function add(string $method, string $path, callable $handler, array $routeMiddleware = []): void
    {
        $pattern = '#^' . preg_replace('#\{(\w+)\}#', '(?P<$1>[^/]+)', $path) . '$#';
        $this->routes[] = compact('method', 'pattern', 'handler', 'routeMiddleware');
    }

    public function middleware(MiddlewareInterface $m): void { $this->middleware[] = $m; }

    public function dispatch(Request $request): Response
    {
        $core = function (Request $req): Response {
            foreach ($this->routes as $route) {
                if ($route['method'] !== $req->method) continue;
                if (preg_match($route['pattern'], $req->path, $m)) {
                    $params = array_map(
                        'rawurldecode',
                        array_filter($m, 'is_string', ARRAY_FILTER_USE_KEY)
                    );
                    $handler = fn(Request $r): Response => ($route['handler'])($r, $params);

                    // Wrap the matched handler in its own route-level middleware
                    // onion (outermost first), so per-route guards run only for
                    // this route, after the global chain has already resolved.
                    $handler = array_reduce(
                        array_reverse($route['routeMiddleware']),
                        fn(callable $next, MiddlewareInterface $mw) =>
                            fn(Request $r) => $mw->handle($r, $next),
                        $handler
                    );

                    return $handler($req);
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
