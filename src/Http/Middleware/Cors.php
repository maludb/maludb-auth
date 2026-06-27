<?php
declare(strict_types=1);

namespace Maludb\Auth\Http\Middleware;

use Maludb\Auth\Http\{Request, Response};

/**
 * CORS middleware.
 *
 * Echoes an allowed request Origin (validated against SITE_URL and the
 * URI allow-list) back as Access-Control-Allow-Origin and short-circuits
 * OPTIONS preflight requests with a 204.
 */
final class Cors implements MiddlewareInterface
{
    private const ALLOW_HEADERS = 'Authorization, Content-Type, X-CSRF-Token';
    private const ALLOW_METHODS = 'GET, POST, PUT, PATCH, DELETE, OPTIONS';

    /**
     * @param string|null $siteUrl  Canonical site origin (SITE_URL).
     * @param string[]    $allowList Patterns from URI_ALLOW_LIST; a trailing
     *                               `/*` (or `*`) is treated as a prefix wildcard.
     */
    public function __construct(
        private ?string $siteUrl = null,
        private array $allowList = [],
    ) {}

    public function handle(Request $request, callable $next): Response
    {
        $origin = $request->header('origin');
        $allowedOrigin = $origin !== null && $this->isAllowed($origin) ? $origin : null;

        if ($request->method === 'OPTIONS') {
            return $this->decorate(new Response(status: 204), $allowedOrigin);
        }

        return $this->decorate($next($request), $allowedOrigin);
    }

    private function decorate(Response $response, ?string $allowedOrigin): Response
    {
        if ($allowedOrigin === null) {
            return $response;
        }

        return $response
            ->withHeader('Access-Control-Allow-Origin', $allowedOrigin)
            ->withHeader('Access-Control-Allow-Credentials', 'true')
            ->withHeader('Access-Control-Allow-Headers', self::ALLOW_HEADERS)
            ->withHeader('Access-Control-Allow-Methods', self::ALLOW_METHODS)
            ->withHeader('Vary', 'Origin');
    }

    private function isAllowed(string $origin): bool
    {
        if ($this->siteUrl !== null && $this->siteUrl !== '' && $origin === $this->siteUrl) {
            return true;
        }

        foreach ($this->allowList as $pattern) {
            $pattern = trim($pattern);
            if ($pattern === '') {
                continue;
            }
            if ($this->matches($origin, $pattern)) {
                return true;
            }
        }

        return false;
    }

    private function matches(string $origin, string $pattern): bool
    {
        // Strip a trailing path-wildcard so `http://localhost:3000/*` matches the
        // bare origin `http://localhost:3000`.
        $prefix = preg_replace('#/?\*$#', '', $pattern);
        if ($prefix === $origin) {
            return true;
        }

        return str_ends_with($pattern, '*') && str_starts_with($origin, $prefix);
    }
}
