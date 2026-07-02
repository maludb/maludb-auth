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
     * @param string[]    $allowList Entries from URI_ALLOW_LIST. Each may carry a
     *                               path or `/*` (it doubles as the redirect-URL
     *                               allowlist); only the derived origin is matched.
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
        // Vary on Origin for EVERY response the middleware touches (allowed,
        // disallowed, and preflight) so shared caches never serve a credentialed
        // allow-origin to a different origin.
        $response = $response->withHeader('Vary', 'Origin');

        if ($allowedOrigin === null) {
            return $response;
        }

        return $response
            ->withHeader('Access-Control-Allow-Origin', $allowedOrigin)
            ->withHeader('Access-Control-Allow-Credentials', 'true')
            ->withHeader('Access-Control-Allow-Headers', self::ALLOW_HEADERS)
            ->withHeader('Access-Control-Allow-Methods', self::ALLOW_METHODS);
    }

    /**
     * A request Origin is allowed iff it EXACTLY equals the origin derived from
     * SITE_URL or any URI_ALLOW_LIST entry. Exact comparison only — no prefix
     * matching — to prevent credentialed-CORS bypasses such as
     * `http://localhost:3000.evil.com`, `http://localhost:30000`, or
     * `http://localhost:3000@evil.com`.
     */
    private function isAllowed(string $origin): bool
    {
        if ($this->siteUrl !== null && $origin === $this->originOf($this->siteUrl)) {
            return true;
        }

        foreach ($this->allowList as $entry) {
            if ($origin === $this->originOf((string) $entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Derive the scheme://host[:port] origin from a configured URL via parse_url.
     * Entries may include a path or `/*`; everything but the origin is dropped.
     * Returns null for unparseable entries so they never match a request origin.
     */
    private function originOf(string $url): ?string
    {
        $p = parse_url(trim($url));
        if (empty($p['scheme']) || empty($p['host'])) {
            return null;
        }
        $origin = $p['scheme'] . '://' . $p['host'];
        if (isset($p['port'])) {
            $origin .= ':' . $p['port'];
        }
        return $origin;
    }
}
