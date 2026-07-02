<?php
declare(strict_types=1);

namespace Maludb\Auth\Http\Middleware;

use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\{Request, Response};
use Maludb\Auth\Support\Config;

/**
 * Gate for /auth/v1/admin/* routes. A request is admin-authorized when EITHER:
 *
 *   - the authenticated user's role is 'service_role' (a service-role JWT
 *     resolved by AuthContext), OR
 *   - the request carries the configured SERVICE_ROLE_KEY in the `apikey` or
 *     `Authorization` header (server-to-server callers without a JWT).
 *
 * Otherwise it short-circuits with 403 not_admin. The key comparison is
 * constant-time to avoid a timing side channel on the secret.
 */
final class RequireAdmin implements MiddlewareInterface
{
    public function __construct(
        private RequestContext $context,
        private Config $config,
    ) {}

    public function handle(Request $request, callable $next): Response
    {
        if ($this->isAuthorized($request)) {
            return $next($request);
        }

        return Response::json(['error' => 'not_admin'], 403);
    }

    private function isAuthorized(Request $request): bool
    {
        if ($this->context->user?->role === 'service_role') {
            return true;
        }

        $configured = $this->config->get('service_role.key');
        if (!is_string($configured) || $configured === '') {
            // No key configured → the header path is disabled; only a
            // service_role JWT can pass.
            return false;
        }

        $presented = $this->presentedKey($request);

        return $presented !== null && hash_equals($configured, $presented);
    }

    private function presentedKey(Request $request): ?string
    {
        $apikey = $request->header('apikey');
        if (is_string($apikey) && $apikey !== '') {
            return $apikey;
        }

        // Bearer <key> in the Authorization header is also accepted.
        $bearer = $request->bearerToken();

        return ($bearer !== null && $bearer !== '') ? $bearer : null;
    }
}
