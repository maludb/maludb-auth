<?php
declare(strict_types=1);

namespace Maludb\Auth\Http\Middleware;

use Maludb\Auth\Http\{AuthenticatedUser, Request, RequestContext, Response};
use Maludb\Auth\Security\Jwt;
use Throwable;

/**
 * Resolves the caller's identity from a validated access token and writes it to
 * the per-request RequestContext. Bearer header wins over the access-token
 * cookie. This middleware NEVER rejects a request: on a missing, invalid, or
 * expired token it simply leaves `$ctx->user` null and lets downstream
 * (route-level auth guards) decide whether that route requires authentication.
 */
final class AuthContext implements MiddlewareInterface
{
    public const ACCESS_TOKEN_COOKIE = 'mb-access-token';

    public function __construct(
        private Jwt $jwt,
        private RequestContext $ctx,
    ) {}

    public function handle(Request $request, callable $next): Response
    {
        $token = $request->bearerToken();
        $viaCookie = false;

        if ($token === null || $token === '') {
            $cookie = $request->cookie(self::ACCESS_TOKEN_COOKIE);
            if ($cookie !== null && $cookie !== '') {
                $token = $cookie;
                $viaCookie = true;
            }
        }

        if ($token !== null && $token !== '') {
            try {
                $claims = $this->jwt->verify($token);
                $this->ctx->user = new AuthenticatedUser(
                    userId: (string) ($claims['sub'] ?? ''),
                    sessionId: isset($claims['session_id']) ? (string) $claims['session_id'] : null,
                    role: (string) ($claims['role'] ?? 'authenticated'),
                    claims: $claims,
                    viaCookie: $viaCookie,
                );
            } catch (Throwable) {
                // Invalid / expired / iss-aud mismatch: leave identity unresolved.
                // Downstream decides whether the route needs auth (no 401 here).
                $this->ctx->user = null;
            }
        }

        return $next($request);
    }
}
