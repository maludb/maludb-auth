<?php
declare(strict_types=1);

namespace Maludb\Auth\Http\Middleware;

use Maludb\Auth\Http\{Request, RequestContext, Response};
use Maludb\Auth\Repositories\SessionRepository;
use Maludb\Auth\Security\Csrf;

/**
 * The dual-mode CSRF fork — the feature that distinguishes this service from
 * Supabase. It enforces a double-submit CSRF token ONLY for requests that carry
 * an ambient cookie credential on an unsafe (state-changing) method. Bearer
 * requests skip CSRF entirely: an attacker's page cannot forge an Authorization
 * header, so there is no ambient authority to abuse.
 *
 * Order: this runs AFTER AuthContext (it reads the resolved identity) and BEFORE
 * the route handler.
 */
final class CsrfGuard implements MiddlewareInterface
{
    public const HEADER = 'X-CSRF-Token';

    public function __construct(
        private RequestContext $ctx,
        private SessionRepository $sessions,
        private Csrf $csrf,
    ) {}

    public function handle(Request $request, callable $next): Response
    {
        $user = $this->ctx->user;

        // Unauthenticated (public/login routes): no cookie credential to protect.
        if ($user === null) {
            return $next($request);
        }

        // Bearer requests: no ambient credential — CSRF is not applicable.
        if ($user->viaCookie === false) {
            return $next($request);
        }

        // Safe methods never mutate state.
        if (!$request->isUnsafeMethod()) {
            return $next($request);
        }

        // Cookie-auth + unsafe: enforce the double-submit token against the session row.
        $session = $user->sessionId !== null ? $this->sessions->find($user->sessionId) : null;
        if ($session === null) {
            return Response::error('csrf_failed', 'CSRF validation failed.', 403);
        }

        $provided = $request->header(self::HEADER) ?? '';
        $expected = (string) ($session['csrf_token'] ?? '');
        if (!$this->csrf->matches($expected, $provided)) {
            return Response::error('csrf_failed', 'CSRF validation failed.', 403);
        }

        return $next($request);
    }
}
