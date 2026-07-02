<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\TokenResponder;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\SessionRepository;

/**
 * POST /auth/v1/logout — revoke the caller's session(s).
 *
 * Requires an authenticated request (RequestContext::user). Scope controls how
 * much is revoked:
 *   - local   (default): just this session.
 *   - global:            every session for the user.
 *   - others:            all sessions except the current one.
 *
 * Always clears the access + refresh cookies (harmless in bearer mode) and
 * returns 204. Deleting the session cascades to its refresh tokens.
 */
final class LogoutController
{
    public function __construct(
        private SessionRepository $sessions,
        private AuditRepository $audit,
    ) {}

    public function handle(Request $request, RequestContext $context): Response
    {
        $user = $context->user;
        if ($user === null) {
            return Response::json(['error' => 'not_authenticated'], 401);
        }

        try {
            $scope = $request->input('scope') ?? $request->query('scope') ?? 'local';
            $sessionId = $user->sessionId;

            match ($scope) {
                'global' => $this->sessions->deleteAllForUser($user->userId),
                'others' => $sessionId !== null
                    ? $this->sessions->deleteOthersForUser($user->userId, $sessionId)
                    : null,
                default => $sessionId !== null ? $this->sessions->delete($sessionId) : null,
            };

            $this->audit->record('logout', [
                'user_id' => $user->userId,
                'scope' => $scope,
            ], $request->ip);

            return (new Response(status: 204))
                ->withClearedCookie(TokenResponder::ACCESS_COOKIE, '/')
                ->withClearedCookie(TokenResponder::REFRESH_COOKIE, TokenResponder::REFRESH_COOKIE_PATH);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }
}
