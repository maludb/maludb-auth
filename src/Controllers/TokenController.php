<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Exceptions\ValidationException;
use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\TokenResponder;
use Maludb\Auth\Http\Validator;
use Maludb\Auth\Services\AuthService;
use Maludb\Auth\Services\TokenService;
use Maludb\Auth\Support\Config;

/**
 * POST /auth/v1/token — the OAuth-style token endpoint.
 *
 * The grant is selected from the QUERY string (`?grant_type=...`), which is the
 * canonical location (it also matches what the RateLimit middleware keys on):
 *   - password:      email+password login.
 *   - refresh_token: rotate a refresh token (body `refresh_token` in bearer mode,
 *                    or the `mb-refresh-token` cookie in cookie mode).
 *
 * All credential/refresh failures are mapped to a single generic invalid_grant
 * by ErrorMapper, so the endpoint cannot be used to enumerate accounts.
 */
final class TokenController
{
    public function __construct(
        private AuthService $auth,
        private TokenService $tokens,
        private TokenResponder $responder,
        private Config $config,
    ) {}

    public function handle(Request $request, RequestContext $context): Response
    {
        try {
            return match ($this->grantType($request)) {
                'password' => $this->passwordGrant($request),
                'refresh_token' => $this->refreshGrant($request),
                default => Response::json([
                    'error' => 'unsupported_grant_type',
                    'error_description' => 'grant_type must be password or refresh_token.',
                ], 400),
            };
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    /**
     * Resolve grant_type from the QUERY string (canonical), falling back to the
     * JSON body. This mirrors RateLimit's resolution so the limiter and the
     * controller always agree on the grant a request carries (Unit 12 M1).
     */
    private function grantType(Request $request): ?string
    {
        $grant = $request->query('grant_type');
        if ($grant === null || $grant === '') {
            $bodyGrant = $request->input('grant_type');
            $grant = is_string($bodyGrant) ? $bodyGrant : null;
        }

        return $grant;
    }

    private function passwordGrant(Request $request): Response
    {
        $input = $request->allInput();
        Validator::requirePresent($input, ['email', 'password']);
        $email = Validator::email($input['email']);

        $issued = $this->auth->login(
            $email,
            (string) $input['password'],
            $request->ip,
            (string) ($request->header('user-agent') ?? ''),
        );

        return $this->responder->respond(
            $issued,
            $request->wantsCookies(),
            (array) $this->config->get('cookie', []),
        );
    }

    private function refreshGrant(Request $request): Response
    {
        // Bearer mode carries the token in the body; cookie mode in the cookie.
        $token = $request->input('refresh_token')
            ?? $request->cookie(TokenResponder::REFRESH_COOKIE);

        if (!is_string($token) || $token === '') {
            throw new ValidationException('Missing refresh token.');
        }

        $issued = $this->tokens->refresh(
            $token,
            $request->ip,
            (string) ($request->header('user-agent') ?? ''),
        );

        return $this->responder->respond(
            $issued,
            $request->wantsCookies(),
            (array) $this->config->get('cookie', []),
        );
    }
}
