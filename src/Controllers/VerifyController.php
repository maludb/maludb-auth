<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Dto\IssuedTokens;
use Maludb\Auth\Exceptions\ValidationException;
use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\TokenResponder;
use Maludb\Auth\Security\RedirectValidator;
use Maludb\Auth\Services\OtpService;
use Maludb\Auth\Support\Config;

/**
 * GET|POST /auth/v1/verify — redeem a one-time token for a session.
 *
 * POST is the API form: JSON {type, token, email} (code) or {type, token_hash}
 * (link), answered by TokenResponder (Bearer body or ?cookie=true cookies).
 *
 * GET is the emailed-link form: token_hash + type + redirect_to in the query.
 * The redirect target is resolved through RedirectValidator (open-redirect
 * defense) and tokens travel in the URL FRAGMENT — never the query string — so
 * they can't leak via Referer headers or server logs. Failures redirect with a
 * generic error fragment: invalid, expired, and consumed are indistinguishable.
 */
final class VerifyController
{
    /** verify `type` values → stored token_type. */
    private const VERIFY_TYPES = [
        'signup' => 'confirmation',
        'invite' => 'invite',
        'recovery' => 'recovery',
        'magiclink' => 'magiclink',
        'email' => 'magiclink',
    ];

    public function __construct(
        private OtpService $otp,
        private TokenResponder $responder,
        private RedirectValidator $redirects,
        private Config $config,
    ) {}

    public function post(Request $request, RequestContext $context): Response
    {
        try {
            $tokenType = $this->tokenType($request->input('type'));

            $issued = $this->otp->verify(
                $tokenType,
                $this->str($request->input('email')),
                $this->str($request->input('token')),
                $this->str($request->input('token_hash')),
                $request->ip,
                (string) ($request->header('user-agent') ?? ''),
            );

            return $this->responder->respond(
                $issued,
                $request->wantsCookies(),
                (array) $this->config->get('cookie', []),
            );
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    public function get(Request $request, RequestContext $context): Response
    {
        $redirect = $this->redirects->resolve($request->query('redirect_to'));

        try {
            $type = (string) $request->query('type', '');
            $tokenType = $this->tokenType($type);

            $issued = $this->otp->verify(
                $tokenType,
                $this->str($request->query('email')),
                $this->str($request->query('token')),
                $this->str($request->query('token_hash')),
                $request->ip,
                (string) ($request->header('user-agent') ?? ''),
            );

            return Response::redirect($this->withFragment($redirect, $this->successFragment($issued, $type)));
        } catch (\Throwable) {
            // Generic failure fragment — no cause disclosed, no exception detail.
            return Response::redirect($this->withFragment($redirect, http_build_query([
                'error' => 'access_denied',
                'error_code' => 'otp_expired',
                'error_description' => 'Email link is invalid or has expired',
            ])));
        }
    }

    /**
     * Append token params to the redirect's fragment. If the (allow-listed)
     * target already carries a fragment — e.g. a hash-router SPA URL like
     * 'https://app/#/callback' — join with '&' so the params land in the SAME
     * fragment; a second '#' would make the browser fold everything into one
     * fragment and the client could never parse access_token out of it.
     */
    private function withFragment(string $url, string $params): string
    {
        $separator = str_contains($url, '#') ? '&' : '#';

        return $url . $separator . $params;
    }

    private function successFragment(IssuedTokens $issued, string $type): string
    {
        return http_build_query([
            'access_token' => $issued->accessToken,
            'refresh_token' => $issued->refreshToken,
            'token_type' => 'bearer',
            'expires_in' => $issued->expiresIn,
            'type' => $type,
        ]);
    }

    private function tokenType(mixed $type): string
    {
        if (!is_string($type) || !isset(self::VERIFY_TYPES[$type])) {
            throw new ValidationException('A valid type is required (signup, invite, recovery, magiclink, email).');
        }

        return self::VERIFY_TYPES[$type];
    }

    private function str(mixed $v): ?string
    {
        return is_string($v) ? $v : null;
    }
}
