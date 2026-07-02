<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\Validator;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Services\OtpService;

/**
 * Password recovery + reauthentication request endpoints.
 *
 * Both ALWAYS return a generic 200 regardless of whether the email/user exists,
 * so neither can be used to enumerate accounts. OtpService::send() is silent on
 * every "don't send" branch, and the emailed token is redeemed via /verify
 * (recovery) or consumed as the PUT /user password-change nonce (reauth).
 *
 * Enumeration is defended at the RESPONSE level (uniform body/status), not at
 * the timing level: an existing account does extra work (token replace + mail
 * dispatch) so a latency oracle remains theoretically possible. This is bounded
 * by the aggressive /recover rate limit (~5/hr per IP+email), which is the
 * accepted mitigation; a fuller fix (constant-work dummy send, or async mail)
 * is deferred with the rest of the mailer hardening.
 */
final class RecoverController
{
    public function __construct(
        private OtpService $otp,
        private UserRepository $users,
        private AuditRepository $audit,
    ) {}

    public function recover(Request $request, RequestContext $context): Response
    {
        try {
            // Validate shape only; never branch the response on existence.
            $email = Validator::email($request->input('email'));
            $redirectTo = $request->input('redirect_to', '');

            // Audit EVERY request unconditionally (before the may-be-silent
            // send), so probes against unknown or banned accounts still leave a
            // trace an operator can find via GET /admin/audit — the enumeration
            // defense makes the RESPONSE uniform, not the server-side record.
            $this->audit->record('recover_requested', ['email' => $email], $request->ip);

            $this->otp->send(
                'recovery',
                $email,
                $request->ip,
                createUser: false,
                redirectTo: is_string($redirectTo) ? $redirectTo : '',
            );

            return $this->generic();
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    public function reauthenticate(Request $request, RequestContext $context): Response
    {
        if ($context->user === null) {
            return Response::json(['error' => 'not_authenticated'], 401);
        }

        try {
            $user = $this->users->findById($context->user->userId);
            if ($user !== null && is_string($user['email'] ?? null) && $user['email'] !== '') {
                // Code-only mail (no verify link); consumed by PUT /user as `nonce`.
                $this->otp->send('reauthentication', (string) $user['email'], $request->ip);
            }

            return $this->generic();
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    private function generic(): Response
    {
        return Response::json([], 200);
    }
}
