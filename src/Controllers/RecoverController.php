<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\Validator;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Services\OtpService;

/**
 * Password recovery + reauthentication request endpoints.
 *
 * Both ALWAYS return a generic 200 regardless of whether the email/user exists,
 * so neither can be used to enumerate accounts. OtpService::send() is silent on
 * every "don't send" branch, and the emailed token is redeemed via /verify
 * (recovery) or consumed as the PUT /user password-change nonce (reauth).
 */
final class RecoverController
{
    public function __construct(
        private OtpService $otp,
        private UserRepository $users,
    ) {}

    public function recover(Request $request, RequestContext $context): Response
    {
        try {
            // Validate shape only; never branch the response on existence.
            $email = Validator::email($request->input('email'));
            $redirectTo = $request->input('redirect_to', '');

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
