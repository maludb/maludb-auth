<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Exceptions\ValidationException;
use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\Validator;
use Maludb\Auth\Services\OtpService;

/**
 * Passwordless request endpoints: POST /otp, POST /magiclink, POST /resend.
 *
 * All three return the SAME generic 200 {} whether or not the email has an
 * account (OtpService's silent branches) — only malformed input gets a 400.
 */
final class OtpController
{
    /** /resend accepts these and maps them onto token types. */
    private const RESEND_TYPES = [
        'signup' => 'confirmation',
        'magiclink' => 'magiclink',
        'recovery' => 'recovery',
    ];

    public function __construct(private OtpService $otp) {}

    /** POST /otp — magic link / email OTP; may create the user. */
    public function otp(Request $request, RequestContext $context): Response
    {
        return $this->sendFor($request, 'magiclink', createUserDefault: true);
    }

    /** POST /magiclink — legacy alias; never creates users. */
    public function magiclink(Request $request, RequestContext $context): Response
    {
        return $this->sendFor($request, 'magiclink', createUserDefault: false);
    }

    /** POST /resend — re-send a confirmation/magiclink/recovery token. */
    public function resend(Request $request, RequestContext $context): Response
    {
        try {
            $type = $request->input('type');
            if (!is_string($type) || !isset(self::RESEND_TYPES[$type])) {
                throw new ValidationException('A valid type is required (signup, magiclink, recovery).');
            }
            $email = Validator::email($request->input('email'));

            $this->otp->send(
                self::RESEND_TYPES[$type],
                $email,
                $request->ip,
                createUser: false,
                redirectTo: $this->redirectTo($request),
            );

            return Response::json([], 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    private function sendFor(Request $request, string $type, bool $createUserDefault): Response
    {
        try {
            $email = Validator::email($request->input('email'));
            $createUser = (bool) ($request->input('create_user', $createUserDefault));

            $this->otp->send(
                $type,
                $email,
                $request->ip,
                createUser: $createUser,
                redirectTo: $this->redirectTo($request),
            );

            return Response::json([], 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    private function redirectTo(Request $request): string
    {
        $r = $request->input('redirect_to', $request->query('redirect_to', ''));

        return is_string($r) ? $r : '';
    }
}
