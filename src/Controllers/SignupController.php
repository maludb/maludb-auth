<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Exceptions\DuplicateEmailException;
use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\TokenResponder;
use Maludb\Auth\Http\UserPresenter;
use Maludb\Auth\Http\Validator;
use Maludb\Auth\Services\AuthService;
use Maludb\Auth\Services\OtpService;
use Maludb\Auth\Services\TokenService;
use Maludb\Auth\Support\Config;

/**
 * POST /auth/v1/signup — register an email+password user.
 *
 * Enumeration defense: a signup for an already-registered email returns the
 * SAME generic 200 success shape as a fresh signup (never "already exists"), so
 * a caller cannot probe which emails have accounts. When autoconfirm is on the
 * success response also issues a live session (like login); otherwise it returns
 * only the public user (client must confirm email — Phase 2).
 *
 * As with /recover, the defense is at the response level, not timing: a genuine
 * signup performs an insert + confirmation mail while the duplicate path returns
 * the fabricated user immediately, so a latency oracle is theoretically possible.
 * The ~10/hr signup rate limit is the accepted bound; constant-work hardening is
 * deferred with the mailer work.
 */
final class SignupController
{
    public function __construct(
        private AuthService $auth,
        private TokenService $tokens,
        private TokenResponder $responder,
        private Config $config,
        private OtpService $otp,
    ) {}

    public function handle(Request $request, RequestContext $context): Response
    {
        try {
            $input = $request->allInput();
            Validator::requirePresent($input, ['email', 'password']);
            $email = Validator::email($input['email']);
            $password = (string) $input['password'];
            $profile = is_array($input['data'] ?? null) ? $input['data'] : [];

            try {
                $user = $this->auth->signup($email, $password, $request->ip, $profile);
            } catch (DuplicateEmailException) {
                // Do NOT reveal the email exists. Return a fabricated,
                // pending-confirmation user object (Supabase's obfuscation
                // strategy): same {user: {...}} shape as a fresh signup that
                // still needs email confirmation, so the caller cannot tell a
                // taken email from a brand-new one. No session is minted and no
                // real user data (id, timestamps) is disclosed.
                return Response::json(['user' => $this->obfuscatedUser($email)], 200);
            }

            // Autoconfirmed users get a live session immediately (parity with login).
            if (($user['email_confirmed_at'] ?? null) !== null) {
                $issued = $this->tokens->issueForUser(
                    $user,
                    $request->ip,
                    (string) ($request->header('user-agent') ?? ''),
                    'aal1',
                    ['password'],
                );

                return $this->responder->respond(
                    $issued,
                    $request->wantsCookies(),
                    (array) $this->config->get('cookie', []),
                );
            }

            // Confirmation required: mint + mail the confirmation token. The
            // response stays the bare user — no session until /verify.
            $redirectTo = $input['redirect_to'] ?? '';
            $this->otp->send(
                'confirmation',
                $email,
                $request->ip,
                createUser: false,
                redirectTo: is_string($redirectTo) ? $redirectTo : '',
            );

            return Response::json(['user' => UserPresenter::toPublic($user)], 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    /**
     * A response-safe, fabricated "pending confirmation" user for the duplicate
     * path. Shaped exactly like UserPresenter output so it is indistinguishable
     * from a genuine unconfirmed signup, but built from a throwaway UUID so it
     * leaks nothing about the real account.
     *
     * @return array<string,mixed>
     */
    private function obfuscatedUser(string $email): array
    {
        $now = gmdate('Y-m-d\TH:i:s\Z');

        return UserPresenter::toPublic([
            'id' => $this->uuidv4(),
            'aud' => 'authenticated',
            'role' => 'authenticated',
            'email' => $email,
            'email_confirmed_at' => null,
            'confirmed_at' => null,
            'created_at' => $now,
            'updated_at' => $now,
            'raw_app_meta_data' => ['provider' => 'email', 'providers' => ['email']],
            'raw_user_meta_data' => [],
        ]);
    }

    private function uuidv4(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }
}
