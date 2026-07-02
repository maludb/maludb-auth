<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\UserPresenter;
use Maludb\Auth\Http\Validator;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\SessionRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Security\Csrf;
use Maludb\Auth\Security\Password;
use Maludb\Auth\Services\OtpService;
use Maludb\Auth\Support\Config;

/**
 * /auth/v1/user — the authenticated user's self-service endpoint.
 *
 * GET reloads and returns the caller's own public user. PUT updates a bounded
 * set of self-serviceable fields. The app_metadata boundary is enforced here:
 * app_metadata is server-controlled and any value in the request body is
 * ignored, so a user cannot escalate their own privileges/claims.
 */
final class UserController
{
    public function __construct(
        private UserRepository $users,
        private SessionRepository $sessions,
        private AuditRepository $audit,
        private Password $password,
        private Csrf $csrf,
        private OtpService $otp,
        private Config $config,
    ) {}

    public function show(Request $request, RequestContext $context): Response
    {
        $auth = $context->user;
        if ($auth === null) {
            return Response::json(['error' => 'not_authenticated'], 401);
        }

        try {
            $user = $this->users->findById($auth->userId);
            if ($user === null) {
                return Response::json(['error' => 'not_authenticated'], 401);
            }

            return Response::json(UserPresenter::toPublic($user), 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    public function update(Request $request, RequestContext $context): Response
    {
        $auth = $context->user;
        if ($auth === null) {
            return Response::json(['error' => 'not_authenticated'], 401);
        }

        try {
            $user = $this->users->findById($auth->userId);
            if ($user === null) {
                return Response::json(['error' => 'not_authenticated'], 401);
            }

            $input = $request->allInput();
            $attrs = [];

            if (array_key_exists('phone', $input)) {
                $attrs['phone'] = $input['phone'];
            }
            if (array_key_exists('email', $input)) {
                // TODO(Phase 2): email change must require a reauthentication
                // nonce + confirmation email before it takes effect. For Phase 1
                // it is gated behind a present valid session (+ CSRF in cookie
                // mode, enforced by middleware) and applied directly.
                $attrs['email'] = Validator::email($input['email']);
            }
            // user_metadata maps to raw_user_meta_data. app_metadata is
            // deliberately NOT read from the body — server-controlled boundary.
            if (array_key_exists('user_metadata', $input) && is_array($input['user_metadata'])) {
                $attrs['raw_user_meta_data'] = $input['user_metadata'];
            }

            $passwordChanged = false;
            if (array_key_exists('password', $input) && $input['password'] !== null && $input['password'] !== '') {
                // When the deployment demands it, a password change must present
                // a live reauthentication nonce (mailed by POST /reauthenticate)
                // on top of the valid session (+ CSRF in cookie mode). The nonce
                // is consumed on use — a second change needs a fresh one.
                if ((bool) $this->config->get('security.update_password_require_reauthentication', false)) {
                    $nonce = $input['nonce'] ?? null;
                    if (!is_string($nonce)
                        || $nonce === ''
                        || !$this->otp->consumeReauthentication($auth->userId, $nonce)) {
                        return Response::json([
                            'error' => 'reauthentication_needed',
                            'error_description' => 'Password change requires reauthentication.',
                        ], 400);
                    }
                }
                $attrs['encrypted_password'] = $this->password->hash((string) $input['password']);
                $passwordChanged = true;
            }

            if ($attrs !== []) {
                $user = $this->users->update($auth->userId, $attrs);
            }

            if ($passwordChanged && $auth->sessionId !== null) {
                // Revoke every OTHER session and rotate this session's CSRF token
                // so a stolen cookie/token from before the change is neutralized.
                $this->sessions->deleteOthersForUser($auth->userId, $auth->sessionId);
                $this->sessions->updateCsrfToken($auth->sessionId, $this->csrf->generate());
                $this->audit->record('password_change', ['user_id' => $auth->userId], $request->ip);
            }

            return Response::json(UserPresenter::toPublic($user), 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }
}
