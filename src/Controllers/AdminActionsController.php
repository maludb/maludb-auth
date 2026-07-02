<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Exceptions\ValidationException;
use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\UserPresenter;
use Maludb\Auth\Http\Validator;
use Maludb\Auth\Mail\MailComposer;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Services\OtpService;
use Maludb\Auth\Support\EmailNormalizer;

/**
 * Service-role-only actions beyond user CRUD: invitations, admin-minted action
 * links, and the audit log. Gated by RequireAdmin in the route wiring — these
 * endpoints deliberately DO disclose account state (409 on a taken email),
 * which is fine for a trusted server-side caller and never exposed publicly.
 *
 * generate_link returns the live OTP + action link to the ADMIN (that is its
 * purpose — the caller delivers it out-of-band); it must never be reachable
 * without the service role.
 */
final class AdminActionsController
{
    /** generate_link `type` → [token_type, verify type in the link]. */
    private const LINK_TYPES = [
        'signup' => ['confirmation', 'signup'],
        'invite' => ['invite', 'invite'],
        'recovery' => ['recovery', 'recovery'],
        'magiclink' => ['magiclink', 'magiclink'],
    ];

    public function __construct(
        private UserRepository $users,
        private OtpService $otp,
        private MailComposer $composer,
        private AuditRepository $audit,
    ) {}

    /** POST /auth/v1/admin/invite — create (or reuse pending) user + send invite mail. */
    public function invite(Request $request): Response
    {
        try {
            $email = Validator::email($request->input('email'));
            $data = is_array($request->input('data')) ? $request->input('data') : [];
            $redirectTo = $this->str($request->input('redirect_to'));

            $user = $this->resolveInvitee($email, $data);
            if ($user === null) {
                return Response::error('email_exists', 'A user with this email address has already been registered.', 409);
            }

            $this->otp->send('invite', $email, $request->ip, createUser: false, redirectTo: $redirectTo);
            $this->audit->record('user_invited', ['user_id' => $user['id']], $request->ip);

            return Response::json(UserPresenter::toPublic($user), 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    /** POST /auth/v1/admin/generate_link — mint a token WITHOUT sending mail. */
    public function generateLink(Request $request): Response
    {
        try {
            $type = $request->input('type');
            if (!is_string($type) || !isset(self::LINK_TYPES[$type])) {
                throw new ValidationException('A valid type is required (signup, invite, recovery, magiclink).');
            }
            [$tokenType, $verifyType] = self::LINK_TYPES[$type];
            $email = Validator::email($request->input('email'));
            $redirectTo = $this->str($request->input('redirect_to'));

            $user = $this->users->findByEmail($email);
            if ($user === null) {
                if ($type !== 'invite') {
                    return Response::error('user_not_found', 'User with this email not found.', 404);
                }
                $user = $this->otp->createPasswordlessUser(EmailNormalizer::normalize($email));
            }

            $minted = $this->otp->mint($user, $tokenType);
            $this->audit->record('link_generated', ['user_id' => $user['id'], 'link_type' => $type], $request->ip);

            return Response::json([
                'action_link' => $this->composer->actionLink($verifyType, $minted['hash'], $redirectTo),
                'email_otp' => $minted['token'],
                'hashed_token' => $minted['hash'],
                'verification_type' => $type,
                'user' => UserPresenter::toPublic($user),
            ], 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    /** GET /auth/v1/admin/audit — newest-first audit entries, paginated. */
    public function auditLog(Request $request): Response
    {
        try {
            $page = max(1, (int) ($request->query('page') ?? '1'));
            $perPage = max(1, min(100, (int) ($request->query('per_page') ?? '50')));

            return Response::json([
                'entries' => $this->audit->page($page, $perPage),
                'page' => $page,
                'per_page' => $perPage,
            ], 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    /**
     * The user an invite may target: a fresh passwordless account, or an
     * existing never-confirmed one (re-invite). Confirmed accounts → null (409).
     *
     * @param array<string,mixed> $data
     * @return array<string,mixed>|null
     */
    private function resolveInvitee(string $email, array $data): ?array
    {
        $existing = $this->users->findByEmail($email);
        if ($existing !== null) {
            return ($existing['email_confirmed_at'] ?? null) === null ? $existing : null;
        }

        return $this->otp->createPasswordlessUser(EmailNormalizer::normalize($email), $data);
    }

    private function str(mixed $v): string
    {
        return is_string($v) ? $v : '';
    }
}
