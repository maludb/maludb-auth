<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\UserPresenter;
use Maludb\Auth\Http\Validator;
use Maludb\Auth\Repositories\AuditRepository;
use Maludb\Auth\Repositories\UserRepository;
use Maludb\Auth\Security\Password;

/**
 * /auth/v1/admin/users — service-role user CRUD.
 *
 * Access is gated by RequireAdmin (applied in the route wiring). Every response
 * runs through UserPresenter::toPublic so no admin response can leak
 * encrypted_password or other sensitive columns. All mutations are audited.
 */
final class AdminUsersController
{
    private const DEFAULT_PER_PAGE = 50;

    public function __construct(
        private UserRepository $users,
        private AuditRepository $audit,
        private Password $password,
    ) {}

    public function list(Request $request): Response
    {
        try {
            $page = max(1, (int) ($request->query('page') ?? 1));
            $perPage = (int) ($request->query('per_page') ?? self::DEFAULT_PER_PAGE);
            $perPage = max(1, min(1000, $perPage));

            $rows = $this->users->list($page, $perPage);

            return Response::json([
                'users' => array_map([UserPresenter::class, 'toPublic'], $rows),
                'page' => $page,
                'per_page' => $perPage,
            ], 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    public function create(Request $request): Response
    {
        try {
            $input = $request->allInput();
            Validator::requirePresent($input, ['email', 'password']);
            $email = Validator::email($input['email']);
            $hash = $this->password->hash((string) $input['password']);

            $emailConfirm = (bool) ($input['email_confirm'] ?? false);
            $userMeta = is_array($input['user_metadata'] ?? null) ? $input['user_metadata'] : [];

            $attrs = [
                'email' => $email,
                'encrypted_password' => $hash,
                'raw_app_meta_data' => ['provider' => 'email', 'providers' => ['email']],
                'raw_user_meta_data' => $userMeta,
            ];
            if (isset($input['phone'])) {
                $attrs['phone'] = (string) $input['phone'];
            }

            $user = $this->users->create($attrs);

            if ($emailConfirm) {
                $this->users->markEmailConfirmed($user['id']);
                $user = $this->users->findById($user['id']) ?? $user;
            }

            $this->audit->record('admin_user_created', ['user_id' => $user['id']], $request->ip);

            return Response::json(UserPresenter::toPublic($user), 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    /** @param array<string,string> $params */
    public function show(Request $request, array $params): Response
    {
        try {
            $user = $this->users->findById($params['id'] ?? '');
            if ($user === null) {
                return Response::json(['error' => 'user_not_found'], 404);
            }

            return Response::json(UserPresenter::toPublic($user), 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    /** @param array<string,string> $params */
    public function update(Request $request, array $params): Response
    {
        try {
            $id = $params['id'] ?? '';
            if ($this->users->findById($id) === null) {
                return Response::json(['error' => 'user_not_found'], 404);
            }

            $input = $request->allInput();
            $attrs = [];

            if (array_key_exists('email', $input)) {
                $attrs['email'] = Validator::email($input['email']);
            }
            if (array_key_exists('phone', $input)) {
                $attrs['phone'] = $input['phone'];
            }
            if (array_key_exists('user_metadata', $input) && is_array($input['user_metadata'])) {
                $attrs['raw_user_meta_data'] = $input['user_metadata'];
            }
            // Admins MAY set app_metadata (they are the server-controlled boundary).
            if (array_key_exists('app_metadata', $input) && is_array($input['app_metadata'])) {
                $attrs['raw_app_meta_data'] = $input['app_metadata'];
            }
            if (array_key_exists('password', $input) && $input['password'] !== null && $input['password'] !== '') {
                $attrs['encrypted_password'] = $this->password->hash((string) $input['password']);
            }
            if (array_key_exists('email_confirm', $input) && (bool) $input['email_confirm'] === true) {
                $this->users->markEmailConfirmed($id);
            }

            $user = $attrs === [] ? $this->users->findById($id) : $this->users->update($id, $attrs);

            $this->audit->record('admin_user_updated', ['user_id' => $id], $request->ip);

            return Response::json(UserPresenter::toPublic($user), 200);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    /** @param array<string,string> $params */
    public function delete(Request $request, array $params): Response
    {
        try {
            $id = $params['id'] ?? '';
            if ($this->users->findById($id) === null) {
                return Response::json(['error' => 'user_not_found'], 404);
            }

            $this->users->softDelete($id);
            $this->audit->record('admin_user_deleted', ['user_id' => $id], $request->ip);

            return new Response(status: 204);
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }
}
