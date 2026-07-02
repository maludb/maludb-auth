<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

/**
 * Turns a raw auth.users row into the public, response-safe user shape.
 *
 * This is an ALLOWLIST, not a denylist: only fields explicitly named here reach
 * a response body. Sensitive columns (encrypted_password, every *_token /
 * *_change column, is_super_admin, deleted_at, banned metadata beyond
 * banned_until) can therefore never leak by accident when the schema grows — a
 * new column is invisible to clients until it is deliberately added here.
 *
 * raw_app_meta_data / raw_user_meta_data are re-keyed to the client-facing
 * app_metadata / user_metadata names, matching the JWT claim shape.
 */
final class UserPresenter
{
    /**
     * @param array<string,mixed> $userRow A hydrated auth.users row.
     * @return array<string,mixed> Allowlisted, response-safe user fields.
     */
    public static function toPublic(array $userRow): array
    {
        return [
            'id' => $userRow['id'] ?? null,
            'aud' => $userRow['aud'] ?? null,
            'role' => $userRow['role'] ?? null,
            'email' => $userRow['email'] ?? null,
            'phone' => $userRow['phone'] ?? null,
            'email_confirmed_at' => $userRow['email_confirmed_at'] ?? null,
            'phone_confirmed_at' => $userRow['phone_confirmed_at'] ?? null,
            'confirmed_at' => $userRow['confirmed_at'] ?? null,
            'last_sign_in_at' => $userRow['last_sign_in_at'] ?? null,
            'created_at' => $userRow['created_at'] ?? null,
            'updated_at' => $userRow['updated_at'] ?? null,
            'banned_until' => $userRow['banned_until'] ?? null,
            'is_anonymous' => (bool) ($userRow['is_anonymous'] ?? false),
            'app_metadata' => $userRow['raw_app_meta_data'] ?? [],
            'user_metadata' => $userRow['raw_user_meta_data'] ?? [],
        ];
    }
}
