<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Http\UserPresenter;
use PHPUnit\Framework\TestCase;

final class UserPresenterTest extends TestCase
{
    private function fullRow(): array
    {
        return [
            'id' => 'uuid-1',
            'aud' => 'authenticated',
            'role' => 'authenticated',
            'email' => 'user@example.com',
            'encrypted_password' => '$2y$10$secretsecretsecret',
            'phone' => null,
            'email_confirmed_at' => '2026-01-01T00:00:00Z',
            'phone_confirmed_at' => null,
            'confirmed_at' => '2026-01-01T00:00:00Z',
            'last_sign_in_at' => null,
            'created_at' => '2026-01-01T00:00:00Z',
            'updated_at' => '2026-01-01T00:00:00Z',
            'banned_until' => null,
            'is_anonymous' => false,
            'is_super_admin' => true,
            'deleted_at' => null,
            'confirmation_token' => 'sekret-conf',
            'recovery_token' => 'sekret-rec',
            'raw_app_meta_data' => ['provider' => 'email'],
            'raw_user_meta_data' => ['name' => 'Ada'],
        ];
    }

    public function test_output_excludes_encrypted_password_and_all_tokens(): void
    {
        $public = UserPresenter::toPublic($this->fullRow());

        $this->assertArrayNotHasKey('encrypted_password', $public);
        $this->assertArrayNotHasKey('confirmation_token', $public);
        $this->assertArrayNotHasKey('recovery_token', $public);
        $this->assertArrayNotHasKey('is_super_admin', $public);
        $this->assertArrayNotHasKey('deleted_at', $public);
        // And nothing sensitive survived a JSON round-trip either.
        $this->assertStringNotContainsString('encrypted_password', json_encode($public));
        $this->assertStringNotContainsString('sekret', json_encode($public));
    }

    public function test_remaps_metadata_and_keeps_safe_fields(): void
    {
        $public = UserPresenter::toPublic($this->fullRow());

        $this->assertSame('uuid-1', $public['id']);
        $this->assertSame('user@example.com', $public['email']);
        $this->assertSame(['provider' => 'email'], $public['app_metadata']);
        $this->assertSame(['name' => 'Ada'], $public['user_metadata']);
        $this->assertArrayNotHasKey('raw_app_meta_data', $public);
        $this->assertArrayNotHasKey('raw_user_meta_data', $public);
    }

    public function test_missing_metadata_defaults_to_empty_arrays(): void
    {
        $public = UserPresenter::toPublic(['id' => 'x']);

        $this->assertSame([], $public['app_metadata']);
        $this->assertSame([], $public['user_metadata']);
        $this->assertFalse($public['is_anonymous']);
    }
}
