<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Exceptions\DuplicateEmailException;
use Maludb\Auth\Exceptions\InvalidCredentialsException;
use Maludb\Auth\Exceptions\InvalidRefreshTokenException;
use Maludb\Auth\Exceptions\RefreshTokenReuseException;
use Maludb\Auth\Exceptions\SessionExpiredException;
use Maludb\Auth\Exceptions\SignupDisabledException;
use Maludb\Auth\Exceptions\UserBannedException;
use Maludb\Auth\Exceptions\ValidationException;
use Maludb\Auth\Http\ErrorMapper;
use PHPUnit\Framework\TestCase;

final class ErrorMapperTest extends TestCase
{
    public function test_validation_exception_maps_to_400(): void
    {
        $res = ErrorMapper::map(new ValidationException('bad email'));
        $this->assertSame(400, $res->status);
        $body = json_decode($res->body, true);
        $this->assertSame('validation_failed', $body['error']);
    }

    public function test_credential_and_refresh_errors_collapse_to_generic_invalid_grant(): void
    {
        foreach ([
            new InvalidCredentialsException('x'),
            new InvalidRefreshTokenException('x'),
            new RefreshTokenReuseException('x'),
        ] as $e) {
            $res = ErrorMapper::map($e);
            $this->assertSame(400, $res->status);
            $body = json_decode($res->body, true);
            $this->assertSame('invalid_grant', $body['error']);
            $this->assertSame('Invalid login credentials', $body['error_description']);
        }
    }

    public function test_banned_maps_to_403_generic(): void
    {
        $res = ErrorMapper::map(new UserBannedException('banned'));
        $this->assertSame(403, $res->status);
        $this->assertSame('user_banned', json_decode($res->body, true)['error']);
    }

    public function test_signup_disabled_maps_to_422(): void
    {
        $res = ErrorMapper::map(new SignupDisabledException('off'));
        $this->assertSame(422, $res->status);
        $this->assertSame('signup_disabled', json_decode($res->body, true)['error']);
    }

    public function test_session_expired_maps_to_401(): void
    {
        $res = ErrorMapper::map(new SessionExpiredException('gone'));
        $this->assertSame(401, $res->status);
        $this->assertSame('session_expired', json_decode($res->body, true)['error']);
    }

    public function test_weak_password_maps_to_400(): void
    {
        $res = ErrorMapper::map(new \InvalidArgumentException('Password too short.'));
        $this->assertSame(400, $res->status);
        $this->assertSame('weak_password', json_decode($res->body, true)['error']);
    }

    public function test_duplicate_email_stays_generic(): void
    {
        $res = ErrorMapper::map(new DuplicateEmailException('Email already registered.'));
        $this->assertSame(400, $res->status);
        $this->assertStringNotContainsString('already registered', $res->body);
    }

    public function test_unexpected_error_never_leaks_message_or_trace(): void
    {
        $secret = 'SECRET-DB-PATH-/var/lib/pg/passwords';
        $res = ErrorMapper::map(new \RuntimeException($secret));

        $this->assertSame(500, $res->status);
        $this->assertSame('internal_error', json_decode($res->body, true)['error']);
        $this->assertStringNotContainsString($secret, $res->body);
        $this->assertStringNotContainsString('RuntimeException', $res->body);
    }
}
