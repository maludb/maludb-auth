<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Exceptions\ValidationException;
use Maludb\Auth\Http\Validator;
use PHPUnit\Framework\TestCase;

final class ValidatorTest extends TestCase
{
    public function test_email_normalizes_and_returns(): void
    {
        $this->assertSame('user@example.com', Validator::email('  User@Example.COM '));
    }

    public function test_email_rejects_invalid(): void
    {
        $this->expectException(ValidationException::class);
        Validator::email('not-an-email');
    }

    public function test_email_rejects_non_string(): void
    {
        $this->expectException(ValidationException::class);
        Validator::email(null);
    }

    public function test_require_present_passes_when_all_present(): void
    {
        Validator::requirePresent(['email' => 'a@b.com', 'password' => 'x'], ['email', 'password']);
        $this->addToAssertionCount(1);
    }

    public function test_require_present_throws_on_missing(): void
    {
        $this->expectException(ValidationException::class);
        Validator::requirePresent(['email' => 'a@b.com'], ['email', 'password']);
    }

    public function test_require_present_throws_on_empty_string(): void
    {
        $this->expectException(ValidationException::class);
        Validator::requirePresent(['email' => ''], ['email']);
    }
}
