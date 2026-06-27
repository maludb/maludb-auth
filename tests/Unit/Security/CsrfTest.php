<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Security;

use Maludb\Auth\Security\Csrf;
use PHPUnit\Framework\TestCase;

final class CsrfTest extends TestCase
{
    public function test_generate_returns_64_hex_chars(): void
    {
        $token = (new Csrf())->generate();
        $this->assertSame(64, strlen($token));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $token);
    }

    public function test_generate_is_unique(): void
    {
        $csrf = new Csrf();
        $this->assertNotSame($csrf->generate(), $csrf->generate());
    }

    public function test_matches_true_only_on_exact_match(): void
    {
        $csrf = new Csrf();
        $token = $csrf->generate();
        $this->assertTrue($csrf->matches($token, $token));
        $this->assertFalse($csrf->matches($token, $csrf->generate()));
    }

    public function test_empty_tokens_never_match(): void
    {
        $csrf = new Csrf();
        $token = $csrf->generate();
        $this->assertFalse($csrf->matches('', ''));
        $this->assertFalse($csrf->matches('', $token));
        $this->assertFalse($csrf->matches($token, ''));
    }
}
