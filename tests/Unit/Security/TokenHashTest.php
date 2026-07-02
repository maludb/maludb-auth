<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Security;

use Maludb\Auth\Security\TokenHash;
use PHPUnit\Framework\TestCase;

final class TokenHashTest extends TestCase
{
    public function test_random_is_url_safe_and_unpadded(): void
    {
        $token = (new TokenHash())->random();
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $token);
        $this->assertStringNotContainsString('=', $token);
        $this->assertStringNotContainsString('+', $token);
        $this->assertStringNotContainsString('/', $token);
    }

    public function test_random_is_unique(): void
    {
        $th = new TokenHash();
        $this->assertNotSame($th->random(), $th->random());
    }

    public function test_random_byte_length_controls_output_length(): void
    {
        $th = new TokenHash();
        // 64 bytes base64url-encoded (unpadded) is longer than the 32-byte default.
        $this->assertGreaterThan(strlen($th->random(32)), strlen($th->random(64)));
    }

    public function test_otp_is_exactly_n_zero_padded_digits(): void
    {
        $th = new TokenHash();
        for ($i = 0; $i < 200; $i++) {
            $this->assertMatchesRegularExpression('/^[0-9]{6}$/', $th->otp());
        }
        $this->assertMatchesRegularExpression('/^[0-9]{8}$/', $th->otp(8));
    }

    public function test_otp_varies(): void
    {
        $th = new TokenHash();
        $seen = [];
        for ($i = 0; $i < 50; $i++) {
            $seen[$th->otp()] = true;
        }
        // 50 draws from a million-value space colliding down to 1 value is
        // impossible unless otp() is constant.
        $this->assertGreaterThan(1, count($seen));
    }

    public function test_hash_is_deterministic_sha256_hex(): void
    {
        $th = new TokenHash();
        $hash = $th->hash('some-opaque-token');
        $this->assertSame(64, strlen($hash));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
        $this->assertSame($hash, $th->hash('some-opaque-token'));
        $this->assertSame(hash('sha256', 'some-opaque-token'), $hash);
    }

    public function test_different_inputs_produce_different_hashes(): void
    {
        $th = new TokenHash();
        $this->assertNotSame($th->hash('a'), $th->hash('b'));
    }
}
