<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Security;

use Maludb\Auth\Security\Password;
use PHPUnit\Framework\TestCase;

final class PasswordTest extends TestCase
{
    public function test_hash_and_verify_roundtrip(): void
    {
        $p = new Password(minLength: 12);
        $hash = $p->hash('correct horse battery');
        $this->assertTrue($p->verify('correct horse battery', $hash));
        $this->assertFalse($p->verify('wrong', $hash));
    }

    public function test_rejects_short_password(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new Password(12))->hash('short');
    }

    public function test_rejects_over_72_bytes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new Password(12))->hash(str_repeat('a', 73));
    }

    public function test_needs_rehash_false_for_current_hash(): void
    {
        $p = new Password(12);
        $hash = $p->hash('correct horse battery');
        $this->assertFalse($p->needsRehash($hash));
    }

    public function test_dummy_hash_is_valid_bcrypt_at_default_cost_and_never_verifies(): void
    {
        $p = new Password(12);
        $dummy = $p->dummyHash();

        // (a) it is a real bcrypt hash
        $info = password_get_info($dummy);
        $this->assertSame('bcrypt', $info['algoName']);
        $this->assertStringStartsWith('$2y$', $dummy);

        // (b) cost matches PASSWORD_BCRYPT's default so timing equals real hashes
        $defaultCost = password_get_info(password_hash('x', PASSWORD_BCRYPT))['options']['cost'];
        $this->assertSame($defaultCost, $info['options']['cost']);

        // (c) it never verifies any input
        $this->assertFalse($p->verify('anything', $dummy));
    }
}
