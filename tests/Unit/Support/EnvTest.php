<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Support;

use Maludb\Auth\Support\Env;
use PHPUnit\Framework\TestCase;

final class EnvTest extends TestCase
{
    /** @var string[] keys set during a test, cleared in tearDown */
    private array $keys = [];

    protected function tearDown(): void
    {
        foreach ($this->keys as $key) {
            unset($_ENV[$key]);
            putenv($key);
        }
        $this->keys = [];
    }

    private function set(string $key, string $value): void
    {
        $_ENV[$key] = $value;
        putenv("$key=$value");
        $this->keys[] = $key;
    }

    public function test_bool_parses_truthy_values(): void
    {
        $this->set('MB_TEST_BOOL', 'true');
        $this->assertTrue(Env::bool('MB_TEST_BOOL'));
    }

    public function test_bool_parses_falsy_values(): void
    {
        $this->set('MB_TEST_BOOL', 'false');
        $this->assertFalse(Env::bool('MB_TEST_BOOL'));
    }

    public function test_bool_returns_default_when_missing(): void
    {
        $this->assertTrue(Env::bool('MB_TEST_MISSING', true));
        $this->assertFalse(Env::bool('MB_TEST_MISSING', false));
    }

    public function test_int_parses_value(): void
    {
        $this->set('MB_TEST_INT', '3600');
        $this->assertSame(3600, Env::int('MB_TEST_INT'));
    }

    public function test_int_returns_default_when_missing(): void
    {
        $this->assertSame(42, Env::int('MB_TEST_MISSING', 42));
    }
}
