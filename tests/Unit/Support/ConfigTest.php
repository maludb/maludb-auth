<?php
namespace Maludb\Auth\Tests\Unit\Support;

use Maludb\Auth\Support\Config;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function test_get_returns_value_with_dot_notation(): void
    {
        $c = new Config(['jwt' => ['exp' => 3600]]);
        $this->assertSame(3600, $c->get('jwt.exp'));
    }

    public function test_get_returns_default_when_missing(): void
    {
        $c = new Config([]);
        $this->assertSame('fallback', $c->get('nope.here', 'fallback'));
    }
}
