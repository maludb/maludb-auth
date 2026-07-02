<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Support;

use Maludb\Auth\Support\EmailNormalizer;
use PHPUnit\Framework\TestCase;

final class EmailNormalizerTest extends TestCase
{
    public function test_lowercases_and_trims(): void
    {
        $this->assertSame('user@x.com', EmailNormalizer::normalize(' User@X.com '));
    }

    public function test_already_normalized_is_unchanged(): void
    {
        $this->assertSame('a@b.co', EmailNormalizer::normalize('a@b.co'));
    }

    public function test_trims_tabs_and_newlines(): void
    {
        $this->assertSame('foo@bar.com', EmailNormalizer::normalize("\tFOO@BAR.com\n"));
    }
}
