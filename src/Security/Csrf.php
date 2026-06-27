<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

final class Csrf
{
    public function generate(): string
    {
        return bin2hex(random_bytes(32)); // 64 hex chars
    }

    public function matches(string $expected, string $provided): bool
    {
        if ($expected === '' || $provided === '') {
            return false;
        }
        return hash_equals($expected, $provided);
    }
}
