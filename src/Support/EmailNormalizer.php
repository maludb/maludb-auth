<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

final class EmailNormalizer
{
    public static function normalize(string $email): string
    {
        return strtolower(trim($email));
    }
}
