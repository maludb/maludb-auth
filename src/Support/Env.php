<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

use Dotenv\Dotenv;

final class Env
{
    public static function load(string $basePath): void
    {
        if (is_file($basePath . '/.env')) {
            Dotenv::createImmutable($basePath)->safeLoad();
        }
    }

    public static function get(string $key, ?string $default = null): ?string
    {
        $v = $_ENV[$key] ?? getenv($key);
        return $v === false ? $default : ($v ?? $default);
    }

    public static function bool(string $key, bool $default = false): bool
    {
        $v = self::get($key);
        return $v === null ? $default : in_array(strtolower($v), ['1','true','yes','on'], true);
    }

    public static function int(string $key, int $default = 0): int
    {
        $v = self::get($key);
        return $v === null ? $default : (int) $v;
    }
}
