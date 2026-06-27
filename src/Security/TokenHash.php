<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

final class TokenHash
{
    public function random(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    public function hash(string $token): string
    {
        return hash('sha256', $token); // store this; compare incoming by re-hashing
    }
}
