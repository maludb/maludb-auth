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

    /** Crypto-random numeric OTP, zero-padded to exactly $digits characters. */
    public function otp(int $digits = 6): string
    {
        $max = (10 ** $digits) - 1;

        return str_pad((string) random_int(0, $max), $digits, '0', STR_PAD_LEFT);
    }
}
