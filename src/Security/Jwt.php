<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

use Firebase\JWT\JWT as FirebaseJwt;
use Firebase\JWT\Key;

final class Jwt
{
    public function __construct(
        private string $privateKeyPem,
        private string $publicKeyPem,
        private string $kid,
        private string $issuer,
        private string $audience,
    ) {}

    /** @param array<string,mixed> $claims */
    public function issue(array $claims, int $ttlSeconds): string
    {
        $now = time();
        $payload = array_merge([
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'iat' => $now,
            'exp' => $now + $ttlSeconds,
            'jti' => bin2hex(random_bytes(16)),
        ], $claims);
        return FirebaseJwt::encode($payload, $this->privateKeyPem, 'RS256', $this->kid);
    }

    /** @return array<string,mixed> */
    public function verify(string $token): array
    {
        $decoded = FirebaseJwt::decode($token, new Key($this->publicKeyPem, 'RS256'));
        return json_decode(json_encode($decoded), true);
    }
}
