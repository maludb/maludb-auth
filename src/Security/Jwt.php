<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

use Firebase\JWT\JWT as FirebaseJwt;
use Firebase\JWT\Key;
use Maludb\Auth\Exceptions\InvalidTokenException;

final class Jwt
{
    public function __construct(
        private string $privateKeyPem,
        private string $publicKeyPem,
        private string $kid,
        private string $issuer,
        private string $audience,
        private int $leeway = 30,
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

    /**
     * Complete token validator: everything downstream trusts the result.
     * firebase/php-jwt verifies the RS256 signature + exp/nbf/iat (with leeway)
     * but does NOT check issuer/audience, so we enforce those ourselves.
     *
     * @return array<string,mixed>
     */
    public function verify(string $token): array
    {
        // Tolerate minor clock drift across hosts on exp/nbf/iat checks.
        FirebaseJwt::$leeway = $this->leeway;

        $decoded = FirebaseJwt::decode($token, new Key($this->publicKeyPem, 'RS256'));
        $claims = json_decode(json_encode($decoded), true);

        if (!is_array($claims)) {
            throw new InvalidTokenException('Decoded token claims are not an array.');
        }
        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new InvalidTokenException('Token issuer mismatch.');
        }
        if (($claims['aud'] ?? null) !== $this->audience) {
            throw new InvalidTokenException('Token audience mismatch.');
        }

        return $claims;
    }
}
