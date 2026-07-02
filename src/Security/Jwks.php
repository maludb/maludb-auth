<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

use RuntimeException;

/**
 * Builds a JSON Web Key Set (JWKS) from the service's RSA public key.
 *
 * The public modulus (`n`) and exponent (`e`) are extracted from the PEM via
 * openssl and encoded as base64url (no padding) per RFC 7517 / RFC 7518.
 */
final class Jwks
{
    public function __construct(
        private string $publicKeyPath,
        private string $kid,
    ) {}

    /** @return array{keys: array<int, array<string, string>>} */
    public function keySet(): array
    {
        return ['keys' => [$this->jwk()]];
    }

    /** @return array<string, string> */
    private function jwk(): array
    {
        $pem = @file_get_contents($this->publicKeyPath);
        if ($pem === false) {
            throw new RuntimeException("Unable to read public key: {$this->publicKeyPath}");
        }

        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new RuntimeException('Invalid RSA public key.');
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new RuntimeException('Public key is not an RSA key.');
        }

        return [
            'kty' => 'RSA',
            'kid' => $this->kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => self::base64url($details['rsa']['n']),
            'e'   => self::base64url($details['rsa']['e']),
        ];
    }

    private static function base64url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
