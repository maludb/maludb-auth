<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Security;

use Maludb\Auth\Security\Jwt;
use PHPUnit\Framework\TestCase;

final class JwtTest extends TestCase
{
    /** @return array{0:string,1:string} */
    private function keys(): array
    {
        $res = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_pkey_export($res, $priv);
        $pub = openssl_pkey_get_details($res)['key'];
        return [$priv, $pub];
    }

    public function test_sign_and_verify_roundtrip(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');
        $token = $jwt->issue(['sub' => 'user-uuid', 'role' => 'authenticated'], 3600);
        $claims = $jwt->verify($token);
        $this->assertSame('user-uuid', $claims['sub']);
        $this->assertSame('authenticated', $claims['role']);
        $this->assertSame('iss', $claims['iss']);
        $this->assertSame('aud', $claims['aud']);
        $this->assertArrayHasKey('iat', $claims);
        $this->assertArrayHasKey('exp', $claims);
        $this->assertArrayHasKey('jti', $claims);
    }

    public function test_tampered_token_is_rejected(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');
        $token = $jwt->issue(['sub' => 'x'], 3600) . 'tamper';
        $this->expectException(\Firebase\JWT\SignatureInvalidException::class);
        $jwt->verify($token);
    }

    public function test_expired_token_is_rejected(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');
        $token = $jwt->issue(['sub' => 'x'], -100); // expired well beyond the leeway window
        $this->expectException(\Firebase\JWT\ExpiredException::class);
        $jwt->verify($token);
    }

    public function test_alg_none_token_is_rejected(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');

        $b64 = static fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $header = $b64('{"alg":"none","typ":"JWT"}');
        $payload = $b64(json_encode(['sub' => 'x', 'iss' => 'iss', 'aud' => 'aud']));
        $token = $header . '.' . $payload . '.'; // empty signature

        $this->expectException(\Exception::class);
        $jwt->verify($token);
    }

    public function test_hs256_token_signed_with_public_key_is_rejected(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');

        // Classic algorithm-confusion attack: forge an HS256 token using the
        // public key (known to everyone) as the HMAC secret. Pinning to RS256
        // must reject it.
        $token = \Firebase\JWT\JWT::encode(['sub' => 'x', 'iss' => 'iss', 'aud' => 'aud'], $pub, 'HS256');

        $this->expectException(\UnexpectedValueException::class);
        $jwt->verify($token);
    }

    public function test_wrong_issuer_is_rejected(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');

        $now = time();
        $token = \Firebase\JWT\JWT::encode(
            ['sub' => 'x', 'iss' => 'evil', 'aud' => 'aud', 'iat' => $now, 'exp' => $now + 3600],
            $priv,
            'RS256',
            'key-1',
        );

        $this->expectException(\Maludb\Auth\Exceptions\InvalidTokenException::class);
        $jwt->verify($token);
    }

    public function test_wrong_audience_is_rejected(): void
    {
        [$priv, $pub] = $this->keys();
        $jwt = new Jwt($priv, $pub, 'key-1', 'iss', 'aud');

        $now = time();
        $token = \Firebase\JWT\JWT::encode(
            ['sub' => 'x', 'iss' => 'iss', 'aud' => 'evil', 'iat' => $now, 'exp' => $now + 3600],
            $priv,
            'RS256',
            'key-1',
        );

        $this->expectException(\Maludb\Auth\Exceptions\InvalidTokenException::class);
        $jwt->verify($token);
    }
}
