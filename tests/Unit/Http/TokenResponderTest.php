<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Http;

use Maludb\Auth\Dto\IssuedTokens;
use Maludb\Auth\Http\TokenResponder;
use PHPUnit\Framework\TestCase;

final class TokenResponderTest extends TestCase
{
    private const COOKIE_CFG = ['secure' => true, 'samesite' => 'Strict'];

    private function user(): array
    {
        return [
            'id' => 'user-1',
            'email' => 'a@example.com',
            'encrypted_password' => '$2y$10$SECRETHASH',
            'role' => 'authenticated',
        ];
    }

    private function tokens(?string $refresh = 'refresh-raw'): IssuedTokens
    {
        return new IssuedTokens(
            accessToken: 'access-jwt',
            refreshToken: $refresh,
            csrfToken: 'csrf-tok',
            sessionId: 'sess-1',
            expiresIn: 3600,
            user: $this->user(),
        );
    }

    /** @return array<string,string> name => value */
    private function cookieMap(array $cookies): array
    {
        $out = [];
        foreach ($cookies as $c) {
            $out[$c['name']] = $c;
        }
        return $out;
    }

    // --- Bearer mode -------------------------------------------------------

    public function test_bearer_body_has_tokens_and_no_cookies(): void
    {
        $res = (new TokenResponder())->respond($this->tokens(), false, self::COOKIE_CFG);
        $body = json_decode($res->body, true);

        $this->assertSame('access-jwt', $body['access_token']);
        $this->assertSame('bearer', $body['token_type']);
        $this->assertSame(3600, $body['expires_in']);
        $this->assertSame('refresh-raw', $body['refresh_token']);
        $this->assertArrayHasKey('user', $body);
        $this->assertCount(0, $res->cookies);
    }

    public function test_bearer_body_omits_encrypted_password(): void
    {
        $res = (new TokenResponder())->respond($this->tokens(), false, self::COOKIE_CFG);

        $this->assertStringNotContainsString('encrypted_password', $res->body);
        $this->assertStringNotContainsString('SECRETHASH', $res->body);

        $body = json_decode($res->body, true);
        $this->assertArrayNotHasKey('encrypted_password', $body['user']);
        $this->assertSame('a@example.com', $body['user']['email']);
    }

    public function test_bearer_omits_refresh_token_when_null(): void
    {
        $res = (new TokenResponder())->respond($this->tokens(null), false, self::COOKIE_CFG);
        $body = json_decode($res->body, true);

        $this->assertArrayNotHasKey('refresh_token', $body);
        $this->assertSame('access-jwt', $body['access_token']);
    }

    // --- Cookie mode -------------------------------------------------------

    public function test_cookie_body_has_user_and_csrf_no_tokens(): void
    {
        $res = (new TokenResponder())->respond($this->tokens(), true, self::COOKIE_CFG);
        $body = json_decode($res->body, true);

        $this->assertArrayHasKey('user', $body);
        $this->assertSame('csrf-tok', $body['csrf_token']);
        $this->assertArrayNotHasKey('access_token', $body);
        $this->assertArrayNotHasKey('refresh_token', $body);
    }

    public function test_cookie_mode_omits_encrypted_password(): void
    {
        $res = (new TokenResponder())->respond($this->tokens(), true, self::COOKIE_CFG);

        $this->assertStringNotContainsString('encrypted_password', $res->body);
        $this->assertStringNotContainsString('SECRETHASH', $res->body);
    }

    public function test_cookie_mode_sets_both_cookies_with_correct_flags_and_paths(): void
    {
        $res = (new TokenResponder())->respond($this->tokens(), true, self::COOKIE_CFG);
        $cookies = $this->cookieMap($res->cookies);

        $this->assertArrayHasKey(TokenResponder::ACCESS_COOKIE, $cookies);
        $this->assertArrayHasKey(TokenResponder::REFRESH_COOKIE, $cookies);

        $access = $cookies[TokenResponder::ACCESS_COOKIE];
        $this->assertSame('access-jwt', $access['value']);
        $this->assertSame('/', $access['options']['path']);
        $this->assertTrue($access['options']['httponly']);
        $this->assertTrue($access['options']['secure']);
        $this->assertSame('Strict', $access['options']['samesite']);

        $refresh = $cookies[TokenResponder::REFRESH_COOKIE];
        $this->assertSame('refresh-raw', $refresh['value']);
        $this->assertSame('/auth/v1/token', $refresh['options']['path']);
        $this->assertTrue($refresh['options']['httponly']);
        $this->assertTrue($refresh['options']['secure']);
    }

    public function test_cookie_mode_leaves_refresh_cookie_unset_when_null(): void
    {
        $res = (new TokenResponder())->respond($this->tokens(null), true, self::COOKIE_CFG);
        $cookies = $this->cookieMap($res->cookies);

        $this->assertArrayHasKey(TokenResponder::ACCESS_COOKIE, $cookies);
        $this->assertArrayNotHasKey(TokenResponder::REFRESH_COOKIE, $cookies);
    }

    public function test_public_user_helper_strips_sensitive_fields(): void
    {
        $clean = TokenResponder::publicUser($this->user());
        $this->assertArrayNotHasKey('encrypted_password', $clean);
        $this->assertSame('user-1', $clean['id']);
    }
}
