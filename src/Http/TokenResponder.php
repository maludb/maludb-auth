<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

use Maludb\Auth\Dto\IssuedTokens;

/**
 * Centralizes dual-mode (Bearer vs cookie) delivery of an issued session so every
 * controller shapes token responses identically.
 *
 * Bearer mode (default): tokens live in the JSON body, no Set-Cookie.
 * Cookie mode (`?cookie=true`): tokens live in httpOnly cookies; the body carries
 * only the user and the CSRF token the client echoes back on unsafe requests.
 *
 * In BOTH modes the user object is passed through publicUser() so sensitive
 * columns (encrypted_password et al.) never reach a response body.
 */
final class TokenResponder
{
    public const ACCESS_COOKIE = 'mb-access-token';
    public const REFRESH_COOKIE = 'mb-refresh-token';
    public const REFRESH_COOKIE_PATH = '/auth/v1/token';

    /**
     * @param array{secure?:bool,samesite?:string} $cookieCfg
     */
    public function respond(IssuedTokens $t, bool $wantsCookies, array $cookieCfg): Response
    {
        $user = self::publicUser($t->user);

        return $wantsCookies
            ? $this->cookieResponse($t, $user, $cookieCfg)
            : $this->bearerResponse($t, $user);
    }

    /**
     * Reduce a user row to the allowlisted, response-safe public shape.
     *
     * Delegates to UserPresenter::toPublic() so the allowlist lives in one place
     * (closing the earlier denylist gap: a new sensitive column can no longer
     * slip into a response body just because it wasn't explicitly denied).
     *
     * @param array<string,mixed> $user
     * @return array<string,mixed>
     */
    public static function publicUser(array $user): array
    {
        return UserPresenter::toPublic($user);
    }

    /** @param array<string,mixed> $user */
    private function bearerResponse(IssuedTokens $t, array $user): Response
    {
        $body = [
            'access_token' => $t->accessToken,
            'token_type' => 'bearer',
            'expires_in' => $t->expiresIn,
        ];
        // Omit refresh_token entirely on the grace / CAS-lost path (null).
        if ($t->refreshToken !== null) {
            $body['refresh_token'] = $t->refreshToken;
        }
        $body['user'] = $user;

        return Response::json($body);
    }

    /**
     * @param array<string,mixed> $user
     * @param array{secure?:bool,samesite?:string} $cookieCfg
     */
    private function cookieResponse(IssuedTokens $t, array $user, array $cookieCfg): Response
    {
        $secure = (bool) ($cookieCfg['secure'] ?? false);
        $samesite = (string) ($cookieCfg['samesite'] ?? 'Lax');

        $res = Response::json([
            'user' => $user,
            'csrf_token' => $t->csrfToken,
        ]);

        $res->withCookie(self::ACCESS_COOKIE, $t->accessToken, [
            'httponly' => true,
            'path' => '/',
            'secure' => $secure,
            'samesite' => $samesite,
        ]);

        // Only (re)set the refresh cookie when a fresh refresh token was minted.
        // On the grace / CAS-lost path ($t->refreshToken === null) we leave the
        // client's existing refresh cookie untouched rather than clobbering it.
        if ($t->refreshToken !== null) {
            $res->withCookie(self::REFRESH_COOKIE, $t->refreshToken, [
                'httponly' => true,
                'path' => self::REFRESH_COOKIE_PATH,
                'secure' => $secure,
                'samesite' => $samesite,
            ]);
        }

        return $res;
    }
}
