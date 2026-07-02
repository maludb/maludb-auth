<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

use Maludb\Auth\Exceptions\DuplicateEmailException;
use Maludb\Auth\Exceptions\InvalidCredentialsException;
use Maludb\Auth\Exceptions\InvalidRefreshTokenException;
use Maludb\Auth\Exceptions\RefreshTokenReuseException;
use Maludb\Auth\Exceptions\SessionExpiredException;
use Maludb\Auth\Exceptions\SignupDisabledException;
use Maludb\Auth\Exceptions\UserBannedException;
use Maludb\Auth\Exceptions\ValidationException;

/**
 * Central exception-to-Response mapping shared by controllers (and App::handle).
 *
 * Two security properties are load-bearing here:
 *
 *  1. Credential/refresh failures collapse to a SINGLE generic `invalid_grant`
 *     response. An attacker cannot distinguish "no such user" from "wrong
 *     password" from "replayed/stolen refresh token" by the response.
 *
 *  2. Unexpected throwables NEVER leak their message or stack trace. The body is
 *     always a static `internal_error`; the real detail is logged server-side.
 *     This is the no-leak guarantee — a bug or SQL error must not surface DB
 *     structure, file paths, or secrets to the client.
 */
final class ErrorMapper
{
    public static function map(\Throwable $e): Response
    {
        return match (true) {
            $e instanceof ValidationException => Response::json([
                'error' => 'validation_failed',
                'error_description' => $e->getMessage(),
            ], 400),

            // Generic — deliberately indistinguishable across the three cases.
            $e instanceof InvalidCredentialsException,
            $e instanceof InvalidRefreshTokenException,
            $e instanceof RefreshTokenReuseException => Response::json([
                'error' => 'invalid_grant',
                'error_description' => 'Invalid login credentials',
            ], 400),

            $e instanceof UserBannedException => Response::json([
                'error' => 'user_banned',
            ], 403),

            $e instanceof SignupDisabledException => Response::json([
                'error' => 'signup_disabled',
            ], 422),

            $e instanceof SessionExpiredException => Response::json([
                'error' => 'session_expired',
            ], 401),

            // Password policy from Password::hash() throws \InvalidArgumentException.
            $e instanceof \InvalidArgumentException => Response::json([
                'error' => 'weak_password',
            ], 400),

            // Should be handled specially by callers (signup returns generic
            // success). If it reaches here, stay generic — no enumeration leak.
            $e instanceof DuplicateEmailException => Response::json([
                'error' => 'validation_failed',
                'error_description' => 'Unable to process request.',
            ], 400),

            // Anything unexpected: log server-side, return an opaque 500.
            default => self::internal($e),
        };
    }

    private static function internal(\Throwable $e): Response
    {
        error_log(sprintf(
            '[maludb-auth] unexpected %s: %s in %s:%d',
            $e::class,
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
        ));

        return Response::json(['error' => 'internal_error'], 500);
    }
}
