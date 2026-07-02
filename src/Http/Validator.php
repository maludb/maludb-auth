<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

use Maludb\Auth\Exceptions\ValidationException;

/**
 * Small, dependency-free request-input validators. Each throws a
 * ValidationException (mapped to a 400 by ErrorMapper) with a safe message.
 */
final class Validator
{
    /**
     * Normalize and validate an email address.
     *
     * @throws ValidationException when the value is not a syntactically valid email.
     */
    public static function email(mixed $email): string
    {
        if (!is_string($email)) {
            throw new ValidationException('A valid email is required.');
        }
        $normalized = strtolower(trim($email));
        if ($normalized === '' || filter_var($normalized, FILTER_VALIDATE_EMAIL) === false) {
            throw new ValidationException('A valid email is required.');
        }
        return $normalized;
    }

    /**
     * Assert that every named key is present and non-empty in the input map.
     *
     * @param array<string,mixed> $input
     * @param string[] $keys
     * @throws ValidationException when any key is missing or empty.
     */
    public static function requirePresent(array $input, array $keys): void
    {
        foreach ($keys as $key) {
            $value = $input[$key] ?? null;
            if ($value === null || $value === '') {
                throw new ValidationException("Missing required field: {$key}.");
            }
        }
    }
}
