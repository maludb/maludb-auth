<?php
declare(strict_types=1);

namespace Maludb\Auth\Exceptions;

/**
 * Thrown when request input fails a syntactic/structural validation check
 * (missing field, malformed email). The message is safe to surface to the
 * caller as a 400 validation error.
 */
final class ValidationException extends \RuntimeException
{
}
