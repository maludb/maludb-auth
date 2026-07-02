<?php
declare(strict_types=1);

namespace Maludb\Auth\Exceptions;

/**
 * A one-time token failed redemption. Deliberately covers ALL failure causes —
 * unknown, expired, consumed, wrong type, wrong email — so the response cannot
 * be used to distinguish them (ErrorMapper collapses this to a generic 401).
 */
final class InvalidOtpException extends \RuntimeException
{
}
