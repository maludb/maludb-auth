<?php
declare(strict_types=1);

namespace Maludb\Auth\Exceptions;

/**
 * Password login attempted on an account whose email is not yet confirmed
 * (only reachable when MAILER_AUTOCONFIRM is off). Thrown AFTER the credential
 * check passed, so a wrong password on an unconfirmed account still reads as
 * the generic invalid_grant.
 */
final class EmailNotConfirmedException extends \RuntimeException
{
}
