<?php
declare(strict_types=1);

namespace Maludb\Auth\Mail;

/**
 * Writes mail to error_log. DEV ONLY: bodies contain live one-time codes, so
 * this driver must never be configured in production (the log becomes an
 * account-takeover oracle for anyone who can read it).
 */
final class LogMailer implements MailerInterface
{
    public function send(string $to, string $subject, string $text): void
    {
        error_log(sprintf("[maludb-auth mail] to=%s subject=%s\n%s", $to, $subject, $text));
    }
}
