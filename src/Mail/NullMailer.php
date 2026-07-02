<?php
declare(strict_types=1);

namespace Maludb\Auth\Mail;

/** Drops all mail. For deployments that handle delivery out-of-band. */
final class NullMailer implements MailerInterface
{
    public function send(string $to, string $subject, string $text): void
    {
        // Intentionally nothing.
    }
}
