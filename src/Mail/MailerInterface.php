<?php
declare(strict_types=1);

namespace Maludb\Auth\Mail;

/**
 * Outbound mail boundary. Implementations must throw on delivery failure so
 * callers can decide whether the failure is user-visible; they must never
 * mutate or log full message bodies beyond their documented sink (bodies
 * contain live one-time codes).
 */
interface MailerInterface
{
    public function send(string $to, string $subject, string $text): void;
}
