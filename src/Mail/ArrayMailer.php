<?php
declare(strict_types=1);

namespace Maludb\Auth\Mail;

/**
 * In-memory capture for tests. Never selectable via MAILER_DRIVER — test code
 * constructs and injects it directly.
 */
final class ArrayMailer implements MailerInterface
{
    /** @var array<int,array{to:string,subject:string,text:string}> */
    public array $sent = [];

    public function send(string $to, string $subject, string $text): void
    {
        $this->sent[] = ['to' => $to, 'subject' => $subject, 'text' => $text];
    }

    /** @return array{to:string,subject:string,text:string}|null */
    public function last(): ?array
    {
        return $this->sent === [] ? null : $this->sent[array_key_last($this->sent)];
    }
}
