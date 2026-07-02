<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Unit\Mail;

use Maludb\Auth\Mail\MailComposer;
use PHPUnit\Framework\TestCase;

final class MailComposerTest extends TestCase
{
    private function composer(): MailComposer
    {
        return new MailComposer('http://localhost:8080', 'http://localhost:3000');
    }

    public function test_recovery_mail_embeds_link_code_and_redirect(): void
    {
        $mail = $this->composer()->compose(
            'recovery',
            'user@example.com',
            '123456',
            str_repeat('a', 64),
            'http://localhost:3000/reset',
        );

        $this->assertNotSame('', $mail['subject']);
        $this->assertStringContainsString('123456', $mail['text']);
        $this->assertStringContainsString(
            'http://localhost:8080/auth/v1/verify?token_hash=' . str_repeat('a', 64)
            . '&type=recovery&redirect_to=' . rawurlencode('http://localhost:3000/reset'),
            $mail['text'],
        );
    }

    public function test_confirmation_uses_signup_verify_type(): void
    {
        $mail = $this->composer()->compose(
            'confirmation', 'user@example.com', '654321', str_repeat('b', 64), '',
        );
        $this->assertStringContainsString('&type=signup&', $mail['text']);
    }

    public function test_magiclink_and_invite_verify_types(): void
    {
        $c = $this->composer();
        $this->assertStringContainsString(
            '&type=magiclink&',
            $c->compose('magiclink', 'u@x.com', '111111', str_repeat('c', 64), '')['text'],
        );
        $this->assertStringContainsString(
            '&type=invite&',
            $c->compose('invite', 'u@x.com', '111111', str_repeat('d', 64), '')['text'],
        );
    }

    public function test_reauthentication_mail_has_code_but_no_link(): void
    {
        $mail = $this->composer()->compose(
            'reauthentication', 'user@example.com', '987654', str_repeat('e', 64), '',
        );
        $this->assertStringContainsString('987654', $mail['text']);
        $this->assertStringNotContainsString('/verify', $mail['text']);
        $this->assertStringNotContainsString(str_repeat('e', 64), $mail['text']);
    }

    public function test_unknown_type_throws(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->composer()->compose('nope', 'u@x.com', '1', 'h', '');
    }
}
