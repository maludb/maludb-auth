<?php
declare(strict_types=1);

namespace Maludb\Auth\Mail;

/**
 * Builds the subject/body for each one-time-token mail. Every mail carries the
 * 6-digit code; link-redeemable types also carry a GET /verify URL holding the
 * token HASH (the stored value — possession of the link is possession of the
 * token, but the DB never holds anything redeemable in plaintext).
 * reauthentication is code-only: it is consumed by PUT /user, not /verify.
 */
final class MailComposer
{
    /** token_type => [verify ?type= value, subject, intro line] */
    private const TYPES = [
        'confirmation' => ['signup', 'Confirm your email', 'Confirm your email address'],
        'recovery' => ['recovery', 'Reset your password', 'Reset your password'],
        'magiclink' => ['magiclink', 'Your login link', 'Log in to your account'],
        'invite' => ['invite', 'You have been invited', 'Accept your invitation'],
        'reauthentication' => [null, 'Confirm it\'s you', 'Confirm this change'],
    ];

    public function __construct(
        private string $appUrl,
        private ?string $siteUrl,
    ) {}

    /**
     * @return array{subject:string,text:string}
     */
    public function compose(
        string $type,
        string $email,
        string $otp,
        string $tokenHash,
        string $redirectTo,
    ): array {
        if (!isset(self::TYPES[$type])) {
            throw new \InvalidArgumentException("Unknown mail type: {$type}");
        }
        [$verifyType, $subject, $intro] = self::TYPES[$type];

        $lines = ["{$intro} for {$email}.", ''];
        if ($verifyType !== null) {
            $lines[] = 'Follow this link:';
            $lines[] = $this->actionLink($verifyType, $tokenHash, $redirectTo);
            $lines[] = '';
            $lines[] = "Or enter this code: {$otp}";
        } else {
            $lines[] = "Enter this code: {$otp}";
        }
        $lines[] = '';
        $lines[] = 'If you did not request this, you can safely ignore this email.';

        return ['subject' => $subject, 'text' => implode("\n", $lines)];
    }

    /** The GET /verify URL for link-based redemption (Supabase "action link"). */
    public function actionLink(string $verifyType, string $tokenHash, string $redirectTo): string
    {
        $redirect = $redirectTo !== '' ? $redirectTo : (string) $this->siteUrl;

        return rtrim($this->appUrl, '/')
            . '/auth/v1/verify?token_hash=' . rawurlencode($tokenHash)
            . '&type=' . rawurlencode($verifyType)
            . '&redirect_to=' . rawurlencode($redirect);
    }
}
