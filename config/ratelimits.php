<?php
declare(strict_types=1);

/**
 * Rate-limit buckets by category → [capacity, refillPerSecond].
 *
 * Token-bucket semantics (see Security\RateLimiter): `capacity` is the burst
 * size (how many attempts back-to-back before the bucket empties) and
 * `refillPerSecond` is the steady-state allowance. A category's sustained rate
 * is roughly refillPerSecond * 3600 per hour once the initial burst is spent.
 *
 * Defaults are deliberately conservative for the sensitive credential flows and
 * looser for token refresh (a legitimately busy path). Tune per deployment.
 */
return [
    // POST /token grant_type=password — login attempts.
    'login'         => ['capacity' => 30, 'refillPerSecond' => 30 / 3600],   // ~30/hr

    // POST /token grant_type=refresh_token — silent session refresh.
    'token_refresh' => ['capacity' => 60, 'refillPerSecond' => 60 / 3600],   // ~60/hr

    // POST /signup — account creation.
    'signup'        => ['capacity' => 10, 'refillPerSecond' => 10 / 3600],   // ~10/hr

    // POST /recover — password-reset request.
    'recover'       => ['capacity' => 5,  'refillPerSecond' => 5 / 3600],    // ~5/hr

    // POST /verify — email/phone verification.
    'verify'        => ['capacity' => 30, 'refillPerSecond' => 30 / 3600],   // ~30/hr

    // POST /otp, /magiclink — one-time-password / magic-link request.
    'otp'           => ['capacity' => 10, 'refillPerSecond' => 10 / 3600],   // ~10/hr

    // POST /resend — re-send confirmation/OTP mail.
    'resend'        => ['capacity' => 10, 'refillPerSecond' => 10 / 3600],   // ~10/hr
];
