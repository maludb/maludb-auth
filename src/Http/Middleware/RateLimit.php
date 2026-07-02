<?php
declare(strict_types=1);

namespace Maludb\Auth\Http\Middleware;

use Maludb\Auth\Http\{Request, Response};
use Maludb\Auth\Security\RateLimiterInterface;
use Maludb\Auth\Support\EmailNormalizer;
use Throwable;

/**
 * Token-bucket rate limiting keyed by request category + client identifier.
 *
 * A request is matched to a category (login, signup, refresh, …) from its
 * method/path/grant_type. Every matched category is enforced against the client
 * IP and, when the body carries an email, ALSO against that normalized email —
 * blocking on EITHER bucket. Unmatched requests pass through unthrottled.
 *
 * FAIL-CLOSED: RateLimiter::attempt() performs a DB write and throws on failure.
 * A throw here means we cannot prove the request is under the limit, so we DENY
 * it (503). We never let a request through when the limiter errored — that would
 * disable rate limiting exactly when the datastore is unhealthy.
 *
 * Place this middleware BEFORE AuthContext in the chain.
 */
final class RateLimit implements MiddlewareInterface
{
    /**
     * @param array<string,array{capacity:int,refillPerSecond:float}> $limits
     */
    public function __construct(
        private RateLimiterInterface $limiter,
        private array $limits,
    ) {}

    public function handle(Request $request, callable $next): Response
    {
        $category = $this->categorize($request);
        if ($category === null || !isset($this->limits[$category])) {
            return $next($request);
        }

        $cfg = $this->limits[$category];
        $capacity = (int) $cfg['capacity'];
        $refill = (float) $cfg['refillPerSecond'];

        // Build every bucket key that applies to this request.
        $keys = ["{$category}:ip:{$request->ip}"];
        $email = $request->input('email');
        if (is_string($email) && trim($email) !== '') {
            $normalized = EmailNormalizer::normalize($email);
            $keys[] = "{$category}:email:{$normalized}";
        }

        foreach ($keys as $key) {
            try {
                $allowed = $this->limiter->attempt($key, $capacity, $refill);
            } catch (Throwable) {
                // FAIL CLOSED: limiter/datastore error => deny, never fall through.
                return Response::error('over_rate_limit', 'Rate limiting unavailable.', 503)
                    ->withHeader('Retry-After', '60');
            }

            if (!$allowed) {
                return Response::error('over_rate_limit', 'Rate limit exceeded.', 429)
                    ->withHeader('Retry-After', $this->retryAfter($refill));
            }
        }

        return $next($request);
    }

    private function categorize(Request $request): ?string
    {
        $path = $request->path;

        if (!$request->isUnsafeMethod()) {
            // GET /verify redeems emailed tokens (link clicks), so it must be
            // throttled even though the method is "safe" — a 6-digit code space
            // is brute-forceable through any unthrottled redemption path.
            return ($request->method === 'GET' && $this->pathEndsWith($path, '/verify'))
                ? 'verify'
                : null;
        }

        if ($this->pathEndsWith($path, '/token')) {
            // Query is canonical per the design; the JSON body is a defensive
            // fallback so the login limiter can't disappear if a client sends
            // grant_type in the body instead.
            $grant = $request->query('grant_type');
            if ($grant === null || $grant === '') {
                $bodyGrant = $request->input('grant_type');
                $grant = is_string($bodyGrant) ? $bodyGrant : null;
            }
            return match ($grant) {
                'password' => 'login',
                'refresh_token' => 'token_refresh',
                default => null,
            };
        }

        return match (true) {
            $this->pathEndsWith($path, '/signup')    => 'signup',
            $this->pathEndsWith($path, '/recover')   => 'recover',
            $this->pathEndsWith($path, '/verify')    => 'verify',
            $this->pathEndsWith($path, '/otp'),
            $this->pathEndsWith($path, '/magiclink') => 'otp',
            $this->pathEndsWith($path, '/resend')    => 'resend',
            default => null,
        };
    }

    private function pathEndsWith(string $path, string $suffix): bool
    {
        return $path === $suffix || str_ends_with($path, $suffix);
    }

    /** Whole seconds until one token refills, floored at 1. */
    private function retryAfter(float $refillPerSecond): string
    {
        if ($refillPerSecond <= 0.0) {
            return '3600';
        }
        return (string) max(1, (int) ceil(1.0 / $refillPerSecond));
    }
}
