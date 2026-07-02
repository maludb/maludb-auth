<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

use PDO;

final class RateLimiter implements RateLimiterInterface
{
    public function __construct(private PDO $pdo) {}

    /**
     * Attempt to consume one token from the bucket identified by $key.
     *
     * Token-bucket algorithm executed as a single atomic Postgres upsert.
     * Returns true if the attempt is allowed (a token was available),
     * false if the bucket is exhausted.
     *
     * FAIL-CLOSED CONTRACT: this method performs a database write and will
     * throw \PDOException on any DB error (connection loss, timeout, etc.).
     * Callers MUST fail CLOSED on exception — i.e. deny the attempt / treat it
     * as rate-limited — and MUST NEVER fail open (allow) when this throws.
     * Letting an exception fall through to "allow" would disable rate limiting
     * exactly when the datastore is unhealthy. (Consumed by the Unit 11
     * middleware.)
     *
     * @throws \PDOException on database failure.
     */
    public function attempt(string $key, int $capacity, float $refillPerSecond): bool
    {
        // NOTE: the named placeholders are reused (:cap ×3, :refill ×2). This
        // relies on the PDO pgsql driver with ATTR_EMULATE_PREPARES=false, which
        // maps repeated named placeholders to a single bound value. A future
        // port to MySQL or another driver must give each occurrence a distinct
        // placeholder name (e.g. :cap1/:cap2/:cap3).
        //
        // tokens is floored at -1 via GREATEST to cap the "debt" a hammered key
        // can accumulate. Without this floor, sustained hammering drives tokens
        // arbitrarily negative, so a legitimate user stays blocked long past the
        // intended window (an amplified lockout DoS). Floored at -1, a quiet key
        // recovers to >= 0 within 1/refill seconds.
        $sql = <<<SQL
        INSERT INTO auth.rate_limits (bucket_key, tokens, updated_at)
        VALUES (:k, :cap - 1, now())
        ON CONFLICT (bucket_key) DO UPDATE SET
            tokens = GREATEST(
                -1,
                LEAST(:cap,
                    auth.rate_limits.tokens
                    + EXTRACT(EPOCH FROM (now() - auth.rate_limits.updated_at)) * :refill
                ) - 1
            ),
            updated_at = now()
        RETURNING tokens
        SQL;
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':k' => $key, ':cap' => $capacity, ':refill' => $refillPerSecond]);
        return ((float) $stmt->fetchColumn()) >= 0.0;
    }
}
