<?php
declare(strict_types=1);

namespace Maludb\Auth\Security;

use PDO;

final class RateLimiter
{
    public function __construct(private PDO $pdo) {}

    public function attempt(string $key, int $capacity, float $refillPerSecond): bool
    {
        $sql = <<<SQL
        INSERT INTO auth.rate_limits (bucket_key, tokens, updated_at)
        VALUES (:k, :cap - 1, now())
        ON CONFLICT (bucket_key) DO UPDATE SET
            tokens = LEAST(:cap,
                auth.rate_limits.tokens
                + EXTRACT(EPOCH FROM (now() - auth.rate_limits.updated_at)) * :refill
            ) - 1,
            updated_at = now()
        RETURNING tokens
        SQL;
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':k' => $key, ':cap' => $capacity, ':refill' => $refillPerSecond]);
        return ((float) $stmt->fetchColumn()) >= 0.0;
    }
}
