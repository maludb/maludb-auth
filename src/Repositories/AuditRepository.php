<?php
declare(strict_types=1);

namespace Maludb\Auth\Repositories;

use PDO;

/**
 * Data access for auth.audit_log_entries.
 *
 * The whole event is stored in the jsonb `payload` column as
 * json_encode(['action' => $action] + $payload) — the primary action is merged
 * first so a stray 'action' key inside $payload cannot override it. On read,
 * payload is json_decode(..., true)d back into a PHP array.
 */
final class AuditRepository
{
    public function __construct(private PDO $pdo) {}

    /**
     * @param array<string,mixed> $payload
     */
    public function record(string $action, array $payload, string $ip): void
    {
        // clock_timestamp() (not now()) so entries recorded within a single
        // transaction still get distinct, monotonically increasing timestamps —
        // now() is frozen at transaction start, which would make recent()'s
        // ordering non-deterministic for same-transaction inserts.
        $stmt = $this->pdo->prepare(
            'INSERT INTO auth.audit_log_entries (payload, ip_address, created_at)
             VALUES (:payload::jsonb, :ip, clock_timestamp())'
        );
        $stmt->execute([
            ':payload' => json_encode(['action' => $action] + $payload, JSON_THROW_ON_ERROR),
            ':ip' => $ip,
        ]);
    }

    /**
     * @return array<int,array<string,mixed>> Newest entries first; payload as arrays.
     */
    public function recent(int $limit): array
    {
        return $this->page(1, $limit);
    }

    /**
     * @return array<int,array<string,mixed>> Newest first, offset-paginated.
     */
    public function page(int $page, int $perPage): array
    {
        $perPage = max(1, min(1000, $perPage));
        $offset = (max(1, $page) - 1) * $perPage;

        $stmt = $this->pdo->prepare(
            'SELECT * FROM auth.audit_log_entries
             ORDER BY created_at DESC LIMIT :limit OFFSET :offset'
        );
        $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        return array_map(
            static function (array $row): array {
                if (isset($row['payload']) && is_string($row['payload'])) {
                    $row['payload'] = json_decode($row['payload'], true, 512, JSON_THROW_ON_ERROR);
                }
                return $row;
            },
            $stmt->fetchAll()
        );
    }
}
