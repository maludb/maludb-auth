<?php
declare(strict_types=1);

namespace Maludb\Auth\Repositories;

use PDO;

/**
 * Data access for auth.sessions. Straightforward CRUD; all writes use prepared
 * statements and rely on Postgres now() for timestamps.
 */
final class SessionRepository
{
    public function __construct(private PDO $pdo) {}

    /**
     * @return array<string,mixed> The created session row (aal defaults to 'aal1').
     */
    public function create(
        string $userId,
        string $csrfToken,
        ?string $ip,
        ?string $userAgent,
        ?string $notAfter,
    ): array {
        $sql = <<<SQL
        INSERT INTO auth.sessions (user_id, csrf_token, ip, user_agent, not_after)
        VALUES (:user_id, :csrf_token, :ip, :user_agent, :not_after)
        RETURNING *
        SQL;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':user_id' => $userId,
            ':csrf_token' => $csrfToken,
            ':ip' => $ip,
            ':user_agent' => $userAgent,
            ':not_after' => $notAfter,
        ]);

        return $stmt->fetch();
    }

    /** @return array<string,mixed>|null */
    public function find(string $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM auth.sessions WHERE id = :id');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();

        return $row === false ? null : $row;
    }

    public function touchRefreshedAt(string $id): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE auth.sessions SET refreshed_at = now(), updated_at = now() WHERE id = :id'
        );
        $stmt->execute([':id' => $id]);
    }

    public function updateCsrfToken(string $id, string $newCsrfToken): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE auth.sessions SET csrf_token = :csrf, updated_at = now() WHERE id = :id'
        );
        $stmt->execute([':csrf' => $newCsrfToken, ':id' => $id]);
    }

    public function updateAal(string $id, string $aal, ?string $factorId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE auth.sessions SET aal = :aal, factor_id = :factor_id, updated_at = now()
             WHERE id = :id'
        );
        $stmt->execute([':aal' => $aal, ':factor_id' => $factorId, ':id' => $id]);
    }

    public function delete(string $id): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM auth.sessions WHERE id = :id');
        $stmt->execute([':id' => $id]);
    }

    public function deleteAllForUser(string $userId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM auth.sessions WHERE user_id = :user_id');
        $stmt->execute([':user_id' => $userId]);
    }

    public function deleteOthersForUser(string $userId, string $keepId): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM auth.sessions WHERE user_id = :user_id AND id <> :keep_id'
        );
        $stmt->execute([':user_id' => $userId, ':keep_id' => $keepId]);
    }
}
