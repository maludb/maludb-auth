<?php
declare(strict_types=1);

namespace Maludb\Auth\Repositories;

use PDO;

/**
 * Data access for auth.refresh_tokens. Straightforward CRUD; all writes use
 * prepared statements. Token hashes are opaque strings (SHA-256 hex) produced
 * upstream — this repository never hashes.
 */
final class RefreshTokenRepository
{
    public function __construct(private PDO $pdo) {}

    /**
     * @return array<string,mixed> The issued token row (revoked = false).
     */
    public function issue(string $sessionId, string $userId, string $tokenHash, ?string $parent = null): array
    {
        $sql = <<<SQL
        INSERT INTO auth.refresh_tokens (session_id, user_id, token_hash, parent)
        VALUES (:session_id, :user_id, :token_hash, :parent)
        RETURNING *
        SQL;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':session_id' => $sessionId,
            ':user_id' => $userId,
            ':token_hash' => $tokenHash,
            ':parent' => $parent,
        ]);

        return $stmt->fetch();
    }

    /** @return array<string,mixed>|null */
    public function findByHash(string $hash): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM auth.refresh_tokens WHERE token_hash = :hash');
        $stmt->execute([':hash' => $hash]);
        $row = $stmt->fetch();

        return $row === false ? null : $row;
    }

    public function revoke(int $id): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE auth.refresh_tokens SET revoked = true, updated_at = now() WHERE id = :id'
        );
        $stmt->execute([':id' => $id]);
    }

    public function revokeAllForSession(string $sessionId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE auth.refresh_tokens SET revoked = true, updated_at = now()
             WHERE session_id = :session_id AND revoked = false'
        );
        $stmt->execute([':session_id' => $sessionId]);
    }

    /**
     * @return array<int,array<string,mixed>> Active (unrevoked) tokens for the session, oldest first.
     */
    public function findActiveBySession(string $sessionId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM auth.refresh_tokens
             WHERE session_id = :session_id AND revoked = false
             ORDER BY id ASC'
        );
        $stmt->execute([':session_id' => $sessionId]);

        return $stmt->fetchAll();
    }
}
