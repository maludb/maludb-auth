<?php
declare(strict_types=1);

namespace Maludb\Auth\Repositories;

use PDO;

/**
 * Data access for auth.one_time_tokens (emailed OTP codes / verify links).
 *
 * Tokens are stored HASHED (sha256 hex) — plaintext codes never touch the DB.
 * replace() upholds the single-live-token invariant: minting a new token for a
 * (user, type) pair deletes the previous one in the same statement flow, so an
 * older emailed code can never race a newer one.
 */
final class OneTimeTokenRepository
{
    public function __construct(private PDO $pdo) {}

    /**
     * Delete any existing token for (user, type), then insert the new one.
     *
     * @return array<string,mixed> The inserted row.
     */
    public function replace(string $userId, string $type, string $tokenHash, string $relatesTo): array
    {
        $this->deleteAllFor($userId, $type);

        $stmt = $this->pdo->prepare(
            'INSERT INTO auth.one_time_tokens (user_id, token_type, token_hash, relates_to)
             VALUES (:user_id, :type, :hash, :relates_to)
             RETURNING *'
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':type' => $type,
            ':hash' => $tokenHash,
            ':relates_to' => $relatesTo,
        ]);

        return $stmt->fetch();
    }

    /** @return array<string,mixed>|null */
    public function findByHash(string $tokenHash): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM auth.one_time_tokens WHERE token_hash = :hash'
        );
        $stmt->execute([':hash' => $tokenHash]);
        $row = $stmt->fetch();

        return $row === false ? null : $row;
    }

    /** @return array<string,mixed>|null */
    public function findForUser(string $userId, string $type): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM auth.one_time_tokens WHERE user_id = :user_id AND token_type = :type'
        );
        $stmt->execute([':user_id' => $userId, ':type' => $type]);
        $row = $stmt->fetch();

        return $row === false ? null : $row;
    }

    public function delete(string $id): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM auth.one_time_tokens WHERE id = :id');
        $stmt->execute([':id' => $id]);
    }

    public function deleteAllFor(string $userId, string $type): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM auth.one_time_tokens WHERE user_id = :user_id AND token_type = :type'
        );
        $stmt->execute([':user_id' => $userId, ':type' => $type]);
    }
}
