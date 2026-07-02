<?php
declare(strict_types=1);

namespace Maludb\Auth\Repositories;

use Maludb\Auth\Support\EmailNormalizer;
use PDO;

/**
 * Data access for auth.identities.
 *
 * identity_data is a jsonb column: on write it is json_encode()d and bound with
 * an explicit ::jsonb cast; on read it is json_decode(..., true)d back into a PHP
 * array, mirroring UserRepository's handling of its jsonb columns.
 *
 * email is normalized (lowercase + trim) via EmailNormalizer to match the citext
 * column and the way UserRepository stores user emails.
 */
final class IdentityRepository
{
    public function __construct(private PDO $pdo) {}

    /**
     * @param array<string,mixed> $attrs Supported keys: user_id, provider,
     *   provider_id, identity_data (array), email.
     * @return array<string,mixed> The created row (identity_data as an array).
     */
    public function create(array $attrs): array
    {
        $email = isset($attrs['email']) && $attrs['email'] !== null
            ? EmailNormalizer::normalize((string) $attrs['email'])
            : null;
        $identityData = $attrs['identity_data'] ?? [];

        $sql = <<<SQL
        INSERT INTO auth.identities
            (user_id, provider, provider_id, identity_data, email)
        VALUES
            (:user_id, :provider, :provider_id, :identity_data::jsonb, :email)
        RETURNING *
        SQL;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':user_id' => $attrs['user_id'],
            ':provider' => $attrs['provider'],
            ':provider_id' => $attrs['provider_id'],
            ':identity_data' => json_encode($identityData, JSON_THROW_ON_ERROR),
            ':email' => $email,
        ]);

        return $this->hydrate($stmt->fetch());
    }

    /** @return array<int,array<string,mixed>> Identities for a user. */
    public function findByUserId(string $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM auth.identities WHERE user_id = :user_id ORDER BY created_at ASC'
        );
        $stmt->execute([':user_id' => $userId]);

        return array_map([$this, 'hydrate'], $stmt->fetchAll());
    }

    /**
     * Decode the identity_data jsonb column into a PHP array.
     *
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private function hydrate(array $row): array
    {
        if (isset($row['identity_data']) && is_string($row['identity_data'])) {
            $row['identity_data'] = json_decode($row['identity_data'], true, 512, JSON_THROW_ON_ERROR);
        }

        return $row;
    }
}
