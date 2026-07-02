<?php
declare(strict_types=1);

namespace Maludb\Auth\Repositories;

use Maludb\Auth\Exceptions\DuplicateEmailException;
use Maludb\Auth\Support\EmailNormalizer;
use PDO;
use PDOException;

/**
 * Data access for auth.users.
 *
 * JSON columns: raw_app_meta_data and raw_user_meta_data are jsonb. On write
 * they are json_encode()d and bound with an explicit ::jsonb cast; on read they
 * are json_decode(..., true)d back into PHP arrays. Callers therefore always
 * work with arrays, never JSON strings.
 *
 * Email is always normalized (lowercase + trim) via EmailNormalizer before any
 * insert, update, or lookup, matching the citext column + partial unique index
 * (users_email_unique WHERE deleted_at IS NULL).
 *
 * confirmed_at is a GENERATED ALWAYS column and is never written here.
 */
final class UserRepository
{
    /** Columns whose values are jsonb and must be decoded to arrays on read. */
    private const JSON_COLUMNS = ['raw_app_meta_data', 'raw_user_meta_data'];

    public function __construct(private PDO $pdo) {}

    /**
     * @param array<string,mixed> $attrs Supported keys: email, encrypted_password,
     *   raw_app_meta_data, raw_user_meta_data, email_confirmed_at, phone.
     * @return array<string,mixed> The created row (metadata as arrays).
     * @throws DuplicateEmailException on unique_violation (23505).
     */
    public function create(array $attrs): array
    {
        $email = isset($attrs['email']) ? EmailNormalizer::normalize((string) $attrs['email']) : null;
        $appMeta = $attrs['raw_app_meta_data'] ?? [];
        $userMeta = $attrs['raw_user_meta_data'] ?? [];

        $sql = <<<SQL
        INSERT INTO auth.users
            (email, encrypted_password, email_confirmed_at, phone,
             raw_app_meta_data, raw_user_meta_data)
        VALUES
            (:email, :encrypted_password, :email_confirmed_at, :phone,
             :app_meta::jsonb, :user_meta::jsonb)
        RETURNING *
        SQL;

        $stmt = $this->pdo->prepare($sql);
        try {
            $stmt->execute([
                ':email' => $email,
                ':encrypted_password' => $attrs['encrypted_password'] ?? null,
                ':email_confirmed_at' => $attrs['email_confirmed_at'] ?? null,
                ':phone' => $attrs['phone'] ?? null,
                ':app_meta' => json_encode($appMeta, JSON_THROW_ON_ERROR),
                ':user_meta' => json_encode($userMeta, JSON_THROW_ON_ERROR),
            ]);
        } catch (PDOException $e) {
            throw $this->translate($e);
        }

        return $this->hydrate($stmt->fetch());
    }

    /** @return array<string,mixed>|null */
    public function findByEmail(string $email): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM auth.users WHERE email = :email AND deleted_at IS NULL'
        );
        $stmt->execute([':email' => EmailNormalizer::normalize($email)]);
        $row = $stmt->fetch();

        return $row === false ? null : $this->hydrate($row);
    }

    /** @return array<string,mixed>|null */
    public function findById(string $id): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM auth.users WHERE id = :id AND deleted_at IS NULL'
        );
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();

        return $row === false ? null : $this->hydrate($row);
    }

    /**
     * Update a whitelisted subset of columns.
     *
     * @param array<string,mixed> $attrs Supported keys: email, encrypted_password,
     *   email_confirmed_at, phone, raw_app_meta_data, raw_user_meta_data.
     * @return array<string,mixed> The updated row.
     * @throws DuplicateEmailException on unique_violation (23505).
     */
    public function update(string $id, array $attrs): array
    {
        $sets = [];
        $params = [':id' => $id];

        if (array_key_exists('email', $attrs)) {
            $sets[] = 'email = :email';
            $params[':email'] = $attrs['email'] === null
                ? null
                : EmailNormalizer::normalize((string) $attrs['email']);
        }
        if (array_key_exists('encrypted_password', $attrs)) {
            $sets[] = 'encrypted_password = :encrypted_password';
            $params[':encrypted_password'] = $attrs['encrypted_password'];
        }
        if (array_key_exists('email_confirmed_at', $attrs)) {
            $sets[] = 'email_confirmed_at = :email_confirmed_at';
            $params[':email_confirmed_at'] = $attrs['email_confirmed_at'];
        }
        if (array_key_exists('phone', $attrs)) {
            $sets[] = 'phone = :phone';
            $params[':phone'] = $attrs['phone'];
        }
        if (array_key_exists('raw_app_meta_data', $attrs)) {
            $sets[] = 'raw_app_meta_data = :app_meta::jsonb';
            $params[':app_meta'] = json_encode($attrs['raw_app_meta_data'], JSON_THROW_ON_ERROR);
        }
        if (array_key_exists('raw_user_meta_data', $attrs)) {
            $sets[] = 'raw_user_meta_data = :user_meta::jsonb';
            $params[':user_meta'] = json_encode($attrs['raw_user_meta_data'], JSON_THROW_ON_ERROR);
        }

        if ($sets === []) {
            $found = $this->findById($id);
            if ($found === null) {
                throw new \RuntimeException("User {$id} not found.");
            }
            return $found;
        }

        $sets[] = 'updated_at = now()';
        $sql = 'UPDATE auth.users SET ' . implode(', ', $sets)
            . ' WHERE id = :id AND deleted_at IS NULL RETURNING *';

        $stmt = $this->pdo->prepare($sql);
        try {
            $stmt->execute($params);
        } catch (PDOException $e) {
            throw $this->translate($e);
        }

        $row = $stmt->fetch();
        if ($row === false) {
            throw new \RuntimeException("User {$id} not found.");
        }

        return $this->hydrate($row);
    }

    public function markEmailConfirmed(string $id): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE auth.users SET email_confirmed_at = now(), updated_at = now()
             WHERE id = :id AND deleted_at IS NULL'
        );
        $stmt->execute([':id' => $id]);
    }

    public function setLastSignInAt(string $id): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE auth.users SET last_sign_in_at = now(), updated_at = now()
             WHERE id = :id AND deleted_at IS NULL'
        );
        $stmt->execute([':id' => $id]);
    }

    /**
     * @return array<int,array<string,mixed>> Non-deleted users, newest first.
     */
    public function list(int $page, int $perPage): array
    {
        $page = max(1, $page);
        $perPage = max(1, $perPage);
        $offset = ($page - 1) * $perPage;

        $stmt = $this->pdo->prepare(
            'SELECT * FROM auth.users WHERE deleted_at IS NULL
             ORDER BY created_at DESC, id DESC
             LIMIT :limit OFFSET :offset'
        );
        $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        return array_map([$this, 'hydrate'], $stmt->fetchAll());
    }

    public function softDelete(string $id): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE auth.users SET deleted_at = now(), updated_at = now()
             WHERE id = :id AND deleted_at IS NULL'
        );
        $stmt->execute([':id' => $id]);
    }

    /**
     * Decode jsonb columns into PHP arrays.
     *
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private function hydrate(array $row): array
    {
        foreach (self::JSON_COLUMNS as $col) {
            if (isset($row[$col]) && is_string($row[$col])) {
                $row[$col] = json_decode($row[$col], true, 512, JSON_THROW_ON_ERROR);
            }
        }
        return $row;
    }

    private function translate(PDOException $e): \Throwable
    {
        if ($e->getCode() === '23505') {
            return new DuplicateEmailException('Email already registered.', 0, $e);
        }
        return $e;
    }
}
