<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

/**
 * Verifies the core auth schema created by migration 0002 exists in the test
 * DB. The harness (tests/bootstrap.php) applies all migrations once at suite
 * start, so the tables are present here. Each test runs inside the parent's
 * rolled-back transaction; querying information_schema is read-only and safe.
 */
final class CoreSchemaTest extends IntegrationTestCase
{
    /**
     * @return string[]
     */
    private function tableNames(): array
    {
        return self::$pdo->query(
            "SELECT table_name FROM information_schema.tables
             WHERE table_schema = 'auth'"
        )->fetchAll(\PDO::FETCH_COLUMN);
    }

    private function columnExists(string $table, string $column): bool
    {
        $stmt = self::$pdo->prepare(
            "SELECT count(*) FROM information_schema.columns
             WHERE table_schema = 'auth' AND table_name = :t AND column_name = :c"
        );
        $stmt->execute([':t' => $table, ':c' => $column]);
        return (int) $stmt->fetchColumn() === 1;
    }

    public function test_core_tables_exist(): void
    {
        $tables = $this->tableNames();
        foreach ([
            'users',
            'identities',
            'sessions',
            'refresh_tokens',
            'audit_log_entries',
            'rate_limits',
        ] as $expected) {
            $this->assertContains($expected, $tables, "Expected auth.$expected to exist");
        }
    }

    public function test_key_columns_exist(): void
    {
        $this->assertTrue($this->columnExists('users', 'encrypted_password'));
        $this->assertTrue($this->columnExists('sessions', 'csrf_token'));
        $this->assertTrue($this->columnExists('refresh_tokens', 'parent'));
        $this->assertTrue($this->columnExists('refresh_tokens', 'revoked'));
    }

    public function test_users_confirmed_at_is_generated(): void
    {
        $stmt = self::$pdo->prepare(
            "SELECT is_generated FROM information_schema.columns
             WHERE table_schema = 'auth' AND table_name = 'users'
               AND column_name = :c"
        );
        $stmt->execute([':c' => 'confirmed_at']);
        $this->assertSame('ALWAYS', $stmt->fetchColumn());
    }
}
