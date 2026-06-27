<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Support\Migrator;

final class MigratorTest extends IntegrationTestCase
{
    private const SCHEMA = 'auth_migrator_test';

    /**
     * The migrator runs DDL that cannot live inside the parent's rolled-back
     * transaction, so we override setUp()/tearDown() to skip the transaction.
     * Instead we operate on a THROWAWAY schema (never the canonical 'auth'),
     * recreating it for each test for a clean slate and dropping it afterward.
     */
    protected function setUp(): void
    {
        self::$pdo->exec('DROP SCHEMA IF EXISTS ' . self::SCHEMA . ' CASCADE');
        self::$pdo->exec('CREATE SCHEMA ' . self::SCHEMA);
    }

    protected function tearDown(): void
    {
        self::$pdo->exec('DROP SCHEMA IF EXISTS ' . self::SCHEMA . ' CASCADE');
    }

    public function test_applies_and_records_migrations_idempotently(): void
    {
        $dir = dirname(__DIR__, 1) . '/fixtures/migrations';
        $m = new Migrator(self::$pdo, $dir, self::SCHEMA);

        $applied = $m->run();
        $this->assertSame(['0001_dummy_table', '0002_dummy_table_two'], $applied);

        $count = (int) self::$pdo
            ->query('SELECT count(*) FROM ' . self::SCHEMA . '.schema_migrations')
            ->fetchColumn();
        $this->assertSame(2, $count);

        $this->assertSame([], $m->run()); // idempotent
    }

    public function test_failing_migration_rolls_back_and_is_not_recorded(): void
    {
        $dir = dirname(__DIR__, 1) . '/fixtures/migrations_failing';
        $m = new Migrator(self::$pdo, $dir, self::SCHEMA);

        try {
            $m->run();
            $this->fail('Expected the broken migration to throw.');
        } catch (\Throwable $e) {
            // Expected: 0002_broken contains invalid SQL.
        }

        // The good first migration committed and is recorded.
        $recorded = self::$pdo
            ->query('SELECT version FROM ' . self::SCHEMA . '.schema_migrations ORDER BY version')
            ->fetchAll(\PDO::FETCH_COLUMN);
        $this->assertSame(['0001_dummy_ok'], $recorded);

        // The failed migration is NOT recorded...
        $this->assertNotContains('0002_broken', $recorded);

        // ...and its DDL left nothing behind (no partial table from that file).
        $brokenTableExists = (int) self::$pdo->query(
            "SELECT count(*) FROM information_schema.tables
             WHERE table_schema = '" . self::SCHEMA . "' AND table_name = 'dummy_two'"
        )->fetchColumn();
        $this->assertSame(0, $brokenTableExists);
    }

    public function test_missing_migrations_dir_throws(): void
    {
        $m = new Migrator(self::$pdo, '/no/such/migrations/dir', self::SCHEMA);
        $this->expectException(\RuntimeException::class);
        $m->run();
    }
}
