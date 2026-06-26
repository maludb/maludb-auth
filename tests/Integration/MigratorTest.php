<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Support\Migrator;

final class MigratorTest extends IntegrationTestCase
{
    /**
     * Migrations run DDL that cannot live inside the parent's rolled-back
     * transaction, so we override setUp()/tearDown() to skip the transaction.
     * We DROP the auth schema for a clean slate before each test instead.
     */
    protected function setUp(): void
    {
        self::$pdo->exec('DROP SCHEMA IF EXISTS auth CASCADE');
    }

    protected function tearDown(): void
    {
        // No transaction to roll back; nothing to do.
    }

    public function test_applies_and_records_migrations_idempotently(): void
    {
        $dir = dirname(__DIR__, 2) . '/migrations';
        $m = new Migrator(self::$pdo, $dir);
        $applied = $m->run();
        $this->assertContains('0001_create_schema_migrations', $applied);

        $count = (int) self::$pdo
            ->query("SELECT count(*) FROM auth.schema_migrations WHERE version='0001_create_schema_migrations'")
            ->fetchColumn();
        $this->assertSame(1, $count);

        $this->assertSame([], $m->run()); // idempotent
    }
}
