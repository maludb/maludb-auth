<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

final class DatabaseTest extends IntegrationTestCase
{
    public function test_connection_runs_a_query(): void
    {
        $stmt = self::$pdo->query('SELECT 1 AS one');
        $this->assertSame('1', (string) $stmt->fetchColumn());
    }
}
