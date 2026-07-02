<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Repositories\AuditRepository;

final class AuditRepositoryTest extends IntegrationTestCase
{
    private function repo(): AuditRepository
    {
        return new AuditRepository(self::$pdo);
    }

    public function test_record_stores_action_in_payload(): void
    {
        $this->repo()->record('user_signedup', ['user_id' => 'abc', 'email' => 'a@b.com'], '203.0.113.7');

        $row = self::$pdo->query(
            "SELECT payload->>'action' AS action,
                    payload->>'user_id' AS user_id,
                    ip_address
             FROM auth.audit_log_entries
             ORDER BY created_at DESC LIMIT 1"
        )->fetch();

        $this->assertSame('user_signedup', $row['action']);
        $this->assertSame('abc', $row['user_id']);
        $this->assertSame('203.0.113.7', $row['ip_address']);
    }

    public function test_recent_returns_entries_newest_first(): void
    {
        $this->repo()->record('first', [], '1.1.1.1');
        $this->repo()->record('second', [], '2.2.2.2');
        $this->repo()->record('third', [], '3.3.3.3');

        $rows = $this->repo()->recent(2);

        $this->assertCount(2, $rows);
        // payload round-trips as a PHP array.
        $this->assertIsArray($rows[0]['payload']);
        $this->assertSame('third', $rows[0]['payload']['action']);
        $this->assertSame('second', $rows[1]['payload']['action']);
        $this->assertSame('3.3.3.3', $rows[0]['ip_address']);
    }

    public function test_recent_honours_limit(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->repo()->record("evt{$i}", [], '9.9.9.9');
        }

        $this->assertCount(3, $this->repo()->recent(3));
    }

    public function test_record_merges_payload_without_clobbering_action(): void
    {
        // An 'action' key inside $payload must not override the primary action
        // (['action'=>$action] + $payload => left operand wins on key collision).
        $this->repo()->record('login', ['action' => 'ignored', 'method' => 'password'], '4.4.4.4');

        $rows = $this->repo()->recent(1);
        $this->assertSame('login', $rows[0]['payload']['action']);
        $this->assertSame('password', $rows[0]['payload']['method']);
    }
}
