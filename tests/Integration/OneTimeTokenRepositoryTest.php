<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Repositories\OneTimeTokenRepository;

final class OneTimeTokenRepositoryTest extends IntegrationTestCase
{
    private OneTimeTokenRepository $tokens;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tokens = new OneTimeTokenRepository(self::$pdo);
    }

    private function createUser(string $email = 'ott@example.com'): string
    {
        $stmt = self::$pdo->prepare(
            'INSERT INTO auth.users (email) VALUES (:e) RETURNING id'
        );
        $stmt->execute([':e' => $email]);

        return (string) $stmt->fetchColumn();
    }

    public function test_replace_inserts_and_find_by_hash_roundtrips(): void
    {
        $userId = $this->createUser();
        $hash = str_repeat('a', 64);

        $row = $this->tokens->replace($userId, 'recovery', $hash, 'ott@example.com');

        $this->assertSame($userId, $row['user_id']);
        $this->assertSame('recovery', $row['token_type']);
        $this->assertSame($hash, $row['token_hash']);
        $this->assertSame('ott@example.com', $row['relates_to']);

        $found = $this->tokens->findByHash($hash);
        $this->assertNotNull($found);
        $this->assertSame($row['id'], $found['id']);
    }

    public function test_replace_enforces_single_live_token_per_user_and_type(): void
    {
        $userId = $this->createUser();
        $this->tokens->replace($userId, 'recovery', str_repeat('a', 64), '');
        $this->tokens->replace($userId, 'recovery', str_repeat('b', 64), '');

        // Old token is dead, new one lives.
        $this->assertNull($this->tokens->findByHash(str_repeat('a', 64)));
        $this->assertNotNull($this->tokens->findByHash(str_repeat('b', 64)));

        $count = (int) self::$pdo->query(
            "SELECT count(*) FROM auth.one_time_tokens WHERE token_type = 'recovery'"
        )->fetchColumn();
        $this->assertSame(1, $count);
    }

    public function test_distinct_types_coexist_for_one_user(): void
    {
        $userId = $this->createUser();
        $this->tokens->replace($userId, 'recovery', str_repeat('a', 64), '');
        $this->tokens->replace($userId, 'confirmation', str_repeat('b', 64), '');

        $this->assertNotNull($this->tokens->findByHash(str_repeat('a', 64)));
        $this->assertNotNull($this->tokens->findByHash(str_repeat('b', 64)));
    }

    public function test_find_for_user_and_delete(): void
    {
        $userId = $this->createUser();
        $row = $this->tokens->replace($userId, 'reauthentication', str_repeat('c', 64), '');

        $found = $this->tokens->findForUser($userId, 'reauthentication');
        $this->assertNotNull($found);
        $this->assertSame($row['id'], $found['id']);

        $this->tokens->delete($row['id']);
        $this->assertNull($this->tokens->findForUser($userId, 'reauthentication'));
    }

    public function test_delete_all_for_user_and_type(): void
    {
        $userId = $this->createUser();
        $this->tokens->replace($userId, 'magiclink', str_repeat('d', 64), '');
        $this->tokens->deleteAllFor($userId, 'magiclink');

        $this->assertNull($this->tokens->findForUser($userId, 'magiclink'));
    }
}
