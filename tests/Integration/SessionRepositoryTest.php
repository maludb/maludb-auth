<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Repositories\RefreshTokenRepository;
use Maludb\Auth\Repositories\SessionRepository;
use Maludb\Auth\Repositories\UserRepository;

final class SessionRepositoryTest extends IntegrationTestCase
{
    private function users(): UserRepository
    {
        return new UserRepository(self::$pdo);
    }

    private function sessions(): SessionRepository
    {
        return new SessionRepository(self::$pdo);
    }

    private function tokens(): RefreshTokenRepository
    {
        return new RefreshTokenRepository(self::$pdo);
    }

    private function makeUser(string $email = 'sess@example.com'): string
    {
        return $this->users()->create(['email' => $email])['id'];
    }

    // --- SessionRepository -------------------------------------------------

    public function test_create_inserts_session_with_defaults(): void
    {
        $userId = $this->makeUser();
        $row = $this->sessions()->create(
            $userId,
            csrfToken: 'csrf-abc',
            ip: '203.0.113.5',
            userAgent: 'PHPUnit/1.0',
            notAfter: '2026-12-31 00:00:00+00',
        );

        $this->assertArrayHasKey('id', $row);
        $this->assertNotEmpty($row['id']);
        $this->assertSame($userId, $row['user_id']);
        $this->assertSame('aal1', $row['aal']);
        $this->assertSame('csrf-abc', $row['csrf_token']);
        $this->assertSame('203.0.113.5', $row['ip']);
        $this->assertSame('PHPUnit/1.0', $row['user_agent']);
        $this->assertNotNull($row['not_after']);
        $this->assertNull($row['refreshed_at']);
    }

    public function test_find_returns_session_or_null(): void
    {
        $userId = $this->makeUser();
        $row = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);

        $found = $this->sessions()->find($row['id']);
        $this->assertNotNull($found);
        $this->assertSame($row['id'], $found['id']);

        $this->assertNull($this->sessions()->find('00000000-0000-0000-0000-000000000000'));
    }

    public function test_touch_refreshed_at(): void
    {
        $userId = $this->makeUser();
        $row = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);
        $this->assertNull($row['refreshed_at']);

        $this->sessions()->touchRefreshedAt($row['id']);

        $found = $this->sessions()->find($row['id']);
        $this->assertNotNull($found['refreshed_at']);
    }

    public function test_update_csrf_token(): void
    {
        $userId = $this->makeUser();
        $row = $this->sessions()->create($userId, 'old-csrf', '1.2.3.4', 'ua', null);

        $this->sessions()->updateCsrfToken($row['id'], 'new-csrf');

        $found = $this->sessions()->find($row['id']);
        $this->assertSame('new-csrf', $found['csrf_token']);
    }

    public function test_update_aal(): void
    {
        $userId = $this->makeUser();
        $row = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);
        $factorId = '11111111-1111-1111-1111-111111111111';

        $this->sessions()->updateAal($row['id'], 'aal2', $factorId);

        $found = $this->sessions()->find($row['id']);
        $this->assertSame('aal2', $found['aal']);
        $this->assertSame($factorId, $found['factor_id']);
    }

    public function test_delete_removes_session(): void
    {
        $userId = $this->makeUser();
        $row = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);

        $this->sessions()->delete($row['id']);

        $this->assertNull($this->sessions()->find($row['id']));
    }

    public function test_delete_all_for_user(): void
    {
        $userId = $this->makeUser();
        $a = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);
        $b = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);

        $this->sessions()->deleteAllForUser($userId);

        $this->assertNull($this->sessions()->find($a['id']));
        $this->assertNull($this->sessions()->find($b['id']));
    }

    public function test_delete_others_for_user_keeps_one(): void
    {
        $userId = $this->makeUser();
        $keep = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);
        $drop = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);

        $this->sessions()->deleteOthersForUser($userId, $keep['id']);

        $this->assertNotNull($this->sessions()->find($keep['id']));
        $this->assertNull($this->sessions()->find($drop['id']));
    }

    // --- RefreshTokenRepository -------------------------------------------

    public function test_issue_inserts_unrevoked_token(): void
    {
        $userId = $this->makeUser();
        $session = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);

        $row = $this->tokens()->issue($session['id'], $userId, 'hash-1');

        $this->assertArrayHasKey('id', $row);
        $this->assertSame('hash-1', $row['token_hash']);
        $this->assertSame($session['id'], $row['session_id']);
        $this->assertSame($userId, $row['user_id']);
        $this->assertFalse((bool) $row['revoked']);
        $this->assertNull($row['parent']);
    }

    public function test_issue_records_parent(): void
    {
        $userId = $this->makeUser();
        $session = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);

        $row = $this->tokens()->issue($session['id'], $userId, 'hash-child', 'hash-parent');

        $this->assertSame('hash-parent', $row['parent']);
    }

    public function test_find_by_hash(): void
    {
        $userId = $this->makeUser();
        $session = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);
        $issued = $this->tokens()->issue($session['id'], $userId, 'find-me');

        $found = $this->tokens()->findByHash('find-me');
        $this->assertNotNull($found);
        $this->assertSame($issued['id'], $found['id']);

        $this->assertNull($this->tokens()->findByHash('does-not-exist'));
    }

    public function test_revoke_single_token(): void
    {
        $userId = $this->makeUser();
        $session = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);
        $issued = $this->tokens()->issue($session['id'], $userId, 'to-revoke');

        $this->tokens()->revoke((int) $issued['id']);

        $found = $this->tokens()->findByHash('to-revoke');
        $this->assertTrue((bool) $found['revoked']);
    }

    public function test_revoke_all_for_session(): void
    {
        $userId = $this->makeUser();
        $session = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);
        $this->tokens()->issue($session['id'], $userId, 'r1');
        $this->tokens()->issue($session['id'], $userId, 'r2');

        $this->tokens()->revokeAllForSession($session['id']);

        $this->assertTrue((bool) $this->tokens()->findByHash('r1')['revoked']);
        $this->assertTrue((bool) $this->tokens()->findByHash('r2')['revoked']);
    }

    public function test_find_active_by_session_excludes_revoked(): void
    {
        $userId = $this->makeUser();
        $session = $this->sessions()->create($userId, 'c', '1.2.3.4', 'ua', null);
        $active = $this->tokens()->issue($session['id'], $userId, 'active');
        $revoked = $this->tokens()->issue($session['id'], $userId, 'revoked');
        $this->tokens()->revoke((int) $revoked['id']);

        $rows = $this->tokens()->findActiveBySession($session['id']);

        $this->assertCount(1, $rows);
        $this->assertSame($active['id'], $rows[0]['id']);
    }
}
