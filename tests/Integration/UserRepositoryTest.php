<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Exceptions\DuplicateEmailException;
use Maludb\Auth\Repositories\UserRepository;

final class UserRepositoryTest extends IntegrationTestCase
{
    private function repo(): UserRepository
    {
        return new UserRepository(self::$pdo);
    }

    public function test_create_normalizes_email_and_returns_row(): void
    {
        $row = $this->repo()->create([
            'email' => '  Alice@Example.COM ',
            'encrypted_password' => 'hash',
        ]);

        $this->assertArrayHasKey('id', $row);
        $this->assertNotEmpty($row['id']);
        $this->assertSame('alice@example.com', $row['email']);
        $this->assertSame('hash', $row['encrypted_password']);
        // Metadata columns round-trip as PHP arrays, not JSON strings.
        $this->assertIsArray($row['raw_app_meta_data']);
        $this->assertIsArray($row['raw_user_meta_data']);
        $this->assertSame([], $row['raw_app_meta_data']);
        $this->assertSame([], $row['raw_user_meta_data']);
    }

    public function test_create_persists_metadata_arrays_and_reads_them_back(): void
    {
        $row = $this->repo()->create([
            'email' => 'meta@example.com',
            'raw_app_meta_data' => ['provider' => 'email', 'providers' => ['email']],
            'raw_user_meta_data' => ['full_name' => 'Meta User', 'age' => 30],
        ]);

        // jsonb does not preserve key order, so compare by key (assertEquals is
        // order-insensitive for associative arrays), not by identical ordering.
        $this->assertEquals(['provider' => 'email', 'providers' => ['email']], $row['raw_app_meta_data']);
        $this->assertEquals(['full_name' => 'Meta User', 'age' => 30], $row['raw_user_meta_data']);

        // And it survives a fresh read from the DB (true round-trip).
        $found = $this->repo()->findById($row['id']);
        $this->assertNotNull($found);
        $this->assertEquals(['provider' => 'email', 'providers' => ['email']], $found['raw_app_meta_data']);
        $this->assertEquals(['full_name' => 'Meta User', 'age' => 30], $found['raw_user_meta_data']);
    }

    public function test_find_by_email_is_case_insensitive(): void
    {
        $created = $this->repo()->create(['email' => 'case@example.com']);

        $found = $this->repo()->findByEmail('CASE@EXAMPLE.COM');
        $this->assertNotNull($found);
        $this->assertSame($created['id'], $found['id']);

        // Lookup with surrounding whitespace also normalizes.
        $foundTrimmed = $this->repo()->findByEmail('  Case@Example.com  ');
        $this->assertNotNull($foundTrimmed);
        $this->assertSame($created['id'], $foundTrimmed['id']);
    }

    public function test_find_by_email_returns_null_when_missing(): void
    {
        $this->assertNull($this->repo()->findByEmail('nobody@example.com'));
    }

    public function test_find_by_id_returns_null_when_missing(): void
    {
        $this->assertNull($this->repo()->findById('00000000-0000-0000-0000-000000000000'));
    }

    public function test_duplicate_email_throws_duplicate_email_exception(): void
    {
        $this->repo()->create(['email' => 'dup@example.com']);

        $this->expectException(DuplicateEmailException::class);
        // Different case / whitespace still collides after normalization + citext.
        $this->repo()->create(['email' => ' DUP@example.com ']);
    }

    public function test_create_supports_optional_fields(): void
    {
        $row = $this->repo()->create([
            'email' => 'full@example.com',
            'encrypted_password' => null,
            'email_confirmed_at' => '2026-01-01 00:00:00+00',
            'phone' => '+15551234567',
        ]);

        $this->assertNull($row['encrypted_password']);
        $this->assertNotNull($row['email_confirmed_at']);
        $this->assertSame('+15551234567', $row['phone']);
        // Generated column reflects email_confirmed_at.
        $this->assertNotNull($row['confirmed_at']);
    }

    public function test_update_changes_fields_and_returns_row(): void
    {
        $row = $this->repo()->create(['email' => 'upd@example.com']);

        $updated = $this->repo()->update($row['id'], [
            'phone' => '+15550000000',
            'raw_user_meta_data' => ['nickname' => 'Up'],
        ]);

        $this->assertSame('+15550000000', $updated['phone']);
        $this->assertSame(['nickname' => 'Up'], $updated['raw_user_meta_data']);
    }

    public function test_update_email_normalizes(): void
    {
        $row = $this->repo()->create(['email' => 'before@example.com']);
        $updated = $this->repo()->update($row['id'], ['email' => ' After@Example.COM ']);
        $this->assertSame('after@example.com', $updated['email']);
    }

    public function test_update_to_existing_email_throws(): void
    {
        $this->repo()->create(['email' => 'a@example.com']);
        $b = $this->repo()->create(['email' => 'b@example.com']);

        $this->expectException(DuplicateEmailException::class);
        $this->repo()->update($b['id'], ['email' => 'a@example.com']);
    }

    public function test_mark_email_confirmed_sets_timestamp(): void
    {
        $row = $this->repo()->create(['email' => 'confirm@example.com']);
        $this->assertNull($row['email_confirmed_at']);

        $this->repo()->markEmailConfirmed($row['id']);

        $found = $this->repo()->findById($row['id']);
        $this->assertNotNull($found['email_confirmed_at']);
        $this->assertNotNull($found['confirmed_at']);
    }

    public function test_set_last_sign_in_at(): void
    {
        $row = $this->repo()->create(['email' => 'signin@example.com']);
        $this->assertNull($row['last_sign_in_at']);

        $this->repo()->setLastSignInAt($row['id']);

        $found = $this->repo()->findById($row['id']);
        $this->assertNotNull($found['last_sign_in_at']);
    }

    public function test_list_paginates(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->repo()->create(['email' => "list{$i}@example.com"]);
        }

        $page1 = $this->repo()->list(1, 2);
        $page2 = $this->repo()->list(2, 2);

        $this->assertCount(2, $page1);
        $this->assertCount(2, $page2);
        // Pages are disjoint.
        $ids1 = array_column($page1, 'id');
        $ids2 = array_column($page2, 'id');
        $this->assertSame([], array_intersect($ids1, $ids2));
        // Metadata still round-trips as arrays in the list.
        $this->assertIsArray($page1[0]['raw_app_meta_data']);
    }

    public function test_soft_delete_hides_from_lookup_and_frees_email(): void
    {
        $row = $this->repo()->create(['email' => 'gone@example.com']);

        $this->repo()->softDelete($row['id']);

        // No longer found by email (partial unique index is WHERE deleted_at IS NULL).
        $this->assertNull($this->repo()->findByEmail('gone@example.com'));
        // findById also excludes soft-deleted rows.
        $this->assertNull($this->repo()->findById($row['id']));

        // Email can be reused after soft delete.
        $reused = $this->repo()->create(['email' => 'gone@example.com']);
        $this->assertNotSame($row['id'], $reused['id']);
    }
}
