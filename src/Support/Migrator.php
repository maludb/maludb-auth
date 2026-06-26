<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

use PDO;

final class Migrator
{
    public function __construct(private PDO $pdo, private string $dir) {}

    /** @return string[] versions applied this run */
    public function run(): array
    {
        $this->ensureTable();
        $applied = $this->appliedVersions();
        $newlyApplied = [];
        foreach ($this->files() as $version => $path) {
            if (in_array($version, $applied, true)) {
                continue;
            }
            $sql = file_get_contents($path);
            $this->pdo->exec($sql);
            $stmt = $this->pdo->prepare('INSERT INTO auth.schema_migrations(version) VALUES(:v)');
            $stmt->execute([':v' => $version]);
            $newlyApplied[] = $version;
        }
        return $newlyApplied;
    }

    private function ensureTable(): void
    {
        $this->pdo->exec('CREATE SCHEMA IF NOT EXISTS auth');
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS auth.schema_migrations (
                version varchar(255) PRIMARY KEY,
                applied_at timestamptz NOT NULL DEFAULT now())'
        );
    }

    /** @return string[] */
    private function appliedVersions(): array
    {
        return $this->pdo->query('SELECT version FROM auth.schema_migrations')
            ->fetchAll(PDO::FETCH_COLUMN) ?: [];
    }

    /** @return array<string,string> version => path, sorted */
    private function files(): array
    {
        $out = [];
        foreach (glob($this->dir . '/*.sql') as $path) {
            $out[basename($path, '.sql')] = $path;
        }
        ksort($out);
        return $out;
    }
}
