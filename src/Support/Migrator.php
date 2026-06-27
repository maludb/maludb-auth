<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

use PDO;
use Throwable;

final class Migrator
{
    public function __construct(
        private PDO $pdo,
        private string $dir,
        private string $schema = 'auth',
    ) {}

    /**
     * Apply pending migrations.
     *
     * Each migration's DDL and its schema_migrations insert run inside one
     * explicit transaction, so a mid-migration failure leaves nothing applied
     * or recorded. Note: statements that cannot run inside a transaction (e.g.
     * CREATE INDEX CONCURRENTLY) are NOT supported by this runner — fine for our
     * phases.
     *
     * @return string[] versions applied this run
     */
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
            $this->pdo->beginTransaction();
            try {
                $this->pdo->exec($sql);
                $stmt = $this->pdo->prepare(
                    sprintf('INSERT INTO %s.schema_migrations(version) VALUES(:v)', $this->schema)
                );
                $stmt->execute([':v' => $version]);
                $this->pdo->commit();
            } catch (Throwable $e) {
                if ($this->pdo->inTransaction()) {
                    $this->pdo->rollBack();
                }
                throw $e;
            }
            $newlyApplied[] = $version;
        }
        return $newlyApplied;
    }

    private function ensureTable(): void
    {
        $this->pdo->exec(sprintf('CREATE SCHEMA IF NOT EXISTS %s', $this->schema));
        $this->pdo->exec(sprintf(
            'CREATE TABLE IF NOT EXISTS %s.schema_migrations (
                version varchar(255) PRIMARY KEY,
                applied_at timestamptz NOT NULL DEFAULT now())',
            $this->schema
        ));
    }

    /** @return string[] */
    private function appliedVersions(): array
    {
        return $this->pdo->query(sprintf('SELECT version FROM %s.schema_migrations', $this->schema))
            ->fetchAll(PDO::FETCH_COLUMN) ?: [];
    }

    /** @return array<string,string> version => path, sorted */
    private function files(): array
    {
        if (!is_dir($this->dir)) {
            throw new \RuntimeException("Migrations directory not found: {$this->dir}");
        }
        $out = [];
        foreach (glob($this->dir . '/*.sql') ?: [] as $path) {
            $out[basename($path, '.sql')] = $path;
        }
        ksort($out);
        return $out;
    }
}
