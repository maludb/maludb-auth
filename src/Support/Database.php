<?php
declare(strict_types=1);

namespace Maludb\Auth\Support;

use PDO;

final class Database
{
    private ?PDO $pdo = null;

    public function __construct(private Config $config) {}

    public function connection(): PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }
        $dsn = sprintf(
            'pgsql:host=%s;port=%d;dbname=%s',
            $this->config->get('db.host'),
            $this->config->get('db.port'),
            $this->config->get('db.name'),
        );
        $this->pdo = new PDO($dsn, $this->config->get('db.user'), $this->config->get('db.password'), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        return $this->pdo;
    }
}
