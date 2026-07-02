<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Support\{Config, Database, Env};
use PHPUnit\Framework\TestCase;
use PDO;

abstract class IntegrationTestCase extends TestCase
{
    protected static PDO $pdo;
    protected Config $config;

    public static function setUpBeforeClass(): void
    {
        $base = dirname(__DIR__, 2);
        Env::load($base);
        $_ENV['APP_ENV'] = 'testing';
        putenv('APP_ENV=testing');
        $config = new Config(require $base . '/config/config.php');
        self::$pdo = (new Database($config))->connection();
    }

    protected function setUp(): void
    {
        $base = dirname(__DIR__, 2);
        $this->config = new Config(require $base . '/config/config.php');
        self::$pdo->beginTransaction();
    }

    protected function tearDown(): void
    {
        if (self::$pdo->inTransaction()) {
            self::$pdo->rollBack();
        }
    }
}
