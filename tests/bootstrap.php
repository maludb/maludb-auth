<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Maludb\Auth\Support\{Config, Database, Env, Migrator};

// Force testing mode so config selects TEST_DB_NAME.
$_ENV['APP_ENV'] = 'testing';
putenv('APP_ENV=testing');

$base = dirname(__DIR__);
Env::load($base);

$config = new Config(require $base . '/config/config.php');
$pdo = (new Database($config))->connection();

// Run the canonical migrations ONCE against the test DB so every integration
// class can assume the 'auth' schema exists, even on a fresh DB and regardless
// of test class order. The migrator is idempotent, so this is cheap on reruns.
(new Migrator($pdo, $base . '/migrations'))->run();
