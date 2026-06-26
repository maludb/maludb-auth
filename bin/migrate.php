<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Maludb\Auth\Support\{Config, Database, Env, Migrator};

Env::load(dirname(__DIR__));
$config = new Config(require dirname(__DIR__) . '/config/config.php');
$pdo = (new Database($config))->connection();
$applied = (new Migrator($pdo, dirname(__DIR__) . '/migrations'))->run();
echo $applied ? "Applied: " . implode(', ', $applied) . "\n" : "Nothing to apply.\n";
