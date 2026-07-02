<?php
declare(strict_types=1);

/**
 * Mint a long-lived service-role JWT for testing admin endpoints.
 *
 * Signs `role: service_role` with the project's JWT private key so AuthContext
 * resolves it and RequireAdmin lets it through. This is a developer helper — do
 * NOT ship the resulting token to clients.
 *
 * Usage:
 *   php bin/issue-service-token.php [ttl_seconds]   # default 1 year
 */

require __DIR__ . '/../vendor/autoload.php';

use Maludb\Auth\Security\Jwt;
use Maludb\Auth\Support\{Config, Env};

$base = dirname(__DIR__);
Env::load($base);
$config = new Config(require $base . '/config/config.php');

$privPath = $base . '/' . ltrim((string) $config->get('jwt.private_key_path'), '/');
$pubPath = $base . '/' . ltrim((string) $config->get('jwt.public_key_path'), '/');

if (!is_file($privPath) || !is_file($pubPath)) {
    fwrite(STDERR, "JWT keypair not found. Run: php bin/keygen.php\n");
    exit(1);
}

$jwt = new Jwt(
    (string) file_get_contents($privPath),
    (string) file_get_contents($pubPath),
    (string) $config->get('jwt.kid'),
    (string) $config->get('jwt.issuer'),
    (string) $config->get('jwt.audience', 'authenticated'),
);

$ttl = isset($argv[1]) ? max(1, (int) $argv[1]) : 31_536_000; // 1 year

$token = $jwt->issue([
    'sub' => 'service_role',
    'role' => 'service_role',
], $ttl);

echo $token . "\n";
