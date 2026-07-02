<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

$force = in_array('--force', array_slice($argv, 1), true);
$dir = dirname(__DIR__) . '/keys';
$privPath = "$dir/jwt_private.pem";
$pubPath = "$dir/jwt_public.pem";

// Refuse to overwrite existing keys: regenerating would invalidate every
// already-issued JWT. Require an explicit --force to proceed.
if (!$force && (is_file($privPath) || is_file($pubPath))) {
    fwrite(STDERR, "Refusing to overwrite existing key files. Re-run with --force to replace them (this invalidates all issued JWTs).\n");
    exit(1);
}

if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
    fwrite(STDERR, "Failed to create keys directory: $dir\n");
    exit(1);
}

$res = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
    'private_key_bits' => 2048,
]);
if ($res === false) {
    fwrite(STDERR, 'openssl_pkey_new() failed: ' . (openssl_error_string() ?: 'unknown error') . "\n");
    exit(1);
}

if (!openssl_pkey_export($res, $privPem)) {
    fwrite(STDERR, 'openssl_pkey_export() failed: ' . (openssl_error_string() ?: 'unknown error') . "\n");
    exit(1);
}
$details = openssl_pkey_get_details($res);
if ($details === false || !isset($details['key'])) {
    fwrite(STDERR, 'openssl_pkey_get_details() failed: ' . (openssl_error_string() ?: 'unknown error') . "\n");
    exit(1);
}
$pubPem = $details['key'];

if (file_put_contents($privPath, $privPem) === false) {
    fwrite(STDERR, "Failed to write $privPath\n");
    exit(1);
}
if (file_put_contents($pubPath, $pubPem) === false) {
    fwrite(STDERR, "Failed to write $pubPath\n");
    exit(1);
}
chmod($privPath, 0600);
echo "Wrote keys/jwt_private.pem and keys/jwt_public.pem\n";
