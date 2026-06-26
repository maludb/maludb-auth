<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

$dir = dirname(__DIR__) . '/keys';
@mkdir($dir, 0700, true);
$res = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
    'private_key_bits' => 2048,
]);
openssl_pkey_export($res, $privPem);
$pubPem = openssl_pkey_get_details($res)['key'];
file_put_contents("$dir/jwt_private.pem", $privPem);
file_put_contents("$dir/jwt_public.pem", $pubPem);
chmod("$dir/jwt_private.pem", 0600);
echo "Wrote keys/jwt_private.pem and keys/jwt_public.pem\n";
