<?php
use Maludb\Auth\Support\Env;

return [
    'app' => ['env' => Env::get('APP_ENV', 'local'), 'url' => Env::get('APP_URL')],
    'site' => [
        'url' => Env::get('SITE_URL'),
        'uri_allow_list' => array_filter(explode(',', Env::get('URI_ALLOW_LIST', ''))),
    ],
    'db' => [
        'host' => Env::get('DB_HOST', '127.0.0.1'),
        'port' => Env::int('DB_PORT', 5432),
        'name' => Env::get('APP_ENV') === 'testing' ? Env::get('TEST_DB_NAME') : Env::get('DB_NAME'),
        'user' => Env::get('DB_USER'),
        'password' => Env::get('DB_PASSWORD'),
    ],
    'jwt' => [
        'issuer' => Env::get('JWT_ISSUER'),
        'audience' => Env::get('JWT_AUDIENCE', 'authenticated'),
        'exp' => Env::int('JWT_EXP', 3600),
        'private_key_path' => Env::get('JWT_PRIVATE_KEY_PATH', 'keys/jwt_private.pem'),
        'public_key_path' => Env::get('JWT_PUBLIC_KEY_PATH', 'keys/jwt_public.pem'),
        'kid' => Env::get('JWT_KID', 'key-1'),
    ],
    'refresh' => [
        'ttl' => Env::int('REFRESH_TOKEN_TTL', 2592000),
        'reuse_interval' => Env::int('REFRESH_TOKEN_REUSE_INTERVAL', 10),
    ],
    'session' => [
        'timebox' => Env::int('SESSION_TIMEBOX', 0),
        'inactivity_timeout' => Env::int('SESSION_INACTIVITY_TIMEOUT', 0),
    ],
    'password' => ['min_length' => Env::int('PASSWORD_MIN_LENGTH', 12)],
    'signup' => [
        'disabled' => Env::bool('DISABLE_SIGNUP', false),
        'autoconfirm' => Env::bool('MAILER_AUTOCONFIRM', true),
    ],
    'cookie' => [
        'secure' => Env::bool('COOKIE_SECURE', false),
        'samesite' => Env::get('COOKIE_SAMESITE', 'Lax'),
    ],
];
