<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Http\{Request, Response};
use Maludb\Auth\Security\Jwks;
use Maludb\Auth\Support\Config;

/**
 * Public, unauthenticated meta endpoints: health, settings, and JWKS.
 */
final class MetaController
{
    public const VERSION = '0.1.0';

    public function __construct(
        private Config $config,
        private Jwks $jwks,
    ) {}

    public function health(Request $request): Response
    {
        return Response::json([
            'name' => 'maludb-auth',
            'version' => self::VERSION,
        ]);
    }

    public function settings(Request $request): Response
    {
        return Response::json([
            'disable_signup' => (bool) $this->config->get('signup.disabled', false),
            'mailer_autoconfirm' => (bool) $this->config->get('signup.autoconfirm', true),
            'external_email_enabled' => true,
            'mailer_otp_exp' => (int) $this->config->get('otp.ttl', 3600),
        ]);
    }

    public function jwks(Request $request): Response
    {
        return Response::json($this->jwks->keySet());
    }
}
