<?php
declare(strict_types=1);

namespace Maludb\Auth;

use Maludb\Auth\Controllers\MetaController;
use Maludb\Auth\Http\Middleware\{Cors, SecurityHeaders};
use Maludb\Auth\Http\{Request, Response, Router};
use Maludb\Auth\Security\Jwks;
use Maludb\Auth\Support\{Config, Database, Env};

/**
 * Application container + front controller.
 *
 * Wires configuration, the database connection, and the HTTP router with the
 * Phase-0 route table and middleware chain (SecurityHeaders -> CORS -> Router).
 */
final class App
{
    private const BASE_PATH = '/auth/v1';

    public function __construct(
        private Config $config,
        private Database $database,
        private Router $router,
    ) {}

    public static function boot(): self
    {
        $base = dirname(__DIR__);
        Env::load($base);

        $config = new Config(require $base . '/config/config.php');
        $database = new Database($config);
        $router = new Router();

        $app = new self($config, $database, $router);
        $app->registerMiddleware();
        $app->registerRoutes($base);

        return $app;
    }

    public function handle(Request $request): Response
    {
        return $this->router->dispatch($request);
    }

    private function registerMiddleware(): void
    {
        $this->router->middleware(new SecurityHeaders());
        $this->router->middleware(new Cors(
            $this->config->get('site.url'),
            $this->config->get('site.uri_allow_list', []),
        ));
    }

    private function registerRoutes(string $base): void
    {
        $jwks = new Jwks(
            $base . '/' . ltrim((string) $this->config->get('jwt.public_key_path'), '/'),
            (string) $this->config->get('jwt.kid'),
        );
        $meta = new MetaController($this->config, $jwks);

        $this->router->add('GET', self::BASE_PATH . '/health', $meta->health(...));
        $this->router->add('GET', self::BASE_PATH . '/settings', $meta->settings(...));
        $this->router->add('GET', self::BASE_PATH . '/.well-known/jwks.json', $meta->jwks(...));
    }
}
