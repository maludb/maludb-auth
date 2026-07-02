<?php
declare(strict_types=1);

namespace Maludb\Auth;

use Maludb\Auth\Controllers\AdminUsersController;
use Maludb\Auth\Controllers\LogoutController;
use Maludb\Auth\Controllers\MetaController;
use Maludb\Auth\Controllers\OtpController;
use Maludb\Auth\Controllers\RecoverController;
use Maludb\Auth\Controllers\SignupController;
use Maludb\Auth\Controllers\TokenController;
use Maludb\Auth\Controllers\UserController;
use Maludb\Auth\Controllers\VerifyController;
use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Middleware\{AuthContext, Cors, CsrfGuard, RateLimit, RequireAdmin, SecurityHeaders};
use Maludb\Auth\Http\{Request, RequestContext, Response, Router, TokenResponder};
use Maludb\Auth\Mail\{LogMailer, MailComposer, MailerInterface, NullMailer};
use Maludb\Auth\Repositories\{AuditRepository, IdentityRepository, OneTimeTokenRepository, RefreshTokenRepository, SessionRepository, UserRepository};
use Maludb\Auth\Security\{Csrf, Jwks, Jwt, Password, RateLimiter, RedirectValidator, TokenHash};
use Maludb\Auth\Services\{AuthService, OtpService, SessionService, TokenService};
use Maludb\Auth\Support\{Config, Database, Env};
use PDO;

/**
 * Application container + front controller.
 *
 * Stateless collaborators (services, repositories, security primitives) are
 * constructed ONCE at boot and reused across requests. Only the mutable
 * per-request identity holder (RequestContext) and the middleware/controllers
 * that read or write it are rebuilt on every request, so no caller's identity
 * can bleed into another request. The full middleware chain is:
 *
 *   SecurityHeaders -> Cors -> RateLimit -> AuthContext -> CsrfGuard -> Router
 *
 * RateLimit sits BEFORE AuthContext so unauthenticated floods are throttled by
 * IP/email before any token work happens.
 */
final class App
{
    private const BASE_PATH = '/auth/v1';

    public function __construct(
        private Config $config,
        private Database $database,
        private PDO $pdo,
        private string $base,
        // Stateless, request-independent collaborators built once at boot.
        private SecurityHeaders $securityHeaders,
        private Cors $cors,
        private RateLimit $rateLimit,
        private Jwt $jwt,
        private Csrf $csrf,
        private SessionRepository $sessions,
        private UserRepository $users,
        private AuditRepository $audit,
        private Password $password,
        private AuthService $auth,
        private TokenService $tokens,
        private TokenResponder $responder,
        private MetaController $meta,
        private OtpService $otp,
        private RedirectValidator $redirects,
    ) {}

    public static function boot(): self
    {
        $base = dirname(__DIR__);
        Env::load($base);

        $config = new Config(require $base . '/config/config.php');
        $database = new Database($config);
        $pdo = $database->connection();

        return self::fromConfig($config, $database, $pdo, $base);
    }

    /**
     * Build the fully-wired app from an existing Config + PDO. Extracted so
     * integration tests can drive the real router against the test DB/keys.
     * $mailer overrides the config-selected driver (tests inject ArrayMailer).
     */
    public static function fromConfig(
        Config $config,
        Database $database,
        PDO $pdo,
        string $base,
        ?MailerInterface $mailer = null,
    ): self {
        $jwt = self::buildJwt($config, $base);
        $csrf = new Csrf();
        $tokenHash = new TokenHash();

        $users = new UserRepository($pdo);
        $sessions = new SessionRepository($pdo);
        $refreshTokens = new RefreshTokenRepository($pdo);
        $identities = new IdentityRepository($pdo);
        $audit = new AuditRepository($pdo);

        $password = new Password((int) $config->get('password.min_length', 12));

        $tokens = new TokenService(
            $users, $sessions, $refreshTokens, $audit,
            $jwt, $csrf, $tokenHash, new SessionService(), $config, $pdo,
        );
        $auth = new AuthService($users, $tokens, $password, $audit, $identities, $config, $pdo);
        $responder = new TokenResponder();

        $mailer ??= match ($config->get('mailer.driver', 'log')) {
            'null' => new NullMailer(),
            default => new LogMailer(),
        };
        $otp = new OtpService(
            $users, $identities, new OneTimeTokenRepository($pdo), $tokens, $audit,
            $mailer,
            new MailComposer((string) $config->get('app.url'), $config->get('site.url')),
            $tokenHash, $config, $pdo,
        );
        $redirects = new RedirectValidator(
            $config->get('site.url'),
            (array) $config->get('site.uri_allow_list', []),
        );

        $rateLimit = new RateLimit(
            new RateLimiter($pdo),
            require $base . '/config/ratelimits.php',
        );

        $cors = new Cors(
            $config->get('site.url'),
            $config->get('site.uri_allow_list', []),
        );

        $jwks = new Jwks(
            $base . '/' . ltrim((string) $config->get('jwt.public_key_path'), '/'),
            (string) $config->get('jwt.kid'),
        );
        $meta = new MetaController($config, $jwks);

        return new self(
            $config, $database, $pdo, $base,
            new SecurityHeaders(), $cors, $rateLimit,
            $jwt, $csrf, $sessions, $users, $audit, $password,
            $auth, $tokens, $responder, $meta, $otp, $redirects,
        );
    }

    private static function buildJwt(Config $config, string $base): Jwt
    {
        // Read with @ so a missing/unreadable key doesn't emit a raw PHP warning;
        // an empty key simply makes the signer throw at issue time, which the
        // top-level handler maps to a generic 500 (no config detail leaked).
        $priv = (string) @file_get_contents(
            $base . '/' . ltrim((string) $config->get('jwt.private_key_path'), '/')
        );
        $pub = (string) @file_get_contents(
            $base . '/' . ltrim((string) $config->get('jwt.public_key_path'), '/')
        );

        return new Jwt(
            $priv,
            $pub,
            (string) $config->get('jwt.kid'),
            (string) $config->get('jwt.issuer'),
            (string) $config->get('jwt.audience', 'authenticated'),
        );
    }

    public function handle(Request $request): Response
    {
        try {
            // Fresh per request: the mutable identity holder plus every component
            // that reads/writes it, so no identity bleeds across requests.
            $context = new RequestContext();
            $router = $this->buildRouter($context);

            $chain = array_reduce(
                array_reverse($this->globalMiddleware($context)),
                fn(callable $next, $mw) => fn(Request $req) => $mw->handle($req, $next),
                fn(Request $req): Response => $router->dispatch($req),
            );

            return $chain($request);
        } catch (\Throwable $e) {
            // Any uncaught error becomes a generic 500 (never a stack trace), and
            // SecurityHeaders still applies because it wraps this catch below.
            return $this->securityHeaders->handle(
                $request,
                static fn(Request $r): Response => ErrorMapper::map($e),
            );
        }
    }

    /**
     * Global middleware, outermost -> innermost. SecurityHeaders is outermost so
     * it decorates every response (including short-circuits from inner
     * middleware). RateLimit precedes AuthContext so floods are throttled first.
     *
     * @return array<int,\Maludb\Auth\Http\Middleware\MiddlewareInterface>
     */
    private function globalMiddleware(RequestContext $context): array
    {
        return [
            $this->securityHeaders,
            $this->cors,
            $this->rateLimit,
            new AuthContext($this->jwt, $context),
            new CsrfGuard($context, $this->sessions, $this->csrf),
        ];
    }

    private function buildRouter(RequestContext $context): Router
    {
        $router = new Router();
        $b = self::BASE_PATH;

        // Controllers that touch the per-request context are rebuilt per request.
        $signup = new SignupController($this->auth, $this->tokens, $this->responder, $this->config, $this->otp);
        $token = new TokenController($this->auth, $this->tokens, $this->responder, $this->config);
        $logout = new LogoutController($this->sessions, $this->audit);
        $user = new UserController(
            $this->users, $this->sessions, $this->audit,
            $this->password, $this->csrf, $this->otp, $this->config,
        );
        $recover = new RecoverController($this->otp, $this->users);
        $otpCtrl = new OtpController($this->otp);
        $verify = new VerifyController($this->otp, $this->responder, $this->redirects, $this->config);
        $admin = new AdminUsersController($this->users, $this->audit, $this->password);

        // --- Public / meta ------------------------------------------------
        $router->add('GET', $b . '/health', $this->meta->health(...));
        $router->add('GET', $b . '/settings', $this->meta->settings(...));
        $router->add('GET', $b . '/.well-known/jwks.json', $this->meta->jwks(...));

        $router->add('POST', $b . '/signup', fn(Request $r) => $signup->handle($r, $context));
        $router->add('POST', $b . '/token', fn(Request $r) => $token->handle($r, $context));
        $router->add('POST', $b . '/recover', fn(Request $r) => $recover->recover($r, $context));
        $router->add('POST', $b . '/otp', fn(Request $r) => $otpCtrl->otp($r, $context));
        $router->add('POST', $b . '/magiclink', fn(Request $r) => $otpCtrl->magiclink($r, $context));
        $router->add('POST', $b . '/resend', fn(Request $r) => $otpCtrl->resend($r, $context));
        $router->add('GET', $b . '/verify', fn(Request $r) => $verify->get($r, $context));
        $router->add('POST', $b . '/verify', fn(Request $r) => $verify->post($r, $context));

        // --- Authenticated ------------------------------------------------
        $router->add('POST', $b . '/logout', fn(Request $r) => $logout->handle($r, $context));
        $router->add('GET', $b . '/user', fn(Request $r) => $user->show($r, $context));
        $router->add('PUT', $b . '/user', fn(Request $r) => $user->update($r, $context));
        $router->add('POST', $b . '/reauthenticate', fn(Request $r) => $recover->reauthenticate($r, $context));

        // --- Admin (RequireAdmin route middleware, /admin/* ONLY) ----------
        $requireAdmin = [new RequireAdmin($context, $this->config)];

        $router->add('GET', $b . '/admin/users', fn(Request $r) => $admin->list($r), $requireAdmin);
        $router->add('POST', $b . '/admin/users', fn(Request $r) => $admin->create($r), $requireAdmin);
        $router->add('GET', $b . '/admin/users/{id}', fn(Request $r, array $p) => $admin->show($r, $p), $requireAdmin);
        $router->add('PUT', $b . '/admin/users/{id}', fn(Request $r, array $p) => $admin->update($r, $p), $requireAdmin);
        $router->add('DELETE', $b . '/admin/users/{id}', fn(Request $r, array $p) => $admin->delete($r, $p), $requireAdmin);

        return $router;
    }
}
