<?php
declare(strict_types=1);

namespace Maludb\Auth\Tests\Integration;

use Maludb\Auth\Controllers\AdminUsersController;
use Maludb\Auth\Controllers\SignupController;
use Maludb\Auth\Controllers\TokenController;
use Maludb\Auth\Controllers\UserController;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Security\Csrf;
use Maludb\Auth\Security\Password;

/**
 * Cross-cutting guard: NO endpoint response body may ever contain
 * `encrypted_password`. Drives the user-returning controllers through their
 * success paths and asserts the string is absent from every body.
 */
final class NoEncryptedPasswordLeakTest extends ControllerTestCase
{
    public function test_no_endpoint_leaks_encrypted_password(): void
    {
        $config = $this->testConfig();
        $bodies = [];

        // Signup (autoconfirm -> tokens).
        $signup = new SignupController(
            $this->authService($config),
            $this->tokenService($config),
            $this->responder(),
            $config,
        );
        $bodies[] = $signup->handle(
            new Request(method: 'POST', path: '/signup', headers: ['User-Agent' => 'p'],
                rawBody: json_encode(['email' => 'leak1@example.com', 'password' => self::PASSWORD]), ip: '1.1.1.1'),
            new RequestContext(),
        );

        // Token (password grant).
        $token = new TokenController(
            $this->authService($config),
            $this->tokenService($config),
            $this->responder(),
            $config,
        );
        $login = $token->handle(
            new Request(method: 'POST', path: '/token', query: ['grant_type' => 'password'],
                headers: ['User-Agent' => 'p'],
                rawBody: json_encode(['email' => 'leak1@example.com', 'password' => self::PASSWORD]), ip: '1.1.1.1'),
            new RequestContext(),
        );
        $bodies[] = $login;

        $accessToken = json_decode($login->body, true)['access_token'];
        $ctx = $this->contextFor($accessToken);

        // GET /user.
        $userCtl = new UserController(
            $this->users(), $this->sessions(), $this->audit(),
            new Password(12), new Csrf(), $this->otpService($config), $config,
        );
        $bodies[] = $userCtl->show(new Request(method: 'GET', path: '/user', ip: '1.1.1.1'), $ctx);

        // Admin create + list.
        $admin = new AdminUsersController($this->users(), $this->audit(), new Password(12));
        $bodies[] = $admin->create(new Request(method: 'POST', path: '/admin/users',
            rawBody: json_encode(['email' => 'leak2@example.com', 'password' => self::PASSWORD, 'email_confirm' => true]),
            ip: '1.1.1.1'));
        $bodies[] = $admin->list(new Request(method: 'GET', path: '/admin/users', ip: '1.1.1.1'));

        foreach ($bodies as $i => $res) {
            /** @var Response $res */
            $this->assertStringNotContainsString(
                'encrypted_password',
                $res->body,
                "Response #{$i} leaked encrypted_password.",
            );
        }
    }
}
