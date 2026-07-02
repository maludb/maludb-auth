<?php
declare(strict_types=1);

namespace Maludb\Auth\Http\Middleware;

use Maludb\Auth\Http\{Request, Response};

interface MiddlewareInterface
{
    public function handle(Request $request, callable $next): Response;
}
