<?php
declare(strict_types=1);

namespace Maludb\Auth\Http;

/**
 * Mutable per-request holder for state that middlewares resolve and controllers
 * read. `Request` is immutable, so the resolved identity cannot live on it; this
 * object is threaded through the chain and written to by AuthContext.
 */
final class RequestContext
{
    public ?AuthenticatedUser $user = null;
}
