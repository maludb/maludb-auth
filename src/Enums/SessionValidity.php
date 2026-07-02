<?php
declare(strict_types=1);

namespace Maludb\Auth\Enums;

/**
 * Result of evaluating a session against the validity rules.
 *
 * Only Valid is a passing state; every other case means the session must be
 * treated as expired (SessionService::assertValid throws for all non-Valid).
 */
enum SessionValidity
{
    case Valid;
    case PastNotAfter;   // now is past the row's explicit not_after timestamp
    case PastTimebox;    // now is past created_at + session.timebox (absolute max lifetime)
    case TimedOut;       // now is past refreshed_at (or created_at) + session.inactivity_timeout
}
