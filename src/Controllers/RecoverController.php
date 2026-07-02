<?php
declare(strict_types=1);

namespace Maludb\Auth\Controllers;

use Maludb\Auth\Http\ErrorMapper;
use Maludb\Auth\Http\Request;
use Maludb\Auth\Http\RequestContext;
use Maludb\Auth\Http\Response;
use Maludb\Auth\Http\Validator;
use Maludb\Auth\Repositories\AuditRepository;

/**
 * Password recovery + reauthentication request endpoints.
 *
 * Both ALWAYS return a generic 200 regardless of whether the email/user exists,
 * so neither can be used to enumerate accounts. Actual token minting + email
 * delivery are Phase 2 (no mailer yet).
 */
final class RecoverController
{
    public function __construct(private AuditRepository $audit) {}

    public function recover(Request $request, RequestContext $context): Response
    {
        try {
            // Validate shape only; never branch the response on existence.
            $email = Validator::email($request->input('email'));

            // TODO(Phase 2): create a recovery one-time token row and send the
            // recovery email via the mailer. Until then we only audit the request
            // and return the same generic 200 whether or not the email exists —
            // no enumeration signal.
            $this->audit->record('recover_requested', ['email' => $email], $request->ip);

            return $this->generic();
        } catch (\Throwable $e) {
            return ErrorMapper::map($e);
        }
    }

    public function reauthenticate(Request $request, RequestContext $context): Response
    {
        if ($context->user === null) {
            return Response::json(['error' => 'not_authenticated'], 401);
        }

        // TODO(Phase 2): generate a reauthentication nonce and deliver it via the
        // mailer/SMS. Stubbed to a generic 200 for Phase 1.
        return $this->generic();
    }

    private function generic(): Response
    {
        return Response::json([], 200);
    }
}
