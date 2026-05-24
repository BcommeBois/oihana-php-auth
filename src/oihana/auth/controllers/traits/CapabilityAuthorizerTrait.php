<?php

namespace oihana\auth\controllers\traits;

use Closure;

use oihana\enums\http\RequestAttribute;

use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Builds a request-scoped `Closure(string $subject): bool` that checks a
 * permission subject against the controller's capability scope.
 *
 * The closure produced by {@see self::buildAuthorizer()} is fully generic and
 * may be reused anywhere a callable-based authorization decision is needed —
 * not only for ArangoDB projection gating via `Field::REQUIRES`. Examples:
 *
 * - Pose it as `$init[Arango::AUTHORIZER]` so the AQL projection layer can
 *   drop edges/joins the user is not allowed to see.
 * - Run an ad-hoc check inside controller logic: `if ( ! $authorizer( 'export.csv' ) ) { ... }`
 * - Pass it to a CLI command that needs the same evaluation surface as the
 *   HTTP layer.
 *
 * Requires {@see CapabilityContextTrait} to be `use`d alongside (already the
 * case when a controller picks up the {@see CapabilityGuardTrait} facade) —
 * the consumer must expose `$this->capabilityEnforcer` and
 * `$this->capabilityObject` declared by that trait.
 *
 * The user identifier is read from
 * `Request::getAttribute( RequestAttribute::USER_ID )` and forwarded to the
 * enforcer untouched — the enforcer implementation is responsible for any
 * backend-specific normalisation.
 *
 * Returns `null` when the enforcer is unavailable or the request carries
 * no authenticated user — the caller decides whether to fail open (omit
 * the authorizer entirely so the framework defaults apply) or to skip the
 * call site that depends on it.
 *
 * @package oihana\auth\controllers\traits
 * @author  Marc Alcaraz
 */
trait CapabilityAuthorizerTrait
{
    /**
     * Build a request-scoped `Closure(string $subject): bool` bound to the
     * controller's capability scope and the request's authenticated user.
     *
     * @param Request|null $request The current PSR-7 request (null in CLI/test contexts).
     *
     * @return Closure|null `null` when the enforcer is unavailable or no
     *                      authenticated user is attached to the request.
     */
    protected function buildAuthorizer( ?Request $request ) : ?Closure
    {
        if ( $this->capabilityEnforcer === null || $request === null )
        {
            return null ;
        }

        $userId = $request->getAttribute( RequestAttribute::USER_ID ) ;

        if ( !is_string( $userId ) || $userId === '' )
        {
            return null ;
        }

        $object   = $this->capabilityObject ;
        $enforcer = $this->capabilityEnforcer ;

        return fn( string $perm ) : bool => $enforcer->has( $userId , $object , $perm ) ;
    }
}
