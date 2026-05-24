<?php

namespace oihana\auth\controllers\traits;

use Casbin\Exceptions\CasbinException;

use Closure;

use oihana\auth\PermissionSubjectResolverInterface;
use oihana\enums\http\RequestAttribute;

use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Builds a request-scoped `Closure(string $subject): bool` that checks a
 * **permission subject** against the policy engine by translating the subject
 * label into the `(object, action)` couple actually enforced.
 *
 * This trait complements {@see CapabilityAuthorizerTrait}:
 *
 * - {@see CapabilityAuthorizerTrait::buildAuthorizer()} expects the passed
 *   string to be a **capability discriminator** (mapped to a `PARAM:<name>`
 *   action by {@see \oihana\auth\CapabilityEnforcerInterface::has()}). It is
 *   used by query-param gating like `?skin=offers.full`.
 *
 * - {@see self::buildPermissionAuthorizer()} expects the passed string to be
 *   a **permission subject label** (e.g. `roles.permissions:list`). It looks
 *   the label up through {@see PermissionSubjectResolverInterface} and runs a
 *   plain `enforceObjectAction(user, object, action)`. Used by AQL projection
 *   gating declared as `Field::REQUIRES => 'roles.permissions:list'`.
 *
 * The two traits are intentionally separate because they answer different
 * questions: capabilities are *route-scope* gates that only exist as
 * `PARAM:` actions, while permission subjects refer to first-class HTTP
 * permissions already present in the seed (and therefore never need to be
 * duplicated as capabilities).
 *
 * Requires the controller to expose `$capabilityEnforcer` (declared by
 * {@see CapabilityContextTrait}) and to receive a
 * {@see PermissionSubjectResolverInterface} through
 * {@see initializePermissionSubjectResolver()} — the latter is wired
 * automatically by `DocumentsController::__construct()` from the DI container.
 *
 * @package oihana\auth\controllers\traits
 * @author  Marc Alcaraz
 */
trait PermissionAuthorizerTrait
{
    /**
     * The shared catalog resolver.
     *
     * Null when the resolver is unavailable in the container (auth disabled,
     * test harness without a permissions model, etc.). The closure built by
     * {@see buildPermissionAuthorizer()} returns null in that case so the
     * AQL projection layer falls open — the framework's `isAuthorized()`
     * fails open on a null authorizer, which mirrors the existing behavior
     * for capability gating.
     */
    protected ?PermissionSubjectResolverInterface $permissionSubjectResolver = null ;

    /**
     * Stores the resolver injected at construction time.
     *
     * Called by `DocumentsController::__construct()` after
     * `initializeCapabilities()` so every controller that consumes the trait
     * can build a permission-subject authorizer without touching its own
     * constructor.
     */
    protected function initializePermissionSubjectResolver( ?PermissionSubjectResolverInterface $resolver = null ) : static
    {
        $this->permissionSubjectResolver = $resolver ;

        return $this ;
    }

    /**
     * Build a request-scoped `Closure(string $subject): bool` that resolves
     * each subject label through the catalog and asks the enforcer whether
     * the request user holds the corresponding `(object, action)` permission.
     *
     * Resolution rules:
     * - No request, no enforcer or no resolver → returns `null`. Callers
     *   that inject the result into `$init[Arango::AUTHORIZER]` therefore
     *   omit the key entirely, and `isAuthorized()` falls open.
     * - No authenticated user on the request → returns `null`.
     * - Subject unknown to the catalog → the closure returns `false`
     *   (gate closed). This is the safe default: a misspelled subject
     *   should not silently widen access.
     * - Subject known → the closure delegates to `enforceObjectAction(user,
     *   object, action)`. Casbin's matcher uses `keyMatch2` so policy
     *   objects like `/roles/:id/permissions` match concrete URLs.
     *
     * @param Request|null $request The current PSR-7 request (null in CLI / test contexts).
     *
     * @return Closure|null
     */
    protected function buildPermissionAuthorizer( ?Request $request ) : ?Closure
    {
        if ( $this->capabilityEnforcer === null || $this->permissionSubjectResolver === null || $request === null )
        {
            return null ;
        }

        $userId = $request->getAttribute( RequestAttribute::USER_ID ) ;

        if ( !is_string( $userId ) || $userId === '' )
        {
            return null ;
        }

        $enforcer = $this->capabilityEnforcer ;
        $resolver = $this->permissionSubjectResolver ;

        return static function ( string $subject ) use ( $enforcer , $resolver , $userId ) : bool
        {
            $couple = $resolver->resolve( $subject ) ;

            if ( $couple === null )
            {
                return false ;
            }

            try
            {
                return $enforcer->enforceObjectAction( $userId , $couple[ 'object' ] , $couple[ 'action' ] ) ;
            }
            catch ( CasbinException )
            {
                return false ;
            }
        } ;
    }
}
