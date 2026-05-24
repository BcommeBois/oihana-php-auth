<?php

namespace oihana\auth\casbin;

use Casbin\Enforcer;
use Casbin\Exceptions\CasbinException;

use InvalidArgumentException;

use oihana\auth\enums\CapabilityAction;
use oihana\auth\enums\CapabilityMode;
use oihana\auth\enums\PermissionEffect;
use oihana\auth\CapabilityEnforcerInterface;
use oihana\enums\Char;

use function oihana\auth\helpers\casbinSafeSubject;

/**
 * Low-level helper that maps capability checks onto the Casbin enforcer.
 *
 * Capability permissions are stored with:
 * - `action = 'PARAM:<capability>'` — the discriminator used by Casbin
 *   `regexMatch(r.act, p.act)`.
 * - `object = '/<resource>'`        — the route scope.
 * - `effect = 'allow' | 'deny'`     — allowlist or denylist semantics.
 *
 * The enforcer exposes three primitives:
 * - {@see self::has()}      — plain Casbin `enforce()` wrapped with the `PARAM:` prefix.
 * - {@see self::isDenied()} — explicit deny lookup (Casbin `enforce()` alone cannot
 *                             distinguish "no matching policy" from "explicit deny").
 * - {@see self::check()}    — mode-aware dispatcher used by controller traits.
 *
 * @package oihana\auth\casbin
 * @author  Marc Alcaraz
 */
readonly class CapabilityEnforcer implements CapabilityEnforcerInterface
{
    /**
     * Creates a new CapabilityEnforcer.
     *
     * @param Enforcer $enforcer The Casbin enforcer (shared with the Authorized middleware).
     * @param string   $domain   The API domain identifier (same value used for HTTP-route enforcement).
     */
    public function __construct
    (
        protected Enforcer $enforcer ,
        protected string   $domain
    ) {}

    /**
     * Mode-aware dispatcher: returns true iff the user is allowed to use the
     * capability under the given enforcement mode.
     *
     * - `REQUIRE` : returns `has($userId, $object, $capability)`.
     * - `DENY`    : returns `!isDenied($userId, $object, $capability)`.
     *
     * @param string $userId
     * @param string $object
     * @param string $capability
     * @param string $mode One of the {@see CapabilityMode} constants.
     * @param string $actionPrefix
     * @return bool
     *
     * @throws CasbinException
     */
    public function check( string $userId , string $object , string $capability , string $mode , string $actionPrefix = CapabilityAction::PARAM ) : bool
    {
        return match ( $mode )
        {
            CapabilityMode::REQUIRE => $this->has      ( $userId , $object , $capability , $actionPrefix ) ,
            CapabilityMode::DENY    => !$this->isDenied( $userId , $object , $capability , $actionPrefix ) ,
            default                 => throw new InvalidArgumentException( "Unknown capability mode: '$mode'" ) ,
        } ;
    }

    /**
     * Returns true iff the user has at least one matching `allow` policy and no
     * matching `deny` policy for the given capability.
     *
     * Thin wrapper around Casbin `enforce()` — maps `$capability` to the
     * `PARAM:<capability>` action string.
     *
     * @param string $userId The user identifier (Zitadel `sub` claim).
     * @param string $object The route scope, e.g. `/products`.
     * @param string $capability The capability discriminator, e.g. `skin.offers.full`.
     * @param string $actionPrefix
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function has( string $userId , string $object , string $capability , string $actionPrefix = CapabilityAction::PARAM ) : bool
    {
        return $this->enforcer->enforce
        (
            casbinSafeSubject( $userId ) ,
            $this->domain ,
            $object ,
            $actionPrefix . Char::COLON . $capability
        ) ;
    }

    /**
     * Plain `enforce(user, domain, object, action)` against the underlying
     * Casbin enforcer — bypasses the `PARAM:` prefix that {@see has()}
     * applies for capability checks.
     *
     * Used by field-level gating where the caller has already resolved a
     * permission subject (e.g. `roles.permissions:list`) into the
     * `(object, action)` couple stored in the `permissions` collection,
     * and wants to ask Casbin "does this user hold that permission?"
     * without rewriting the action string.
     *
     * @param string $userId The user identifier (Zitadel `sub` claim).
     * @param string $object The policy object, e.g. `/roles/:id/permissions`.
     *                       Casbin's `keyMatch2` matcher handles the `:id`
     *                       placeholder against concrete URLs.
     * @param string $action The HTTP verb, e.g. `GET`.
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function enforceObjectAction( string $userId , string $object , string $action ) : bool
    {
        return $this->enforcer->enforce
        (
            casbinSafeSubject( $userId ) ,
            $this->domain ,
            $object ,
            $action
        ) ;
    }

    /**
     * Returns true iff the user has a matching `deny` policy for the given
     * capability.
     *
     * Used by the `DENY` mode (denylist semantics). Casbin `enforce()` cannot
     * be used here because it returns `false` both for "no matching policy"
     * (open access, allowed) and for "explicit deny" (blocked). This method
     * reads the implicit permissions and filters on `effect = 'deny'` to
     * disambiguate.
     *
     * @param string $userId
     * @param string $object
     * @param string $capability
     * @param string $actionPrefix
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function isDenied( string $userId , string $object , string $capability , string $actionPrefix = CapabilityAction::PARAM ) : bool
    {
        $action = $actionPrefix . Char::COLON . $capability ;

        foreach ( $this->enforcer->getImplicitPermissionsForUser( casbinSafeSubject( $userId ) , $this->domain ) as $permission )
        {
            if ( !is_array( $permission ) )
            {
                continue ;
            }

            $permObject = $permission[ 2 ] ?? '' ;
            $permAction = $permission[ 3 ] ?? '' ;
            $permEffect = $permission[ 4 ] ?? PermissionEffect::ALLOW ;

            if ( $permObject === $object && $permAction === $action && $permEffect === PermissionEffect::DENY )
            {
                return true ;
            }
        }

        return false ;
    }
}
