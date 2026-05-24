<?php

namespace oihana\auth;

use Casbin\Exceptions\CasbinException;

use oihana\auth\enums\CapabilityAction;

/**
 * Capability enforcement contract — backend-agnostic.
 *
 * Implementations dispatch capability checks onto a concrete policy engine
 * (Casbin or other). Consumers (controller traits, AQL projection layer)
 * depend on this interface so the policy backend can be swapped or stubbed
 * without touching the controllers.
 *
 * Capability permissions are conventionally stored with:
 * - `action = '<prefix>:<capability>'` where the prefix is one of the
 *   {@see CapabilityAction} constants (typically `PARAM:`).
 * - `object = '/<resource>'` — the route scope.
 * - `effect = 'allow' | 'deny'` — allowlist or denylist semantics.
 *
 * @package oihana\auth
 * @author  Marc Alcaraz
 */
interface CapabilityEnforcerInterface
{
    /**
     * Mode-aware dispatcher: returns true iff the user is allowed to use the
     * capability under the given enforcement mode.
     *
     * - `REQUIRE` mode → delegates to {@see self::has()}.
     * - `DENY`    mode → returns the negation of {@see self::isDenied()}.
     *
     * @param string $userId
     * @param string $object
     * @param string $capability
     * @param string $mode         One of the {@see \oihana\auth\enums\CapabilityMode} constants.
     * @param string $actionPrefix
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function check( string $userId , string $object , string $capability , string $mode , string $actionPrefix = CapabilityAction::PARAM ) : bool ;

    /**
     * Plain enforcement against an already-resolved `(object, action)` couple.
     *
     * Bypasses the capability-prefix machinery used by {@see self::has()} —
     * the caller passes the raw `action` value as stored in the permission
     * table. Used by permission-subject gating where the subject label has
     * already been translated to its `(object, action)` couple.
     *
     * @param string $userId
     * @param string $object
     * @param string $action
     *
     * @return bool
     *
     * @throws CasbinException
     */
    public function enforceObjectAction( string $userId , string $object , string $action ) : bool ;

    /**
     * Returns true iff the user has at least one matching `allow` policy and
     * no matching `deny` policy for the given capability.
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
    public function has( string $userId , string $object , string $capability , string $actionPrefix = CapabilityAction::PARAM ) : bool ;

    /**
     * Returns true iff the user has a matching `deny` policy for the given
     * capability.
     *
     * Required because {@see self::has()} cannot distinguish "no matching
     * policy" (open access) from "explicit deny" (blocked). Denylist-mode
     * checks rely on this primitive.
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
    public function isDenied( string $userId , string $object , string $capability , string $actionPrefix = CapabilityAction::PARAM ) : bool ;
}
