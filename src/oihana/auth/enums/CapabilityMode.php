<?php

namespace oihana\auth\enums;

use oihana\reflect\traits\ConstantsTrait;

/**
 * Capability enforcement modes.
 *
 * - `REQUIRE` (allowlist) : the capability is closed by default. A matching
 *                           permission with `effect = allow` opens it for the
 *                           roles that have it.
 * - `DENY`    (denylist)  : the capability is open by default. A matching
 *                           permission with `effect = deny` blocks the roles
 *                           that have it. Other roles keep access.
 *
 * @package oihana\auth\enums
 * @author  Marc Alcaraz
 */
class CapabilityMode
{
    use ConstantsTrait ;

    /**
     * Denylist mode: the user passes the check by default. A permission with
     * `effect = deny` assigned to one of their roles blocks them.
     */
    public const string DENY = 'deny' ;

    /**
     * Allowlist mode: the permission must be present (with `effect = allow`)
     * for the user to pass the check. Used by default when a value is mapped
     * to a bare string in the capabilities config.
     */
    public const string REQUIRE = 'require' ;
}
