<?php

namespace oihana\auth\enums;

use oihana\reflect\traits\ConstantsTrait;

/**
 * Casbin policy `effect` values as stored on permission documents and
 * materialized in the `rbac` collection.
 *
 * The Casbin policy_effect rule `e = some(allow) && !some(deny)` uses these
 * string values — they must match exactly.
 *
 * @package oihana\auth\enums
 * @author  Marc Alcaraz
 */
class PermissionEffect
{
    use ConstantsTrait ;

    /**
     * Grants access. Default value when `effect` is omitted on a permission.
     */
    public const string ALLOW = 'allow' ;

    /**
     * Blocks access. Overrides any matching `allow` on the same
     * (subject, domain, object, action) tuple per Casbin effect rule.
     */
    public const string DENY = 'deny' ;
}
