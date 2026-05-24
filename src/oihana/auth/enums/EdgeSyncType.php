<?php

namespace oihana\auth\enums;

use oihana\reflect\traits\ConstantsTrait;

/**
 * Edge type identifiers used by {@see \oihana\auth\CasbinPolicySync}
 * to dispatch the appropriate add/remove handler when an authorization
 * edge is inserted or deleted at runtime.
 *
 * Each value names a `(from, to)` vertex pair pattern :
 * `<from-vertex>_<to-vertex>` (singular, no plural / no `_has_`). The
 * value is passed as the second argument to {@see CasbinPolicySync::register()}
 * and matched in `onEdgeInsert` / `onEdgeDelete` to fan out to the
 * correct `add*Policy` / `remove*Policy` method.
 *
 * Kept narrow on purpose : these strings are the wire contract between
 * the DI registration in `casbinSync.php` and the dispatch tables inside
 * the sync class. Adding a new sync flow means adding one constant here
 * and one match arm on each side.
 *
 * @package oihana\auth\enums
 * @author  Marc Alcaraz
 */
class EdgeSyncType
{
    use ConstantsTrait ;

    /**
     * `policy_has_permissions` — permission attached to a policy. Live
     * propagation re-materialises the change on every subject (service,
     * role) currently holding the policy.
     */
    public const string POLICY_PERMISSION = 'policy_permission' ;

    /**
     * `role_has_permissions` — direct permission attached to a role.
     */
    public const string ROLE_PERMISSION = 'role_permission' ;

    /**
     * `role_has_policies` — policy attached to a role (each contained
     * permission materialised on the role identifier so users carrying
     * the role inherit the policy's permissions through Casbin).
     */
    public const string ROLE_POLICY = 'role_policy' ;

    /**
     * `service_has_permissions` — direct permission attached to an M2M service.
     */
    public const string SERVICE_PERMISSION = 'service_permission' ;

    /**
     * `service_has_policies` — policy attached to an M2M service.
     */
    public const string SERVICE_POLICY = 'service_policy' ;

    /**
     * `user_has_permissions` — direct permission attached to a user
     * (bypasses roles).
     */
    public const string USER_PERMISSION = 'user_permission' ;

    /**
     * `user_has_roles` — role grouping attached to a user. Materialised
     * as a Casbin `g` rule (`g, userIdentifier, roleIdentifier, domain`).
     */
    public const string USER_ROLE = 'user_role' ;
}
