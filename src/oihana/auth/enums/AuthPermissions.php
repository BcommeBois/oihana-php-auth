<?php

namespace oihana\auth\enums ;

use oihana\auth\enums\permissions\traits\MePermissionsTrait;
use oihana\auth\enums\permissions\traits\PoliciesPermissionsTrait;
use oihana\auth\enums\permissions\traits\RolesPermissionsTrait;
use oihana\auth\enums\permissions\traits\ServicesPermissionsTrait;
use oihana\auth\enums\permissions\traits\UsersPermissionsTrait;
use oihana\reflect\traits\ConstantsTrait;

/**
 * Generic registry of every auth permission subject provided by the
 * oihana library (me / users / roles / policies / services).
 *
 * Constants are grouped by resource through dedicated traits — one
 * trait per resource — so the class itself stays flat while source
 * files remain resource-focused. Each trait name is
 * `{Resource}PermissionsTrait` and its constants are prefixed with
 * the resource name (pluralized to match the subject convention,
 * e.g. `USERS_LIST`).
 *
 * An application extends this class to add its own business-specific
 * permissions, so a single class names every subject it uses.
 *
 * Invariant: every constant value is a permission subject. An
 * application that grants it must declare the same subject in its seed
 * of permissions — the application, not this library, holds the seed
 * and the test that keeps the two in step.
 *
 * @package oihana\auth\enums
 * @author  Marc Alcaraz
 */
class AuthPermissions
{
    use ConstantsTrait ,
        MePermissionsTrait ,
        PoliciesPermissionsTrait ,
        RolesPermissionsTrait ,
        ServicesPermissionsTrait ,
        UsersPermissionsTrait ;
}
