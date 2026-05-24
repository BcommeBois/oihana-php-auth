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
 * Projects extend this class to add their own business-specific
 * permissions (see `fr\bouney\enums\Permissions`).
 *
 * Invariant: every constant value must correspond to a
 * `[[permissions]].subject` declared in the relevant seed TOML
 * (`auth-seed.toml` for entries defined here, project seeds for
 * extending classes). The `AuthSeedTest` / `BusinessSeedTest`
 * suites enforce this at build time.
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
