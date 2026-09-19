<?php

namespace oihana\auth\enums\permissions\traits ;

/**
 * Permission subjects scoped to the `/services` resource.
 *
 * Grouped in a dedicated trait so the master {@see \oihana\auth\enums\AuthPermissions}
 * class stays flat while source files remain resource-focused. Each constant
 * value must match a `subject` declared in `api/configs/auth-seed.toml` — this
 * invariant is enforced by the permission consistency tests.
 *
 * The `*_LIST` subjects below double as field-level gates for the `?skin=full`
 * projection on `GET /services` and `GET /services/{id}`. They are declared
 * on the `AQL::FIELDS` entries via `Field::REQUIRES`, so a caller lacking
 * the permission receives the service document with the corresponding edge
 * stripped (the `*Count` companion field stays visible regardless, unless
 * explicitly gated).
 *
 * @package oihana\auth\enums\permissions\traits
 * @author  Marc Alcaraz
 */
trait ServicesPermissionsTrait
{
    /**
     * Allows listing services through `GET /services`. The inverse
     * `services[]` projection of a policy is gated by its own subject,
     * {@see PoliciesPermissionsTrait::POLICIES_SERVICES_LIST} : browsing
     * every service and seeing which ones depend on a policy are two
     * separate rights.
     */
    public const string SERVICES_LIST = 'services:list' ;

    /**
     * Allows listing the direct permissions attached to a service
     * through `GET /services/{id}/permissions` and gates the
     * `permissions[]` field projection of `GET /services` and
     * `GET /services/{id}` under `?skin=full`.
     */
    public const string SERVICES_PERMISSIONS_LIST = 'services.permissions:list' ;

    /**
     * Allows reading the effective permissions of a service through
     * `GET /services/{id}/permissions/effective` — the Casbin-deduplicated
     * union of the service's direct permissions and those inherited via
     * its attached policies. Mirrors `users.permissions.effective:get` for
     * Service Accounts (M2M).
     *
     * Granted by default to admin + superadmin only. A service does not
     * self-introspect through this subject — the M2M Bearer token cannot
     * read its own permissions via this route.
     */
    public const string SERVICES_PERMISSIONS_EFFECTIVE_GET = 'services.permissions.effective:get' ;

    /**
     * Allows listing the policies attached to a service through
     * `GET /services/{id}/policies` and gates the `policies[]` field
     * projection of `GET /services` and `GET /services/{id}` under
     * `?skin=full`.
     */
    public const string SERVICES_POLICIES_LIST = 'services.policies:list' ;
}
