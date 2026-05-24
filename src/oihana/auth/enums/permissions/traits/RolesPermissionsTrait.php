<?php

namespace oihana\auth\enums\permissions\traits ;

/**
 * Permission subjects scoped to the `/roles` resource.
 *
 * Grouped in a dedicated trait so the master {@see \oihana\auth\enums\AuthPermissions}
 * class stays flat while source files remain resource-focused. Each constant
 * value must match a `subject` declared in `api/configs/auth-seed.toml` — this
 * invariant is enforced by the permission consistency tests.
 *
 * The `*_LIST` subjects below double as field-level gates for the `?skin=full`
 * projection on `GET /roles` and `GET /roles/{id}`. They are declared on the
 * `AQL::FIELDS` entries via `Field::REQUIRES`, so a caller lacking the
 * permission receives the role document with the corresponding edge stripped
 * (the `*Count` companion field stays visible regardless, unless explicitly
 * gated).
 *
 * @package oihana\auth\enums\permissions\traits
 * @author  Marc Alcaraz
 */
trait RolesPermissionsTrait
{
    /**
     * Allows listing roles through `GET /roles`. Also doubles as the
     * field-level gate for the inverse `roles[]` projection exposed on
     * a parent resource (e.g. `GET /policies/{id}?skin=full`) — same
     * gating semantics, no dedicated sub-resource permission needed.
     */
    public const string ROLES_LIST = 'roles:list' ;

    /**
     * Allows listing the direct permissions attached to a role through
     * `GET /roles/{id}/permissions` and gates the `permissions[]` field
     * projection of `GET /roles` and `GET /roles/{id}` under `?skin=full`.
     *
     * Server-side gating: when the caller lacks this permission, the
     * `permissions[]` array is dropped from the response payload even
     * with `?skin=full`. The `permissionsCount` companion field remains
     * exposed so the UI can still surface the cardinality without leaking
     * the items themselves.
     */
    public const string ROLES_PERMISSIONS_LIST = 'roles.permissions:list' ;

    /**
     * Allows listing the policies attached to a role through
     * `GET /roles/{id}/policies` and gates the `policies[]` field
     * projection of `GET /roles` and `GET /roles/{id}` under `?skin=full`.
     *
     * Same field-level gating semantics as {@see ROLES_PERMISSIONS_LIST} —
     * `policies[]` is stripped when the caller lacks the permission, while
     * `policiesCount` remains visible.
     */
    public const string ROLES_POLICIES_LIST = 'roles.policies:list' ;
}
