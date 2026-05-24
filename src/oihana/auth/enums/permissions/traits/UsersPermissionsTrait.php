<?php

namespace oihana\auth\enums\permissions\traits ;

/**
 * Permission subjects scoped to the `/users` resource.
 *
 * Grouped in a dedicated trait so the master {@see \oihana\auth\enums\AuthPermissions}
 * class stays flat while source files remain resource-focused. Each constant
 * value must match a `subject` declared in `api/configs/auth-seed.toml` — this
 * invariant is enforced by the permission consistency tests.
 *
 * @package oihana\auth\enums\permissions\traits
 * @author  Marc Alcaraz
 */
trait UsersPermissionsTrait
{
    /**
     * Allows listing the direct roles attached to a user through
     * `GET /users/{id}/roles` and gates the `roles[]` field projection
     * of `GET /users` and `GET /users/{id}` under `?skin=full`.
     *
     * Server-side gating: when the caller lacks this permission, the
     * `roles[]` array is dropped from the response payload even with
     * `?skin=full`. The `rolesCount` companion field stays exposed so
     * the UI can still surface the cardinality without leaking the
     * items themselves.
     */
    public const string USERS_ROLES_LIST = 'users.roles:list' ;

    /**
     * Allows listing the direct permissions attached to a user through
     * `GET /users/{id}/permissions` and gates the `permissions[]` field
     * projection of `GET /users` and `GET /users/{id}` under `?skin=full`.
     *
     * Same field-level gating semantics as {@see USERS_ROLES_LIST} —
     * `permissions[]` is stripped when the caller lacks the permission,
     * while `permissionsCount` remains visible.
     */
    public const string USERS_PERMISSIONS_LIST = 'users.permissions:list' ;

    /**
     * Allows reading the effective permissions of a user through
     * `GET /users/{id}/permissions/effective` — the Casbin-deduplicated
     * union of the user's direct permissions and those inherited via
     * their roles.
     *
     * Granted by default to admin + superadmin. The `me.permissions.effective:get`
     * counterpart covers the self-introspection case.
     */
    public const string USERS_PERMISSIONS_EFFECTIVE_GET = 'users.permissions.effective:get' ;

    /**
     * Bypass the strict role-level hierarchy rule on PATCH / DELETE
     * `/users/{id}`. When granted, the caller can mutate users whose
     * maximum role level is greater than or equal to their own.
     *
     * Gated by the `users:bypass.level.hierarchy` subject, typed as a
     * `PARAM:bypass.level.hierarchy` Casbin action. Reserved for
     * service / compliance accounts ; not granted to any role by
     * default, including `superadmin`. Two superadmins therefore
     * cannot mutate each other unless one is explicitly granted this
     * bypass — by design, the strict hierarchy rule is a security
     * invariant, the bypass is an audited escape hatch.
     *
     * @see \oihana\api\controllers\auth\traits\LevelHierarchyGuardTrait
     */
    public const string USERS_BYPASS_LEVEL_HIERARCHY = 'users:bypass.level.hierarchy' ;

    /**
     * Allows reading the lifecycle status of a user through the
     * dedicated route `GET /users/{id}/status`.
     *
     * Standard HTTP-level permission (object = route path, action =
     * `GET`). Seeded for `admin` + `superadmin`. The full document
     * variant (`GET /users/{id}` with `users:get`) also exposes the
     * `status` field, so this permission acts more as a fine-grained
     * companion than a hard wall — it lets an operator grant
     * status-only visibility without leaking the rest of the user
     * record, if a future role calls for it.
     */
    public const string USERS_STATUS_GET = 'users.status:get' ;

    /**
     * Allows changing the lifecycle status of a user through the
     * dedicated route `PATCH /users/{id}/status`.
     *
     * Standard HTTP-level permission (object = route path, action =
     * `PATCH`). Seeded for `admin` + `superadmin`. The controller
     * enforces level hierarchy, superadmin immutability, an
     * anti-lockout rule (no self-edit) and a session revocation
     * cascade on `active → disabled`.
     */
    public const string USERS_STATUS_UPDATE = 'users.status:update' ;

    /**
     * Allows an administrator to request an email change for any
     * other user via POST /users/{id}/email.
     *
     * Cancellation of a pending change is gated by a separate
     * subject ({@see USERS_EMAIL_DELETE}) — the Casbin enforcer
     * matches on (object, action) so a single subject cannot cover
     * both POST and DELETE on a single conceptual resource.
     *
     * Typical use case : a user has lost access to their previous
     * inbox and asks the administrator to start the change on their
     * behalf. Even with this permission, the admin cannot validate
     * the change directly — the verification mail is sent to the new
     * address and the legitimate user must click the link, which
     * acts as a built-in anti-hijack guard.
     *
     * Seeded by default for `admin` + `superadmin` (kept aligned with
     * `users:update` since the admin already controls the user record).
     */
    public const string USERS_EMAIL_UPDATE = 'users.email:update' ;

    /**
     * Allows an administrator to cancel an in-flight email change
     * for any other user via DELETE /users/{id}/email/pending.
     *
     * Granted by default to the same roles as {@see USERS_EMAIL_UPDATE}
     * — anyone who can request a change must be able to cancel it.
     * Kept as a separate subject so a future use-case where an
     * operator wants to grant request-only or cancel-only access
     * remains possible without breaking the policy seed.
     */
    public const string USERS_EMAIL_DELETE = 'users.email:delete' ;
}
