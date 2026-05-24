<?php

namespace oihana\auth\enums\permissions\traits ;

/**
 * Permission subjects scoped to the `/me` resource (current user
 * editing their own profile).
 *
 * Grouped in a dedicated trait so the master {@see \oihana\auth\enums\AuthPermissions}
 * class stays flat while source files remain resource-focused. Each constant
 * value must match a `subject` declared in `api/configs/auth-seed.toml` — this
 * invariant is enforced by the permission consistency tests.
 *
 * Note: only constants required from PHP code live here. Subjects that are
 * only referenced from the role mapping in the seed (`me.activities:list`,
 * `me.sessions:delete`, etc.) intentionally remain string-only — typing
 * them is unnecessary until they are read by application code.
 *
 * @package oihana\auth\enums\permissions\traits
 * @author  Marc Alcaraz
 */
trait MePermissionsTrait
{
    /**
     * Allows the currently authenticated user to request a change of
     * their own email address via POST /me/email.
     *
     * Cancellation of a pending change is gated by a separate
     * subject ({@see ME_EMAIL_DELETE}) — the Casbin enforcer matches
     * on (object, action) so a single subject cannot cover both
     * POST and DELETE on a single conceptual resource.
     *
     * The verification step (POST /me/email/confirm) is intentionally
     * NOT gated by this permission — that endpoint is public so the
     * user can validate from a freshly opened mail client without
     * having to log in first. The verification code itself proves
     * possession of the new address.
     *
     * Seeded by default for `admin` + `superadmin`. Not granted to
     * `guest` — same posture as `me:update`.
     */
    public const string ME_EMAIL_UPDATE = 'me.email:update' ;

    /**
     * Allows the currently authenticated user to cancel an in-flight
     * email change via DELETE /me/email/pending.
     *
     * Granted by default to the same roles as {@see ME_EMAIL_UPDATE}
     * — anyone who can request a change must be able to cancel it.
     * Kept as a separate subject so a future use-case where an
     * operator wants to grant request-only or cancel-only access
     * remains possible without breaking the policy seed.
     */
    public const string ME_EMAIL_DELETE = 'me.email:delete' ;

    /**
     * Allows the currently authenticated user to list their own direct
     * permissions through `GET /me/permissions` and gates the
     * `permissions[]` field projection of `GET /me` under `?skin=full`.
     *
     * Same OR-list semantics as {@see ME_ROLES_LIST}. Note this gates
     * the **direct** permissions (USER_HAS_PERMISSIONS edge), not the
     * effective role-inherited ones — those go through
     * `me.permissions.effective:get` on the dedicated endpoint.
     */
    public const string ME_PERMISSIONS_LIST = 'me.permissions:list' ;

    /**
     * Allows the currently authenticated user to list their own roles
     * through `GET /me/roles` and gates the `roles[]` field projection
     * of `GET /me` under `?skin=full`.
     *
     * Used in the `Field::REQUIRES` OR-list of the shared `Models::USERS`
     * model alongside {@see UsersPermissionsTrait::USERS_ROLES_LIST}.
     * For `GET /me` the caller passes the OR check through this subject
     * (granted to every role including `guest` by default); for
     * `GET /users/{id}` admins pass through `users.roles:list`.
     *
     * Seeded by default for every role (guest + admin + superadmin) —
     * users always have the right to inspect their own roles.
     */
    public const string ME_ROLES_LIST = 'me.roles:list' ;

    /**
     * Allows the currently authenticated user to update their own
     * profile via PATCH /me.
     *
     * The endpoint is intentionally narrow: it accepts `givenName` and
     * `familyName` only. `status` is rejected at the validation rule
     * layer (lifecycle changes go through PATCH /users/{id}/status),
     * `email` goes through the dedicated confirmation flow (POST
     * /me/email), `metadata` was retired in favour of typed properties
     * on `User extends Person`. Future sensitive single-field actions
     * (e.g. phone number, avatar) are expected to follow the same
     * pattern as `status` and `email` — a dedicated sub-route per
     * action with its own permission subject — rather than a `FIELDS`
     * capability nested inside this generic PATCH.
     */
    public const string ME_UPDATE = 'me:update' ;
}
