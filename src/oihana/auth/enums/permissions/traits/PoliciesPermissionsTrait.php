<?php

namespace oihana\auth\enums\permissions\traits ;

/**
 * Permission subjects scoped to the `/policies` resource.
 *
 * Grouped in a dedicated trait so the master {@see \oihana\auth\enums\AuthPermissions}
 * class stays flat while source files remain resource-focused. Each constant
 * value is a permission subject : an application that grants it must declare
 * the same subject in its seed of permissions.
 *
 * The `*_LIST` subjects below double as field-level gates for the `?skin=full`
 * projection on `GET /policies` and `GET /policies/{id}`. They are declared on
 * the `AQL::FIELDS` entries via `Field::REQUIRES`, so a caller lacking the
 * permission receives the policy document with the corresponding edge stripped
 * (the `*Count` companion field stays visible regardless, unless explicitly
 * gated).
 *
 * The inverse views (`roles[]`, `services[]`) each get their own dedicated
 * subject — same convention as the direct sub-resource subjects (e.g.
 * `roles.permissions:list`).
 *
 * @package oihana\auth\enums\permissions\traits
 * @author  Marc Alcaraz
 */
trait PoliciesPermissionsTrait
{
    /**
     * Allows listing the direct permissions attached to a policy through
     * `GET /policies/{id}/permissions` and gates the `permissions[]` field
     * projection of `GET /policies` and `GET /policies/{id}` under
     * `?skin=full`.
     *
     * Server-side gating: when the caller lacks this permission, the
     * `permissions[]` array is dropped from the response payload even with
     * `?skin=full`. The `permissionsCount` companion field stays exposed so
     * the UI can still surface the cardinality without leaking the items
     * themselves.
     */
    public const string POLICIES_PERMISSIONS_LIST = 'policies.permissions:list' ;

    /**
     * Allows listing the roles that depend on a policy and gates the inverse
     * `roles[]` field projection of `GET /policies` and `GET /policies/{id}`
     * under `?skin=full`. Distinct from the global `roles:list` (browse the
     * whole inventory) — a caller may be allowed to see one without the
     * other (e.g. an auditor inspecting a specific policy's footprint vs.
     * browsing all roles).
     *
     * Also gates the dedicated route that lists those roles
     * (`GET /policies/{id}/roles`), when an application registers one.
     */
    public const string POLICIES_ROLES_LIST = 'policies.roles:list' ;

    /**
     * Allows listing the services that depend on a policy — the services
     * the policy is attached to — and gates the inverse `services[]` field
     * projection of `GET /policies` and `GET /policies/{id}` under
     * `?skin=full`. Distinct from the global `services:list` (browse the
     * whole inventory) — a caller may be allowed to see one without the
     * other (e.g. an auditor checking which clients a policy change would
     * reach vs. browsing every client).
     *
     * Also gates the dedicated route that lists those services
     * (`GET /policies/{id}/services`), when an application registers one.
     */
    public const string POLICIES_SERVICES_LIST = 'policies.services:list' ;
}
