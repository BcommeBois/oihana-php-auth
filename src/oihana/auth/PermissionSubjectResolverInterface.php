<?php

namespace oihana\auth;

/**
 * Permission subject resolution contract — backend-agnostic.
 *
 * Resolves a permission subject label (e.g. `roles.permissions:list`) to the
 * `(object, action)` couple actually enforced by the policy engine.
 *
 * The translation step is required because policy engines store permissions
 * as `(user, domain, object, action, effect)` tuples — the human-readable
 * subject label is not carried into the engine. Implementations typically
 * load a `subject → (object, action)` map from a backing store (ArangoDB,
 * OpenEdge, SQL, ...) and cache it.
 *
 * Implementations are expected to be stateless per request beyond their own
 * cache layer, and safe to share as a singleton across the container.
 *
 * @package oihana\auth
 * @author  Marc Alcaraz
 */
interface PermissionSubjectResolverInterface
{
    /**
     * Returns the `(object, action)` couple bound to a permission subject,
     * or `null` when the subject is unknown.
     *
     * @param string $subject The permission subject label, e.g. `roles.permissions:list`.
     *
     * @return array{object: string, action: string}|null
     */
    public function resolve( string $subject ) : ?array ;

    /**
     * Returns the full subject → (object, action) map.
     *
     * Exposed for tests, doctor commands and debug endpoints. Not intended
     * for hot paths — the per-subject {@see self::resolve()} should be
     * preferred since the map grows with the seed.
     *
     * @return array<string, array{object: string, action: string}>
     */
    public function getMap() : array ;
}
