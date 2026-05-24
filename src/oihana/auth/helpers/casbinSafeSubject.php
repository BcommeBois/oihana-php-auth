<?php

namespace oihana\auth\helpers ;

/**
 * Normalises a Casbin subject so it never collides with PHP's silent
 * coercion of purely numeric array keys to `int`.
 *
 * Zitadel identifiers are purely numeric strings (e.g.
 * `364646423545321675`). Casbin uses `array<string, ...>` internally —
 * but PHP coerces purely numeric string keys to `int` in associative
 * arrays. Result : if a row is written with `n_xxx` and read with `xxx`,
 * the lookup silently returns `[]` and the policy check fails without
 * any error. This helper prefixes purely numeric subjects with `n_` to
 * keep them unambiguously string.
 *
 * **Must be applied on every subject crossing the Casbin boundary**,
 * both on read paths (`enforce`, `getImplicitPermissionsForUser`,
 * `getRolesForUserInDomain`, …) and on write paths (`addPolicy`,
 * `removePolicy`, `addGroupingPolicy`, `removeGroupingPolicy`,
 * `deleteRole`).
 *
 * Idempotent : calling it twice on the same subject yields the same
 * result (a previously prefixed `n_xxx` is not numeric so it passes
 * through untouched).
 *
 * @param string $subject Raw subject (Zitadel identifier, role key,
 *                        namespaced `service:{_key}`, …).
 *
 * @return string Safe subject — guaranteed never purely numeric.
 *
 * @example
 * ```php
 * casbinSafeSubject( '364646423545321675' ) ; // 'n_364646423545321675'
 * casbinSafeSubject( 'role_42' )              ; // 'role_42'
 * casbinSafeSubject( 'service:abc123' )       ; // 'service:abc123'
 * casbinSafeSubject( 'n_364646423545321675' ) ; // 'n_364646423545321675' (idempotent)
 * ```
 *
 * @see docs/fr/auth/tips.md For the canonical authoring rule.
 *
 * @author  Marc Alcaraz
 * @package oihana\auth\helpers
 */
function casbinSafeSubject( string $subject ) :string
{
    return ctype_digit( $subject ) ? 'n_' . $subject : $subject ;
}
