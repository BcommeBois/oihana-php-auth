<?php

namespace oihana\auth\enums;

use oihana\reflect\traits\ConstantsTrait;

/**
 * Reserved `action` values for capability-based permissions.
 *
 * Extends the default HTTP-verb vocabulary (`GET`, `POST`, `PATCH`, ...) with
 * non-HTTP categories. Capability permissions store their discriminator as an
 * action string prefixed by one of these categories, e.g. `PARAM:skin.offers.full`.
 *
 * - `PARAM`   : capability on a query parameter or a cross-route route capability,
 *               enforced inside controllers.
 * - `FIELDS`  : capability on the body of a write request (PATCH/POST/PUT) —
 *               gates which fields the caller is allowed to send.
 * - `FEATURE` : reserved for pure UI capabilities (not bound to any endpoint) —
 *               client-side only, not yet enforced server-side.
 *
 * @package oihana\auth\enums
 * @author  Marc Alcaraz
 */
class CapabilityAction
{
    use ConstantsTrait ;

    /**
     * Reserved for pure UI capabilities, not tied to any endpoint. Not
     * implemented server-side — consumed by the client to gate menus/buttons.
     */
    public const string FEATURE = 'FEATURE' ;

    /**
     * Capability on body fields of a write request (PATCH / POST / PUT).
     * Permissions store their discriminator as `FIELDS:<group>.<action>`,
     * e.g. `FIELDS:status.update` for the right to change `user.status`.
     * Enforced inside controllers, before the payload is validated.
     */
    public const string FIELDS = 'FIELDS' ;

    /**
     * Capability on a query parameter value (ex: `?skin=offers.full`) or a
     * cross-route capability (ex: `export`). Enforced in the controller, before
     * the parameter is consumed.
     */
    public const string PARAM = 'PARAM' ;
}
