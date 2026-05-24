<?php

namespace oihana\auth\enums;

use oihana\reflect\traits\ConstantsTrait;

/**
 * Configuration keys for the controller `CAPABILITIES` block.
 *
 * A capabilities block lives inside a `DocumentsController` definition under
 * `ControllerParam::CAPABILITIES` and maps param names (`skin`, `filter`, ...)
 * to a per-param configuration. Each per-param config uses the constants
 * below.
 *
 * Example — gate `?skin=offers.full` on `/products`:
 *
 * ```php
 * ControllerParam::CAPABILITIES =>
 * [
 *     Capability::OBJECT    => '/products' ,
 *     ControllerParam::SKIN =>
 *     [
 *         Capability::POLICY   => CapabilityPolicy::SILENT_DOWNGRADE ,
 *         Capability::FALLBACK => Skin::OFFERS ,
 *         Capability::VALUES   =>
 *         [
 *             Skin::OFFERS_FULL => 'products:skin.offers.full' ,                        // REQUIRE shortcut
 *             Skin::SPECIAL     => [ Capability::DENY => 'products:skin.special' ] ,    // DENY long form
 *         ],
 *     ],
 * ],
 * ```
 *
 * @package oihana\auth\enums
 * @author  Marc Alcaraz
 */
class Capability
{
    use ConstantsTrait ;

    /**
     * Long-form mode marker — denylist semantics.
     *
     * Usage: `[ Capability::DENY => 'products:skin.special' ]`.
     */
    public const string DENY = 'deny' ;

    /**
     * Configuration block for body field gating (PATCH / POST / PUT).
     *
     * Lives at the same level as `ControllerParam::SKIN` / `ControllerParam::FILTER`
     * inside the `CAPABILITIES` block. The block accepts a `POLICY` and a
     * `VALUES` mapping where each entry is `permission => field(s)` — read
     * "this permission grants the right to write these fields in the body".
     * Same field can be listed under several permissions (the gate accepts
     * the request as long as the caller holds at least one of them).
     */
    public const string FIELDS = 'fields' ;

    /**
     * Fallback value to substitute when the user fails the check under the
     * `SILENT_DOWNGRADE` policy. Typically the default value for the param
     * (e.g. `Skin::DEFAULT` or `Skin::OFFERS`).
     */
    public const string FALLBACK = 'fallback' ;

    /**
     * Optional cascade table — `[ value => nextValue ]`.
     *
     * When the active value fails its capability check under the
     * `SILENT_DOWNGRADE` policy, the trait walks the chain step by step
     * and returns the first value that either is not gated or whose
     * permission check succeeds. Cycles are detected and short-circuited.
     *
     * If the cascade is exhausted, the trait falls back on the
     * single `Capability::FALLBACK` (or throws under `STRICT`).
     */
    public const string FALLBACKS = 'fallbacks' ;

    /**
     * Mapping `key => subject` for collection-style params (e.g. `filter`,
     * `sort`, `groupBy`). Same entry shape as {@see self::VALUES}.
     *
     * Keys not listed are left unchecked.
     */
    public const string KEYS = 'keys' ;

    /**
     * Route scope shared by every capability in the CAPABILITIES block.
     *
     * Corresponds to the Casbin `object` field of the matching permissions
     * (e.g. `/products`). Typically the base path of the controller.
     */
    public const string OBJECT = 'object' ;

    /**
     * Enforcement policy for this param. Value must be one of the
     * {@see CapabilityPolicy} constants. Default: `SILENT_DOWNGRADE`.
     */
    public const string POLICY = 'policy' ;

    /**
     * Long-form mode marker — allowlist semantics.
     *
     * Usage: `[ Capability::REQUIRE => 'products:skin.offers.full' ]`.
     */
    public const string REQUIRE = 'require' ;

    /**
     * Permission subject for binary params (e.g. `search`, `bench`) or for
     * transversal capabilities checked manually via `hasCapability()`
     * (e.g. `export`, `import`).
     */
    public const string SUBJECT = 'subject' ;

    /**
     * Mapping `value => subject` for enumerated-value params (e.g. `skin`).
     *
     * The map entry value can be:
     * - a bare string `'products:skin.offers.full'` — equivalent to
     *   `[ Capability::REQUIRE => '...' ]` (shortcut for the common case),
     * - an array `[ Capability::REQUIRE => '...' ]` or
     *   `[ Capability::DENY => '...' ]` when the mode must be explicit.
     *
     * Values not listed in this map are left unchecked (open access).
     */
    public const string VALUES = 'values' ;
}
