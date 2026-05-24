<?php

namespace oihana\auth\enums;

use oihana\reflect\traits\ConstantsTrait;

/**
 * Capability enforcement policies — decide what happens when the user lacks
 * the required capability.
 *
 * - `SILENT_DOWNGRADE` : replace the forbidden value with the configured `Capability::FALLBACK`,
 *                        let the request continue. UX-friendly, default.
 * - `STRICT`           : reject the request with a 403 Forbidden HTTP status.
 *                       Use when the forbidden value must never leak into the processing pipeline (export, admin-only actions).
 *
 * @package oihana\auth\enums
 * @author  Marc Alcaraz
 */
class CapabilityPolicy
{
    use ConstantsTrait ;

    /**
     * Silently replace the forbidden value by the configured fallback, then
     * proceed with the request.
     */
    public const string SILENT_DOWNGRADE = 'silent_downgrade' ;

    /**
     * Reject the request with an HTTP 403 Forbidden response.
     */
    public const string STRICT = 'strict' ;
}
