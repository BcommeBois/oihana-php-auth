<?php

namespace oihana\auth\controllers\traits;

/**
 * Facade bundling the full capability enforcement toolkit.
 *
 * Composes six finer-grained traits — use this facade when a controller
 * needs the complete set of primitives. Pick individual traits when only a
 * subset is needed (reduces surface area and documents intent).
 *
 * Composition:
 * - {@see CapabilityContextTrait}     — init + runtime state + private helpers (required by every feature trait).
 * - {@see CapabilityParamTrait}       — `enforceParam()` for enumerated-value params (e.g. `?skin=`).
 * - {@see CapabilityFilterKeysTrait}  — `enforceFilterKeys()` for collection-key params (e.g. `?filter=`).
 * - {@see CapabilityBinaryTrait}      — `hasCapability()` for binary params or manual transversal checks.
 * - {@see CapabilityFieldsTrait}      — `enforceFields()` for body fields of write requests.
 * - {@see CapabilityAuthorizerTrait}  — `buildAuthorizer()` for a request-scoped Closure(string): bool reusable as e.g. an `Arango::AUTHORIZER` callable.
 *
 * Controller opt-in is driven by the `ControllerParam::CAPABILITIES` block
 * in the controller `$init`. Absence of the block means zero check, zero
 * overhead — strict backwards compatibility.
 *
 * @package oihana\auth\controllers\traits
 * @author  Marc Alcaraz
 */
trait CapabilityGuardTrait
{
    use CapabilityAuthorizerTrait ,
        CapabilityBinaryTrait ,
        CapabilityContextTrait ,
        CapabilityFieldsTrait ,
        CapabilityFilterKeysTrait ,
        CapabilityParamTrait ;
}
