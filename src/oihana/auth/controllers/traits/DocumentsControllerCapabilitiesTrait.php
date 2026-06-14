<?php

namespace oihana\auth\controllers\traits;

use Casbin\Exceptions\CasbinException;

use oihana\controllers\enums\ControllerParam;
use oihana\controllers\traits\prepare\PrepareFilter;
use oihana\controllers\traits\prepare\PrepareSearch;
use oihana\controllers\traits\prepare\PrepareSkin;
use oihana\exceptions\http\Error403;

use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Bundles the capability-aware overrides that a `DocumentsController` (Arango,
 * OpenEdge, ...) must apply on top of the standard `PrepareXxx` chain.
 *
 * The trait composes:
 * - {@see CapabilityGuardTrait} — the enforceParam / enforceFilterKeys /
 *   hasCapability primitives + `initializeCapabilities()` lifecycle.
 * - {@see PrepareFilter}        — the vendor filter-resolution logic, aliased
 *   as `prepareFilterBase()`.
 * - {@see PrepareSearch}        — the vendor search-resolution logic, aliased
 *   as `prepareSearchBase()`.
 * - {@see PrepareSkin}          — the vendor skin-resolution logic, aliased
 *   as `prepareSkinBase()`.
 *
 * Overrides:
 * - {@see self::prepareFilter()} — runs `prepareFilterBase()` then delegates to
 *   `enforceFilterKeys()` to drop forbidden clauses (SILENT_DOWNGRADE) or
 *   throw (STRICT). Re-encodes the registered `$params` when the payload
 *   shrinks so bench/cache layers reflect the effective filter.
 * - {@see self::prepareSearch()} — runs `prepareSearchBase()` then, when the
 *   query param is non-empty, delegates to `hasCapability()` with
 *   `ControllerParam::SEARCH`. A disallowed search is silently cleared
 *   (SILENT_DOWNGRADE) or rejected (STRICT).
 * - {@see self::prepareSkin()}   — runs `prepareSkinBase()` then delegates to
 *   `enforceParam()` with the resolved skin. Updates `$params` when the
 *   value is silently downgraded.
 *
 * A consumer controller must also `use` its regular `DocumentsController*Trait`
 * chain and resolve the trait conflicts on `prepareSkin` / `prepareFilter` /
 * `prepareSearch` with `insteadof`:
 *
 * ```php
 * use DocumentsControllerCapabilitiesTrait ,
 *     DocumentsControllerListTrait ,
 *     ...
 *     {
 *     DocumentsControllerCapabilitiesTrait::prepareSkin   insteadof DocumentsControllerListTrait , ... ;
 *     DocumentsControllerCapabilitiesTrait::prepareFilter insteadof DocumentsControllerListTrait , ... ;
 *     DocumentsControllerCapabilitiesTrait::prepareSearch insteadof DocumentsControllerListTrait , ... ;
 * }
 * ```
 *
 * @package oihana\auth\controllers\traits
 * @author  Marc Alcaraz
 */
trait DocumentsControllerCapabilitiesTrait
{
    use CapabilityGuardTrait ,
        PrepareFilter ,
        PrepareSearch ,
        PrepareSkin
    {
        PrepareFilter::prepareFilter as protected prepareFilterBase ;
        PrepareSearch::prepareSearch as protected prepareSearchBase ;
        PrepareSkin::prepareSkin     as protected prepareSkinBase ;
    }

    /**
     * Capability-aware override of {@see PrepareFilter::prepareFilter}.
     *
     * Resolves the filter payload through the standard validation, then
     * applies the capability check declared under `ControllerParam::FILTER`
     * in the CAPABILITIES block (if any). Forbidden clauses are dropped
     * silently (SILENT_DOWNGRADE) or the request is rejected (STRICT).
     *
     * When the payload shrinks, `$params[ControllerParam::FILTER]` is
     * re-encoded to JSON so bench/cache layers reflect the effective filter.
     *
     * @param Request|null               $request
     * @param array<array-key,mixed>     $args
     * @param array<array-key,mixed>|null $params
     *
     * @return array<array-key,mixed>|null
     *
     * @throws CasbinException
     * @throws Error403
     */
    protected function prepareFilter( ?Request $request , array $args = [] , ?array &$params = null ) : ?array
    {
        $filters = $this->prepareFilterBase( $request , $args , $params ) ;

        if ( !is_array( $filters ) )
        {
            return null;
        }

        $enforced = $this->enforceFilterKeys( $request , ControllerParam::FILTER , $filters ) ;

        if ( $enforced !== $filters && is_array( $params ) && array_key_exists( ControllerParam::FILTER , $params ) )
        {
            $encoded = json_encode( $enforced ) ;
            $params[ ControllerParam::FILTER ] = $encoded !== false ? $encoded : $params[ ControllerParam::FILTER ] ;
        }

        return $enforced ;
    }

    /**
     * Capability-aware override of {@see PrepareSearch::prepareSearch}.
     *
     * Resolves the search string through the standard validation. When the
     * query param carries a non-empty value and a capability is declared
     * under `ControllerParam::SEARCH`, delegates to `hasCapability()`. A
     * disallowed search is cleared to the configured fallback (typically
     * `null`) under SILENT_DOWNGRADE, or rejected with {@see Error403} under
     * STRICT.
     *
     * Updates `$params[ControllerParam::SEARCH]` when the effective value
     * differs from the requested one.
     *
     * @param Request|null               $request
     * @param array<array-key,mixed>     $args
     * @param array<array-key,mixed>|null $params
     *
     * @return string|null
     *
     * @throws CasbinException
     * @throws Error403
     */
    protected function prepareSearch( ?Request $request , array $args = [] , ?array &$params = null ) : ?string
    {
        $search = $this->prepareSearchBase( $request , $args , $params ) ;

        if ( !is_string( $search ) || $search === '' )
        {
            return $search ;
        }

        if ( $this->hasCapability( $request , ControllerParam::SEARCH ) )
        {
            return $search ;
        }

        // Reaching here means hasCapability() returned false, which only happens
        // when a SEARCH capability is declared — so the param config is present.
        $paramConfig = $this->activeParamConfig( ControllerParam::SEARCH ) ?? [] ;

        $fallback = $this->applyCapabilityPolicy( $paramConfig , $search ) ;
        $effective = is_string( $fallback ) ? $fallback : null ;

        if ( $effective !== $search && is_array( $params ) && array_key_exists( ControllerParam::SEARCH , $params ) )
        {
            $params[ ControllerParam::SEARCH ] = $effective ;
        }

        return $effective ;
    }

    /**
     * Capability-aware override of {@see PrepareSkin::prepareSkin}.
     *
     * Resolves the skin through the standard validation, then applies the
     * capability check declared under `ControllerParam::SKIN` in the
     * CAPABILITIES block (if any). When the skin is downgraded and the base
     * method had registered it in `$params`, the registered value is updated
     * so bench/cache layers reflect the effective skin.
     *
     * @param Request|null             $request
     * @param array<string,mixed>      $init
     * @param array<string,mixed>|null $params
     * @param string|null              $method
     *
     * @return string|null
     *
     * @throws CasbinException
     * @throws Error403
     */
    protected function prepareSkin( ?Request $request = null , array $init = [] , ?array &$params = null , ?string $method = null ) : ?string
    {
        $skin     = $this->prepareSkinBase( $request , $init , $params , $method ) ;
        $enforced = $this->enforceParam( $request , ControllerParam::SKIN , $skin ) ;

        $effective = is_string( $enforced ) ? $enforced : null ;

        if ( $effective !== $skin && is_array( $params ) && array_key_exists( ControllerParam::SKIN , $params ) )
        {
            $params[ ControllerParam::SKIN ] = $effective ;
        }

        return $effective ;
    }
}
