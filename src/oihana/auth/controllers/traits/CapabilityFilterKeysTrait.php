<?php

namespace oihana\auth\controllers\traits;

use Casbin\Exceptions\CasbinException;

use oihana\auth\enums\Capability;
use oihana\auth\enums\CapabilityPolicy;
use oihana\exceptions\http\Error403;

use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Capability enforcement for collection-key params (KEYS mapping).
 *
 * Provides {@see self::enforceFilterKeys()} for params like `?filter=` where
 * each clause carries a `key` field (e.g. `{"key":"costPrice","op":"gt","val":100}`)
 * and each sensitive key is mapped to a permission subject.
 *
 * Requires {@see CapabilityContextTrait} to be `use`d alongside — the
 * consumer must provide the two helpers declared abstract below.
 *
 * @package oihana\auth\controllers\traits
 * @author  Marc Alcaraz
 */
trait CapabilityFilterKeysTrait
{
    /**
     * Provided by {@see CapabilityContextTrait::activeParamConfig()}.
     *
     * @return array<array-key,mixed>|null
     */
    abstract protected function activeParamConfig( string $paramName ) : ?array ;

    /**
     * Enforce the capability declared under `$paramName` for each key carried
     * by a `?filter=[{"key":"...", ...}]` payload.
     *
     * Reads the `Capability::KEYS` mapping for the param. For each clause
     * whose `key` is listed and whose Casbin check fails:
     * - If a `Capability::FALLBACKS` chain provides a granted alternative, the
     *   clause's `key` is **substituted** in place (rest of the clause kept
     *   intact: `op`, `val`, `alt`, ...) — useful for graceful precision
     *   downgrades (e.g. `salary` → `salary_range` when only the coarser
     *   permission is granted).
     * - Otherwise, the standard policy applies:
     *   - `SILENT_DOWNGRADE` : the clause is silently dropped from the output.
     *   - `STRICT`           : throws {@see Error403}.
     *
     * Malformed clauses (non-array, missing `key`, non-string key) and keys
     * not listed in the mapping are passed through unchanged. The input
     * shape (single-clause associative vs. list of clauses) is preserved in
     * the output.
     *
     * @param Request|null           $request   The current PSR-7 request (null in CLI/tests).
     * @param string                 $paramName The controller param, e.g. `ControllerParam::FILTER`.
     * @param array<array-key,mixed> $filters   The parsed filter payload from `prepareFilter()`.
     *
     * @return array<array-key,mixed> The (possibly reduced) filter payload.
     *
     * @throws Error403      When the policy is STRICT and a forbidden key is present.
     * @throws CasbinException
     */
    protected function enforceFilterKeys( ?Request $request , string $paramName , array $filters ) : array
    {
        $paramConfig = $this->activeParamConfig( $paramName ) ;

        if ( $paramConfig === null )
        {
            return $filters ;
        }

        $keysMap = $paramConfig[ Capability::KEYS ] ?? null ;

        if ( !is_array( $keysMap ) || $keysMap === [] )
        {
            return $filters ;
        }

        $isList  = array_is_list( $filters ) ;
        $clauses = $isList ? $filters : [ $filters ] ;

        $kept = [] ;

        foreach ( $clauses as $clause )
        {
            if ( !is_array( $clause ) || !isset( $clause[ 'key' ] ) || !is_string( $clause[ 'key' ] ) )
            {
                $kept[] = $clause ;
                continue ;
            }

            $key = $clause[ 'key' ] ;

            if ( !array_key_exists( $key , $keysMap ) )
            {
                $kept[] = $clause ;
                continue ;
            }

            if ( $this->isCapabilityAllowed( $request , $keysMap[ $key ] ) )
            {
                $kept[] = $clause ;
                continue ;
            }

            $cascaded = $this->cascadeFallbackKey( $request , $paramConfig , $key , $keysMap ) ;

            if ( $cascaded !== null )
            {
                $clause[ 'key' ] = $cascaded ;
                $kept[] = $clause ;
                continue ;
            }

            $policy = $paramConfig[ Capability::POLICY ] ?? CapabilityPolicy::SILENT_DOWNGRADE ;

            if ( $policy === CapabilityPolicy::STRICT )
            {
                throw new Error403( sprintf( "Forbidden filter key: '%s'" , $key ) ) ;
            }
        }

        if ( $isList )
        {
            return $kept ;
        }

        $first = $kept[ 0 ] ?? [] ;

        return is_array( $first ) ? $first : [] ;
    }

    /**
     * Walk the `Capability::FALLBACKS` chain for a refused key, returning the
     * first alternative that is either ungated (not in `KEYS`) or whose
     * Casbin check succeeds.
     *
     * Cycles are detected through a visited-set ; malformed entries
     * (non-string targets) and self-loops short-circuit the cascade so the
     * caller falls back on the standard policy.
     *
     * Symmetrical with {@see CapabilityParamTrait::cascadeFallback()} for
     * enumerated-value params — same semantics, different lookup map.
     *
     * @param array<array-key,mixed> $paramConfig
     * @param array<array-key,mixed> $keysMap
     *
     * @return string|null The granted fallback key, or null when the cascade
     *                     is exhausted, malformed, or absent.
     *
     * @throws CasbinException
     */
    private function cascadeFallbackKey
    (
        ?Request $request     ,
        array    $paramConfig ,
        string   $key         ,
        array    $keysMap
    )
    : ?string
    {
        $fallbacks = $paramConfig[ Capability::FALLBACKS ] ?? null ;

        if ( !is_array( $fallbacks ) )
        {
            return null ;
        }

        $current = $key ;
        $visited = [ $current => true ] ;

        while ( array_key_exists( $current , $fallbacks ) )
        {
            $next = $fallbacks[ $current ] ;

            if ( !is_string( $next ) || isset( $visited[ $next ] ) )
            {
                return null ; // malformed entry or cycle — bail out
            }

            $visited[ $next ] = true ;

            // Tier not declared in KEYS → no permission gate, accept it.
            if ( !array_key_exists( $next , $keysMap ) )
            {
                return $next ;
            }

            if ( $this->isCapabilityAllowed( $request , $keysMap[ $next ] ) )
            {
                return $next ;
            }

            $current = $next ;
        }

        return null ;
    }

    /**
     * Provided by {@see CapabilityContextTrait::isCapabilityAllowed()}.
     *
     * @throws CasbinException
     */
    abstract protected function isCapabilityAllowed( ?Request $request , mixed $entry ) : bool ;
}
