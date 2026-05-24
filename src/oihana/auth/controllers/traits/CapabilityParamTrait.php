<?php

namespace oihana\auth\controllers\traits;

use Casbin\Exceptions\CasbinException;

use oihana\auth\enums\Capability;
use oihana\exceptions\http\Error403;

use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Capability enforcement for enumerated-value params (VALUES mapping).
 *
 * Provides {@see self::enforceParam()} for params like `?skin=` where each
 * allowed value is mapped to a permission subject.
 *
 * Requires {@see CapabilityContextTrait} to be `use`d alongside — the
 * consumer must provide the four helpers declared abstract below.
 *
 * @package oihana\auth\controllers\traits
 * @author  Marc Alcaraz
 */
trait CapabilityParamTrait
{
    /**
     * Provided by {@see CapabilityContextTrait::activeParamConfig()}.
     *
     * @return array<array-key,mixed>|null
     */
    abstract protected function activeParamConfig( string $paramName ) : ?array ;

    /**
     * Provided by {@see CapabilityContextTrait::applyCapabilityPolicy()}.
     *
     * @param array<array-key,mixed> $paramConfig
     * @param mixed                  $value
     *
     * @throws Error403 For STRICT policy.
     */
    abstract protected function applyCapabilityPolicy( array $paramConfig , mixed $value ) : mixed ;

    /**
     * Enforce the capability declared under `$paramName` for the given $value.
     *
     * If the value is not mapped, or no capability is declared for this param,
     * returns $value unchanged. Otherwise runs the Casbin check and either
     * returns the value (allowed) or applies the configured policy:
     * - `SILENT_DOWNGRADE` : walks the `Capability::FALLBACKS` cascade if any
     *                       (returns the first granted tier), otherwise falls
     *                       back on `Capability::FALLBACK`.
     * - `STRICT`           : throws {@see Error403}.
     *
     * @param Request|null $request   The current PSR-7 request (null in CLI/tests).
     * @param string       $paramName The controller param, e.g. `ControllerParam::SKIN`.
     * @param mixed        $value     The validated param value.
     *
     * @return mixed The (possibly downgraded) value.
     *
     * @throws Error403      When the policy is STRICT and the cascade is exhausted.
     * @throws CasbinException
     */
    protected function enforceParam( ?Request $request , string $paramName , mixed $value ) : mixed
    {
        $paramConfig = $this->activeParamConfig( $paramName ) ;

        if ( $paramConfig === null )
        {
            return $value ;
        }

        $valuesMap = $paramConfig[ Capability::VALUES ] ?? null ;

        if ( !is_array( $valuesMap ) || ( !is_string( $value ) && !is_int( $value ) ) || !array_key_exists( $value , $valuesMap ) )
        {
            return $value ;
        }

        if ( $this->isCapabilityAllowed( $request , $valuesMap[ $value ] ) )
        {
            return $value ;
        }

        $cascaded = $this->cascadeFallback( $request , $paramConfig , $value , $valuesMap ) ;

        if ( $cascaded !== null )
        {
            return $cascaded ;
        }

        return $this->applyCapabilityPolicy( $paramConfig , $value ) ;
    }

    /**
     * Walk the `Capability::FALLBACKS` chain, returning the first tier that
     * is either ungated (not in `VALUES`) or whose Casbin check succeeds.
     *
     * Cycles are detected through a visited-set ; if the chain loops back
     * onto an already-seen tier, the cascade stops and the caller falls
     * back on the standard policy.
     *
     * @param array<array-key,mixed> $paramConfig
     * @param array<array-key,mixed> $valuesMap
     *
     * @throws CasbinException
     */
    private function cascadeFallback
    (
        ?Request $request     ,
        array    $paramConfig ,
        mixed    $value       ,
        array    $valuesMap   ,
    )
    : mixed
    {
        $fallbacks = $paramConfig[ Capability::FALLBACKS ] ?? null ;

        if ( !is_array( $fallbacks ) )
        {
            return null ;
        }

        $current = $value ;
        $visited = [ $current => true ] ;

        while ( array_key_exists( $current , $fallbacks ) )
        {
            $next = $fallbacks[ $current ] ;

            if ( isset( $visited[ $next ] ) )
            {
                return null ; // cycle detected — bail out and let the policy decide
            }

            $visited[ $next ] = true ;

            // Tier not declared in VALUES → no permission gate, accept it.
            if ( !array_key_exists( $next , $valuesMap ) )
            {
                return $next ;
            }

            if ( $this->isCapabilityAllowed( $request , $valuesMap[ $next ] ) )
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
