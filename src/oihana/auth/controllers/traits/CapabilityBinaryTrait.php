<?php

namespace oihana\auth\controllers\traits;

use Casbin\Exceptions\CasbinException;

use oihana\auth\enums\Capability;

use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Capability enforcement for binary params or transversal actions
 * (SUBJECT only, no VALUES / no KEYS).
 *
 * Provides {@see self::hasCapability()} for params like `?search=`, `?bench=`
 * or manual transversal checks (`export`, `import`) where the config entry
 * carries only a {@see Capability::SUBJECT}.
 *
 * Requires {@see CapabilityContextTrait} to be `use`d alongside — the
 * consumer must provide the two helpers declared abstract below.
 *
 * @package oihana\auth\controllers\traits
 * @author  Marc Alcaraz
 */
trait CapabilityBinaryTrait
{
    /**
     * Provided by {@see CapabilityContextTrait::activeParamConfig()}.
     *
     * @return array<array-key,mixed>|null
     */
    abstract protected function activeParamConfig( string $paramName ) : ?array ;

    /**
     * Boolean check for a SUBJECT-only capability declared under `$paramName`.
     *
     * @param Request|null $request
     * @param string       $paramName
     *
     * @return bool True when the user is allowed — including the no-op cases
     *              (no config, disabled, no enforcer).
     *
     * @throws CasbinException
     */
    protected function hasCapability( ?Request $request , string $paramName ) : bool
    {
        $paramConfig = $this->activeParamConfig( $paramName ) ;

        if ( $paramConfig === null )
        {
            return true ;
        }

        $subject = $paramConfig[ Capability::SUBJECT ] ?? null ;

        if ( !is_string( $subject ) )
        {
            return true ;
        }

        return $this->isCapabilityAllowed( $request , $subject ) ;
    }

    /**
     * Provided by {@see CapabilityContextTrait::isCapabilityAllowed()}.
     *
     * @throws CasbinException
     */
    abstract protected function isCapabilityAllowed( ?Request $request , mixed $entry ) : bool ;
}
