<?php

namespace oihana\auth\casbin\traits;

use Casbin\Enforcer;

use DI\Container;

use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

use function oihana\controllers\helpers\resolveDependency;

/**
 * Standalone trait for the Casbin {@see Enforcer} dependency.
 *
 * Used by middlewares / controllers / auth traits that need to
 * evaluate Casbin policies (authorization checks, effective-permission
 * lookups, policy-attachment validation, etc.). Composable on its own.
 *
 * @package oihana\auth\casbin\traits
 * @author  Marc Alcaraz
 */
trait EnforcerTrait
{
    /**
     * Initialization key for the Casbin Enforcer dependency.
     */
    public const string ENFORCER = 'enforcer' ;

    /**
     * The Casbin Enforcer reference.
     */
    protected ?Enforcer $enforcer = null ;

    /**
     * Initializes the Casbin enforcer dependency from the $init array.
     *
     * @param array $init The initialization array.
     * @param Container|null $container The DI container.
     *
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     *
     * @return static
     */
    protected function initializeEnforcer( array $init , ?Container $container ) :static
    {
        $this->enforcer = resolveDependency( $init[ self::ENFORCER ] ?? null , $container ) ;
        return $this ;
    }
}
