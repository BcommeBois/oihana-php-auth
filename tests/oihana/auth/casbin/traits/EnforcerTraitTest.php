<?php

namespace tests\oihana\auth\casbin\traits;

use Casbin\Enforcer;

use DI\Container;

use oihana\auth\casbin\traits\EnforcerTrait;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;

/**
 * Named fixture exposing the trait under test. Declared outside the test class
 * so the trait members are reachable via a regular class reference (PHP 8.2+
 * forbids `TraitName::method`).
 */
class EnforcerTraitFixture
{
    use EnforcerTrait
    {
        initializeEnforcer as public ;
    }

    public function enforcer() : ?Enforcer
    {
        return $this->enforcer ;
    }
}

#[CoversTrait( EnforcerTrait::class )]
class EnforcerTraitTest extends TestCase
{
    /**
     * The enforcer is resolved from the DI container when its id is registered.
     */
    public function testInitializeEnforcerResolvesFromContainer() : void
    {
        $enforcer  = $this->createStub( Enforcer::class ) ;
        $container = new Container() ;
        $container->set( 'enforcer.service' , $enforcer ) ;

        $fixture = new EnforcerTraitFixture() ;
        $result  = $fixture->initializeEnforcer
        (
            [ EnforcerTraitFixture::ENFORCER => 'enforcer.service' ] ,
            $container
        ) ;

        $this->assertSame( $fixture , $result ) ;     // fluent return
        $this->assertSame( $enforcer , $fixture->enforcer() ) ;
    }

    /**
     * With no container and no id, the enforcer falls back to null.
     */
    public function testInitializeEnforcerDefaultsToNull() : void
    {
        $fixture = new EnforcerTraitFixture() ;

        $fixture->initializeEnforcer( [] , null ) ;

        $this->assertNull( $fixture->enforcer() ) ;
    }
}
