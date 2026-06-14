<?php

namespace tests\oihana\auth\controllers\traits;

use Casbin\Exceptions\CasbinException;

use oihana\auth\casbin\CapabilityEnforcer;
use oihana\auth\PermissionSubjectResolverInterface;
use oihana\auth\controllers\traits\PermissionAuthorizerTrait;
use oihana\enums\http\RequestAttribute;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;

use Slim\Psr7\Factory\ServerRequestFactory;

/**
 * Concrete fixture exposing the trait under test publicly so the test
 * methods can drive `buildPermissionAuthorizer` and
 * `initializePermissionSubjectResolver` directly. PHP 8.2+ forbids
 * referencing trait constants through the trait name, so the fixture
 * also provides a stable consumer class for any future const access.
 */
final class PermissionAuthorizerTraitFixture
{
    use PermissionAuthorizerTrait ;

    public ?CapabilityEnforcer $capabilityEnforcer = null ;

    public function setEnforcer( ?CapabilityEnforcer $enforcer ) : void
    {
        $this->capabilityEnforcer = $enforcer ;
    }

    public function build( $request )
    {
        return $this->buildPermissionAuthorizer( $request ) ;
    }

    public function bindResolver( ?PermissionSubjectResolverInterface $resolver ) : void
    {
        $this->initializePermissionSubjectResolver( $resolver ) ;
    }
}

#[CoversTrait( PermissionAuthorizerTrait::class )]
#[AllowMockObjectsWithoutExpectations]
final class PermissionAuthorizerTraitTest extends TestCase
{
    private function makeRequest( ?string $userId = '123' )
    {
        $request = new ServerRequestFactory()->createServerRequest( 'GET' , '/roles' ) ;

        if ( $userId !== null )
        {
            $request = $request->withAttribute( RequestAttribute::USER_ID , $userId ) ;
        }

        return $request ;
    }

    private function makeEnforcer( bool $verdict , bool $shouldThrow = false ) : CapabilityEnforcer
    {
        $enforcer = $this->getMockBuilder( CapabilityEnforcer::class )
            ->disableOriginalConstructor()
            ->onlyMethods([ 'enforceObjectAction' ])
            ->getMock() ;

        if ( $shouldThrow )
        {
            $enforcer->method( 'enforceObjectAction' )->willThrowException( new CasbinException( 'boom' ) ) ;
        }
        else
        {
            $enforcer->method( 'enforceObjectAction' )->willReturn( $verdict ) ;
        }

        return $enforcer ;
    }

    private function makeResolver( array $map ) : PermissionSubjectResolverInterface
    {
        $resolver = $this->getMockBuilder( PermissionSubjectResolverInterface::class )
            ->onlyMethods([ 'resolve' , 'getMap' ])
            ->getMock() ;

        $resolver->method( 'resolve' )->willReturnCallback( fn( string $s ) => $map[ $s ] ?? null ) ;

        return $resolver ;
    }

    public function testReturnsNullWhenNoEnforcer() : void
    {
        $fixture = new PermissionAuthorizerTraitFixture() ;
        $fixture->bindResolver( $this->makeResolver([]) ) ;

        $this->assertNull( $fixture->build( $this->makeRequest() ) ) ;
    }

    public function testReturnsNullWhenNoResolver() : void
    {
        $fixture = new PermissionAuthorizerTraitFixture() ;
        $fixture->setEnforcer( $this->makeEnforcer( true ) ) ;
        // No resolver bound.
        $this->assertNull( $fixture->build( $this->makeRequest() ) ) ;
    }

    public function testReturnsNullWhenNoRequest() : void
    {
        $fixture = new PermissionAuthorizerTraitFixture() ;
        $fixture->setEnforcer( $this->makeEnforcer( true ) ) ;
        $fixture->bindResolver( $this->makeResolver([]) ) ;

        $this->assertNull( $fixture->build( null ) ) ;
    }

    public function testReturnsNullWhenNoUserAttribute() : void
    {
        $fixture = new PermissionAuthorizerTraitFixture() ;
        $fixture->setEnforcer( $this->makeEnforcer( true ) ) ;
        $fixture->bindResolver( $this->makeResolver([]) ) ;

        $this->assertNull( $fixture->build( $this->makeRequest( null ) ) ) ;
    }

    public function testClosureReturnsFalseForUnknownSubject() : void
    {
        $fixture = new PermissionAuthorizerTraitFixture() ;
        $fixture->setEnforcer( $this->makeEnforcer( true ) ) ;
        $fixture->bindResolver( $this->makeResolver([]) ) ;

        $closure = $fixture->build( $this->makeRequest() ) ;
        $this->assertNotNull( $closure ) ;

        $this->assertFalse( $closure( 'subject.does.not:exist' ) ) ;
    }

    public function testClosureForwardsToEnforcerWhenSubjectKnown() : void
    {
        $fixture = new PermissionAuthorizerTraitFixture() ;
        $fixture->setEnforcer( $this->makeEnforcer( true ) ) ;
        $fixture->bindResolver( $this->makeResolver
        ([
            'roles.permissions:list' => [ 'object' => '/roles/:id/permissions' , 'action' => 'GET' ] ,
        ]) ) ;

        $closure = $fixture->build( $this->makeRequest() ) ;
        $this->assertNotNull( $closure ) ;

        $this->assertTrue( $closure( 'roles.permissions:list' ) ) ;
    }

    public function testClosurePropagatesEnforcerVerdict() : void
    {
        $fixture = new PermissionAuthorizerTraitFixture() ;
        $fixture->setEnforcer( $this->makeEnforcer( false ) ) ;
        $fixture->bindResolver( $this->makeResolver
        ([
            'roles.permissions:list' => [ 'object' => '/roles/:id/permissions' , 'action' => 'GET' ] ,
        ]) ) ;

        $closure = $fixture->build( $this->makeRequest() ) ;

        $this->assertFalse( $closure( 'roles.permissions:list' ) ) ;
    }

    public function testClosureFailsClosedOnCasbinException() : void
    {
        $fixture = new PermissionAuthorizerTraitFixture() ;
        $fixture->setEnforcer( $this->makeEnforcer( true , shouldThrow: true ) ) ;
        $fixture->bindResolver( $this->makeResolver
        ([
            'roles.permissions:list' => [ 'object' => '/roles/:id/permissions' , 'action' => 'GET' ] ,
        ]) ) ;

        $closure = $fixture->build( $this->makeRequest() ) ;

        $this->assertFalse( $closure( 'roles.permissions:list' ) ) ;
    }
}
