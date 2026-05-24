<?php

namespace tests\oihana\auth\controllers\traits;

use Casbin\Enforcer;
use Closure;

use PHPUnit\Framework\TestCase;

use oihana\auth\casbin\CapabilityEnforcer;
use oihana\auth\controllers\traits\CapabilityAuthorizerTrait;
use oihana\enums\http\RequestAttribute;

use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Named consumer fixture exposing the protected trait surface and the two
 * properties the trait expects to find on `CapabilityContextTrait` consumers
 * (`$capabilityEnforcer`, `$capabilityObject`). Avoids depending on the
 * full `CapabilityContextTrait` initialisation pipeline.
 */
final class CapabilityAuthorizerTraitFixture
{
    use CapabilityAuthorizerTrait ;

    public ?CapabilityEnforcer $capabilityEnforcer = null ;
    public string              $capabilityObject   = '' ;

    public function callBuildAuthorizer( ?Request $request ) : ?Closure
    {
        return $this->buildAuthorizer( $request ) ;
    }
}

final class CapabilityAuthorizerTraitTest extends TestCase
{
    private const string OBJECT      = '/users' ;
    private const string DOMAIN      = 'bouney-api' ;
    private const string ALPHA_ID    = 'alice' ;
    private const string NUMERIC_ID  = '364646423545321675' ;
    private const string SAFE_NUMERIC = 'n_364646423545321675' ;

    public function testReturnsNullWhenEnforcerIsMissing() : void
    {
        $fixture = new CapabilityAuthorizerTraitFixture() ;
        $request = $this->createStub( Request::class ) ;

        $this->assertNull( $fixture->callBuildAuthorizer( $request ) ) ;
    }

    public function testReturnsNullWhenRequestIsNull() : void
    {
        $fixture = $this->makeFixture() ;

        $this->assertNull( $fixture->callBuildAuthorizer( null ) ) ;
    }

    public function testReturnsNullWhenUserIdAttributeMissing() : void
    {
        $fixture = $this->makeFixture() ;
        $request = $this->createStub( Request::class ) ;
        $request->method( 'getAttribute' )->willReturn( null ) ;

        $this->assertNull( $fixture->callBuildAuthorizer( $request ) ) ;
    }

    public function testReturnsNullWhenUserIdIsEmpty() : void
    {
        $fixture = $this->makeFixture() ;
        $request = $this->createStub( Request::class ) ;
        $request->method( 'getAttribute' )->willReturn( '' ) ;

        $this->assertNull( $fixture->callBuildAuthorizer( $request ) ) ;
    }

    public function testReturnsNullWhenUserIdIsNotAString() : void
    {
        $fixture = $this->makeFixture() ;
        $request = $this->createStub( Request::class ) ;
        $request->method( 'getAttribute' )->willReturn( 12345 ) ;

        $this->assertNull( $fixture->callBuildAuthorizer( $request ) ) ;
    }

    public function testReturnsClosureWhenEverythingIsInPlace() : void
    {
        $fixture = $this->makeFixture() ;
        $request = $this->stubRequestWithUserId( self::ALPHA_ID ) ;

        $authorizer = $fixture->callBuildAuthorizer( $request ) ;

        $this->assertInstanceOf( Closure::class , $authorizer ) ;
    }

    public function testClosureForwardsToEnforcerHas() : void
    {
        $captured = [] ;

        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturnCallback
        (
            function ( ...$args ) use ( &$captured ) : bool
            {
                $captured = $args ;
                return true ;
            }
        ) ;

        $fixture = new CapabilityAuthorizerTraitFixture() ;
        $fixture->capabilityEnforcer = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;
        $fixture->capabilityObject   = self::OBJECT ;

        $request    = $this->stubRequestWithUserId( self::ALPHA_ID ) ;
        $authorizer = $fixture->callBuildAuthorizer( $request ) ;

        $this->assertTrue( $authorizer( 'users.roles:list' ) ) ;
        $this->assertSame( self::ALPHA_ID                   , $captured[ 0 ] ?? null ) ;
        $this->assertSame( self::DOMAIN                     , $captured[ 1 ] ?? null ) ;
        $this->assertSame( self::OBJECT                     , $captured[ 2 ] ?? null ) ;
        $this->assertSame( 'PARAM:users.roles:list'         , $captured[ 3 ] ?? null ) ;
    }

    public function testClosureNormalisesNumericUserIdViaSafeSubject() : void
    {
        $capturedSubject = null ;

        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturnCallback
        (
            function ( string $sub ) use ( &$capturedSubject ) : bool
            {
                $capturedSubject = $sub ;
                return true ;
            }
        ) ;

        $fixture = new CapabilityAuthorizerTraitFixture() ;
        $fixture->capabilityEnforcer = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;
        $fixture->capabilityObject   = self::OBJECT ;

        $request    = $this->stubRequestWithUserId( self::NUMERIC_ID ) ;
        $authorizer = $fixture->callBuildAuthorizer( $request ) ;

        $authorizer( 'whatever' ) ;

        $this->assertSame( self::SAFE_NUMERIC , $capturedSubject ) ;
    }

    public function testClosurePropagatesEnforcerVerdict() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturn( false ) ;

        $fixture = new CapabilityAuthorizerTraitFixture() ;
        $fixture->capabilityEnforcer = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;
        $fixture->capabilityObject   = self::OBJECT ;

        $request    = $this->stubRequestWithUserId( self::ALPHA_ID ) ;
        $authorizer = $fixture->callBuildAuthorizer( $request ) ;

        $this->assertFalse( $authorizer( 'users.roles:list' ) ) ;
    }

    private function makeFixture() : CapabilityAuthorizerTraitFixture
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturn( true ) ;

        $fixture = new CapabilityAuthorizerTraitFixture() ;
        $fixture->capabilityEnforcer = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;
        $fixture->capabilityObject   = self::OBJECT ;

        return $fixture ;
    }

    private function stubRequestWithUserId( string $userId ) : Request
    {
        $request = $this->createStub( Request::class ) ;
        $request->method( 'getAttribute' )->willReturnCallback
        (
            fn( string $name ) : mixed
                => $name === RequestAttribute::USER_ID ? $userId : null
        ) ;
        return $request ;
    }
}
