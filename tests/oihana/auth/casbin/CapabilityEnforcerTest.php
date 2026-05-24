<?php

namespace tests\oihana\auth\casbin;

use Casbin\Enforcer;

use InvalidArgumentException;

use oihana\auth\casbin\CapabilityEnforcer;
use oihana\auth\enums\CapabilityMode;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( CapabilityEnforcer::class )]
class CapabilityEnforcerTest extends TestCase
{
    private const string USER_ID         = 'user-abc-123' ;
    private const string NUMERIC_USER_ID = '364646423545321675' ;
    private const string SAFE_NUMERIC_ID = 'n_364646423545321675' ;
    private const string DOMAIN          = 'bouney-api' ;
    private const string OBJECT          = '/products' ;
    private const string CAPABILITY      = 'skin.offers.full' ;
    private const string ACTION          = 'PARAM:skin.offers.full' ;

    /**
     * Tests that has() returns true when Casbin grants the capability.
     */
    public function testHasReturnsTrueWhenEnforcerAllows() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturn( true ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertTrue( $capability->has( self::USER_ID , self::OBJECT , self::CAPABILITY ) ) ;
    }

    /**
     * Tests that has() returns false when Casbin denies the capability.
     */
    public function testHasReturnsFalseWhenEnforcerDenies() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturn( false ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertFalse( $capability->has( self::USER_ID , self::OBJECT , self::CAPABILITY ) ) ;
    }

    /**
     * Tests that has() passes the PARAM-prefixed action to Casbin.
     */
    public function testHasPassesPrefixedActionToEnforcer() : void
    {
        $capturedArgs = [] ;

        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturnCallback
        (
            function ( ...$args ) use ( &$capturedArgs ) : bool
            {
                $capturedArgs = $args ;
                return true ;
            }
        ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;
        $capability->has( self::USER_ID , self::OBJECT , self::CAPABILITY ) ;

        $this->assertSame( self::USER_ID , $capturedArgs[ 0 ] ?? null ) ;
        $this->assertSame( self::DOMAIN  , $capturedArgs[ 1 ] ?? null ) ;
        $this->assertSame( self::OBJECT  , $capturedArgs[ 2 ] ?? null ) ;
        $this->assertSame( self::ACTION  , $capturedArgs[ 3 ] ?? null ) ;
    }

    /**
     * Tests that isDenied() returns true when an explicit deny policy matches.
     */
    public function testIsDeniedReturnsTrueWhenDenyPolicyMatches() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'getImplicitPermissionsForUser' )->willReturn
        ([
            [ 'someRole' , self::DOMAIN , self::OBJECT , self::ACTION , 'deny'  ] ,
            [ 'someRole' , self::DOMAIN , '/users'     , 'GET'        , 'allow' ] ,
        ]) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertTrue( $capability->isDenied( self::USER_ID , self::OBJECT , self::CAPABILITY ) ) ;
    }

    /**
     * Tests that isDenied() returns false when no deny policy matches.
     */
    public function testIsDeniedReturnsFalseWhenNoDenyPolicy() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'getImplicitPermissionsForUser' )->willReturn
        ([
            [ 'someRole' , self::DOMAIN , self::OBJECT , self::ACTION , 'allow' ] ,
        ]) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertFalse( $capability->isDenied( self::USER_ID , self::OBJECT , self::CAPABILITY ) ) ;
    }

    /**
     * Tests that isDenied() ignores deny policies that don't match the object.
     */
    public function testIsDeniedIgnoresMismatchedObject() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'getImplicitPermissionsForUser' )->willReturn
        ([
            [ 'someRole' , self::DOMAIN , '/customers' , self::ACTION , 'deny' ] ,
        ]) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertFalse( $capability->isDenied( self::USER_ID , self::OBJECT , self::CAPABILITY ) ) ;
    }

    /**
     * Tests that isDenied() ignores deny policies that don't match the action.
     */
    public function testIsDeniedIgnoresMismatchedAction() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'getImplicitPermissionsForUser' )->willReturn
        ([
            [ 'someRole' , self::DOMAIN , self::OBJECT , 'PARAM:skin.other' , 'deny' ] ,
        ]) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertFalse( $capability->isDenied( self::USER_ID , self::OBJECT , self::CAPABILITY ) ) ;
    }

    /**
     * Tests that isDenied() returns false on empty permission list.
     */
    public function testIsDeniedReturnsFalseOnEmptyPermissions() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'getImplicitPermissionsForUser' )->willReturn( [] ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertFalse( $capability->isDenied( self::USER_ID , self::OBJECT , self::CAPABILITY ) ) ;
    }

    /**
     * Tests that check() with REQUIRE mode delegates to has().
     */
    public function testCheckRequireModeDelegatesToHas() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturn( true ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertTrue
        (
            $capability->check( self::USER_ID , self::OBJECT , self::CAPABILITY , CapabilityMode::REQUIRE )
        ) ;
    }

    /**
     * Tests that check() with REQUIRE mode returns false when has() fails.
     */
    public function testCheckRequireModeReturnsFalseWhenHasFails() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturn( false ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertFalse
        (
            $capability->check( self::USER_ID , self::OBJECT , self::CAPABILITY , CapabilityMode::REQUIRE )
        ) ;
    }

    /**
     * Tests that check() with DENY mode returns true when no deny policy matches.
     */
    public function testCheckDenyModeReturnsTrueWhenNotDenied() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'getImplicitPermissionsForUser' )->willReturn( [] ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertTrue
        (
            $capability->check( self::USER_ID , self::OBJECT , self::CAPABILITY , CapabilityMode::DENY )
        ) ;
    }

    /**
     * Tests that check() with DENY mode returns false when denied.
     */
    public function testCheckDenyModeReturnsFalseWhenDenied() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'getImplicitPermissionsForUser' )->willReturn
        ([
            [ 'someRole' , self::DOMAIN , self::OBJECT , self::ACTION , 'deny' ] ,
        ]) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->assertFalse
        (
            $capability->check( self::USER_ID , self::OBJECT , self::CAPABILITY , CapabilityMode::DENY )
        ) ;
    }

    /**
     * Tests that has() normalises a purely-numeric userId via safeSubject before
     * delegating to Casbin. Regression guard for the 2026-04-25 incident where
     * Zitadel-style identifiers like '364646423545321675' would not match the
     * `n_<id>` keys used by CasbinPolicySync writers.
     */
    public function testHasNormalisesNumericUserIdToSafeSubject() : void
    {
        $capturedArgs = [] ;

        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'enforce' )->willReturnCallback
        (
            function ( ...$args ) use ( &$capturedArgs ) : bool
            {
                $capturedArgs = $args ;
                return true ;
            }
        ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;
        $capability->has( self::NUMERIC_USER_ID , self::OBJECT , self::CAPABILITY ) ;

        $this->assertSame( self::SAFE_NUMERIC_ID , $capturedArgs[ 0 ] ?? null ) ;
    }

    /**
     * Tests that isDenied() normalises a purely-numeric userId via safeSubject
     * before reading the implicit permissions list.
     */
    public function testIsDeniedNormalisesNumericUserIdToSafeSubject() : void
    {
        $capturedSubject = null ;

        $enforcer = $this->createStub( Enforcer::class ) ;
        $enforcer->method( 'getImplicitPermissionsForUser' )->willReturnCallback
        (
            function ( string $subject ) use ( &$capturedSubject ) : array
            {
                $capturedSubject = $subject ;
                return [] ;
            }
        ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;
        $capability->isDenied( self::NUMERIC_USER_ID , self::OBJECT , self::CAPABILITY ) ;

        $this->assertSame( self::SAFE_NUMERIC_ID , $capturedSubject ) ;
    }

    /**
     * Tests that check() throws on unknown mode.
     */
    public function testCheckThrowsOnUnknownMode() : void
    {
        $enforcer = $this->createStub( Enforcer::class ) ;

        $capability = new CapabilityEnforcer( $enforcer , self::DOMAIN ) ;

        $this->expectException( InvalidArgumentException::class ) ;
        $this->expectExceptionMessage( "Unknown capability mode: 'bogus'" ) ;

        $capability->check( self::USER_ID , self::OBJECT , self::CAPABILITY , 'bogus' ) ;
    }
}
