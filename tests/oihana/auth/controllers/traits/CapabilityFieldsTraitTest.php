<?php

namespace tests\oihana\auth\controllers\traits;

use Casbin\Enforcer;
use Casbin\Exceptions\CasbinException;

use oihana\auth\casbin\CapabilityEnforcer;
use oihana\auth\enums\Capability;
use oihana\auth\enums\CapabilityPolicy;
use oihana\auth\controllers\traits\CapabilityFieldsTrait;
use oihana\auth\controllers\traits\CapabilityContextTrait;
use oihana\enums\http\RequestAttribute;
use oihana\controllers\enums\ControllerParam;
use oihana\exceptions\http\Error403;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;

use Psr\Http\Message\ServerRequestInterface;

use Slim\Psr7\Factory\ServerRequestFactory;

/**
 * Named fixture exposing the trait under test. Declared outside the test
 * class so the trait members are reachable via a regular class reference
 * (PHP 8.2+ forbids `TraitName::method`).
 */
class CapabilityFieldsFixture
{
    use CapabilityFieldsTrait , CapabilityContextTrait
    {
        enforceFields          as public ;
        initializeCapabilities as public ;
    }

    /**
     * @param array<array-key,mixed>  $init
     * @param CapabilityEnforcer|null $enforcer
     */
    public function __construct( array $init = [] , ?CapabilityEnforcer $enforcer = null )
    {
        $this->initializeCapabilities( $init , $enforcer ) ;
    }
}

#[CoversTrait( CapabilityFieldsTrait::class )]
class CapabilityFieldsTraitTest extends TestCase
{
    private const string USER_ID            = 'user-fields-001' ;
    private const string DOMAIN             = 'my-api' ;
    private const string OBJECT             = '/users' ;
    private const string SUBJECT_STATUS     = 'users:status:update' ;
    private const string SUBJECT_IDENTITY   = 'users:identity:update' ;
    private const string SUBJECT_AVATAR     = 'users:avatar:update' ;

    private function makeRequest( ?string $userId = self::USER_ID ) : ServerRequestInterface
    {
        $request = new ServerRequestFactory()->createServerRequest( 'PATCH' , '/users/1' ) ;

        if ( $userId !== null )
        {
            $request = $request->withAttribute( RequestAttribute::USER_ID , $userId ) ;
        }

        return $request ;
    }

    private function makeEnforcer( bool $allow ) : CapabilityEnforcer
    {
        $casbin = $this->createStub( Enforcer::class ) ;
        $casbin->method( 'enforce' )->willReturn( $allow ) ;
        $casbin->method( 'getImplicitPermissionsForUser' )->willReturn( [] ) ;

        return new CapabilityEnforcer( $casbin , self::DOMAIN ) ;
    }

    /**
     * Standard config: status (multi-field), avatar (singleton string).
     *
     * @return array<array-key,mixed>
     */
    private function configWithFields( string $policy = CapabilityPolicy::STRICT ) : array
    {
        return
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT => self::OBJECT ,
                Capability::FIELDS =>
                [
                    Capability::POLICY => $policy ,
                    Capability::VALUES =>
                    [
                        self::SUBJECT_STATUS => [ 'status' , 'activated' ] ,
                        self::SUBJECT_AVATAR => 'image' , // singleton string accepted
                    ],
                ],
            ],
        ] ;
    }

    // -------------------------------------------------------------------------
    // No-op cases
    // -------------------------------------------------------------------------

    public function testNoConfigurationIsNoOp() : void
    {
        $fixture = new CapabilityFieldsFixture( [] , null ) ;

        $body   = [ 'status' => 'disabled' , 'givenName' => 'X' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        $this->assertSame( $body , $result ) ;
    }

    public function testNoFieldsBlockIsNoOp() : void
    {
        $fixture = new CapabilityFieldsFixture
        (
            [ ControllerParam::CAPABILITIES => [ Capability::OBJECT => self::OBJECT ] ] ,
            $this->makeEnforcer( false )
        ) ;

        $body   = [ 'status' => 'disabled' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        $this->assertSame( $body , $result ) ;
    }

    public function testEmptyValuesIsNoOp() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT => self::OBJECT ,
                Capability::FIELDS =>
                [
                    Capability::POLICY => CapabilityPolicy::STRICT ,
                    Capability::VALUES => [] ,
                ],
            ],
        ] ;

        $fixture = new CapabilityFieldsFixture( $init , $this->makeEnforcer( false ) ) ;

        $body   = [ 'status' => 'disabled' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        $this->assertSame( $body , $result ) ;
    }

    public function testEmptyBodyIsNoOp() : void
    {
        $fixture = new CapabilityFieldsFixture( $this->configWithFields() , $this->makeEnforcer( false ) ) ;

        $result = $fixture->enforceFields( $this->makeRequest() , [] ) ;

        $this->assertSame( [] , $result ) ;
    }

    // -------------------------------------------------------------------------
    // STRICT + REQUIRE
    // -------------------------------------------------------------------------

    public function testFieldNotGatedPassesThrough() : void
    {
        $fixture = new CapabilityFieldsFixture( $this->configWithFields() , $this->makeEnforcer( false ) ) ;

        // givenName is not in any VALUES entry — should pass through even
        // when Casbin says no.
        $body   = [ 'givenName' => 'Marc' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        $this->assertSame( $body , $result ) ;
    }

    public function testFieldGatedAndAllowedIsKept() : void
    {
        $fixture = new CapabilityFieldsFixture( $this->configWithFields() , $this->makeEnforcer( true ) ) ;

        $body   = [ 'status' => 'disabled' , 'givenName' => 'Marc' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        $this->assertSame( $body , $result ) ;
    }

    public function testFieldGatedAndDeniedThrowsForbiddenUnderStrict() : void
    {
        $fixture = new CapabilityFieldsFixture( $this->configWithFields() , $this->makeEnforcer( false ) ) ;

        $this->expectException( Error403::class ) ;
        $this->expectExceptionMessage( "Forbidden field: 'status'" ) ;

        $fixture->enforceFields( $this->makeRequest() , [ 'status' => 'disabled' ] ) ;
    }

    public function testSecondGatedFieldStringSingletonAlsoEnforced() : void
    {
        $fixture = new CapabilityFieldsFixture( $this->configWithFields() , $this->makeEnforcer( false ) ) ;

        // 'image' is declared as a string singleton in the config — it must
        // be normalized to a one-entry mapping internally.
        $this->expectException( Error403::class ) ;
        $this->expectExceptionMessage( "Forbidden field: 'image'" ) ;

        $fixture->enforceFields( $this->makeRequest() , [ 'image' => 'https://x.png' ] ) ;
    }

    public function testActivatedAlsoEnforcedByStatusPermission() : void
    {
        // 'activated' shares the same permission as 'status' in the config.
        // Without permission, sending it must also be rejected.
        $fixture = new CapabilityFieldsFixture( $this->configWithFields() , $this->makeEnforcer( false ) ) ;

        $this->expectException( Error403::class ) ;
        $this->expectExceptionMessage( "Forbidden field: 'activated'" ) ;

        $fixture->enforceFields( $this->makeRequest() , [ 'activated' => true ] ) ;
    }

    // -------------------------------------------------------------------------
    // SILENT_DOWNGRADE
    // -------------------------------------------------------------------------

    public function testFieldGatedAndDeniedDroppedSilentlyUnderDowngrade() : void
    {
        $fixture = new CapabilityFieldsFixture
        (
            $this->configWithFields( CapabilityPolicy::SILENT_DOWNGRADE ) ,
            $this->makeEnforcer( false )
        ) ;

        $body   = [ 'status' => 'disabled' , 'givenName' => 'Marc' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        // status dropped, givenName kept (not gated)
        $this->assertSame( [ 'givenName' => 'Marc' ] , $result ) ;
    }

    // -------------------------------------------------------------------------
    // Multi-permission OR
    // -------------------------------------------------------------------------

    public function testFieldUnderMultiplePermissionsAllowedIfAnyMatches() : void
    {
        // Same field listed under two distinct permissions — caller needs
        // only one of them. Casbin allow=true on the first lookup short-
        // circuits the OR.
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT => self::OBJECT ,
                Capability::FIELDS =>
                [
                    Capability::POLICY => CapabilityPolicy::STRICT ,
                    Capability::VALUES =>
                    [
                        self::SUBJECT_STATUS   => 'status' ,
                        self::SUBJECT_IDENTITY => 'status' , // gated by either
                    ],
                ],
            ],
        ] ;

        $fixture = new CapabilityFieldsFixture( $init , $this->makeEnforcer( true ) ) ;

        $body   = [ 'status' => 'disabled' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        $this->assertSame( $body , $result ) ;
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    public function testKillSwitchSkipsEnforcement() : void
    {
        $init = $this->configWithFields() ;
        $init[ ControllerParam::CAPABILITIES_ENABLED ] = false ;

        $fixture = new CapabilityFieldsFixture( $init , $this->makeEnforcer( false ) ) ;

        $body   = [ 'status' => 'disabled' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        // kill-switch off → activeParamConfig() returns null → no-op
        $this->assertSame( $body , $result ) ;
    }

    public function testMissingUserIdRejectsUnderStrict() : void
    {
        $fixture = new CapabilityFieldsFixture( $this->configWithFields() , $this->makeEnforcer( true ) ) ;

        // No userId on the request → REQUIRE fails closed.
        $this->expectException( Error403::class ) ;

        $fixture->enforceFields( $this->makeRequest( null ) , [ 'status' => 'disabled' ] ) ;
    }

    public function testMalformedSubjectIsIgnored() : void
    {
        // Empty-string subject must be skipped during inverse-map build.
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT => self::OBJECT ,
                Capability::FIELDS =>
                [
                    Capability::POLICY => CapabilityPolicy::STRICT ,
                    Capability::VALUES =>
                    [
                        ''                   => [ 'ghost' ] , // skipped
                        self::SUBJECT_STATUS => 'status' ,
                    ],
                ],
            ],
        ] ;

        $fixture = new CapabilityFieldsFixture( $init , $this->makeEnforcer( true ) ) ;

        $body   = [ 'ghost' => 'x' , 'status' => 'disabled' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        // 'ghost' was associated to an empty subject → not gated → kept.
        // 'status' is gated and allowed → kept.
        $this->assertSame( $body , $result ) ;
    }

    public function testGatedFieldNotInBodyIsNoOp() : void
    {
        // Body carries only ungated fields; the gated 'status' is absent
        // entirely. No Casbin call should be triggered, no exception.
        $fixture = new CapabilityFieldsFixture( $this->configWithFields() , $this->makeEnforcer( false ) ) ;

        $body   = [ 'givenName' => 'Marc' , 'familyName' => 'Alcaraz' ] ;
        $result = $fixture->enforceFields( $this->makeRequest() , $body ) ;

        $this->assertSame( $body , $result ) ;
    }

    /**
     * Invalid entries (empty string, non-string) inside a subject's field list
     * are skipped during the inverse-map build, while the valid field is still
     * gated. Exercises the per-field skip branch.
     */
    public function testFieldListSkipsInvalidEntriesButGatesValidOnes() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT => self::OBJECT ,
                Capability::FIELDS =>
                [
                    Capability::POLICY => CapabilityPolicy::STRICT ,
                    Capability::VALUES =>
                    [
                        self::SUBJECT_STATUS => [ '' , 42 , 'status' ] , // only 'status' is valid
                    ],
                ],
            ],
        ] ;

        $fixture = new CapabilityFieldsFixture( $init , $this->makeEnforcer( false ) ) ;

        // The invalid entries were skipped → only 'status' is gated → denied → 403.
        $this->expectException( Error403::class ) ;
        $this->expectExceptionMessage( "Forbidden field: 'status'" ) ;

        $fixture->enforceFields( $this->makeRequest() , [ 'status' => 'disabled' ] ) ;
    }

    /**
     * When every declared subject maps only to invalid fields, the inverse map
     * is empty and the body is returned untouched (no Casbin call). Exercises
     * the empty-map short-circuit.
     */
    public function testAllInvalidFieldsLeavesBodyUntouched() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT => self::OBJECT ,
                Capability::FIELDS =>
                [
                    Capability::POLICY => CapabilityPolicy::STRICT ,
                    Capability::VALUES =>
                    [
                        self::SUBJECT_STATUS => [ '' , 42 ] , // no valid field at all
                    ],
                ],
            ],
        ] ;

        $fixture = new CapabilityFieldsFixture( $init , $this->makeEnforcer( false ) ) ;

        $body = [ 'status' => 'disabled' ] ;

        // Inverse map empty → body returned unchanged even though Casbin denies.
        $this->assertSame( $body , $fixture->enforceFields( $this->makeRequest() , $body ) ) ;
    }
}
