<?php

namespace tests\oihana\auth\controllers\traits;

use Casbin\Enforcer;

use Casbin\Exceptions\CasbinException;
use oihana\auth\casbin\CapabilityEnforcer;
use oihana\auth\enums\Capability;
use oihana\auth\enums\CapabilityPolicy;
use oihana\auth\controllers\traits\CapabilityGuardTrait;
use oihana\enums\http\RequestAttribute;
use oihana\controllers\enums\ControllerParam;
use oihana\exceptions\http\Error403;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use Psr\Http\Message\ServerRequestInterface;

use Slim\Psr7\Factory\ServerRequestFactory;

/**
 * Named fixture exposing the trait under test. Declared outside
 * {@see CapabilityGuardTraitTest} so the trait members are reachable via a
 * regular class reference (PHP 8.2+ forbids `TraitName::method`).
 */
class CapabilityGuardFixture
{
    use CapabilityGuardTrait
    {
        enforceFilterKeys      as public ;
        enforceParam           as public ;
        hasCapability          as public ;
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

#[CoversClass( CapabilityGuardTrait::class )]
class CapabilityGuardTraitTest extends TestCase
{
    private const string USER_ID         = 'user-abc-123' ;
    private const string DOMAIN          = 'my-api' ;
    private const string OBJECT          = '/products' ;
    private const string SKIN_FULL       = 'offers.full' ;
    private const string SKIN_DEFAULT    = 'offers' ;
    private const string SKIN_SPECIAL    = 'special' ;
    private const string SUBJECT_FULL    = 'products:skin.offers.full' ;
    private const string SUBJECT_SPECIAL = 'products:skin.special' ;
    private const string ACTION_SPECIAL  = 'PARAM:skin.special' ;

    /**
     * Build a request attributed with the given user id.
     */
    private function makeRequest( ?string $userId = self::USER_ID ) : ServerRequestInterface
    {
        $request = new ServerRequestFactory()->createServerRequest( 'GET' , '/products' ) ;

        if ( $userId !== null )
        {
            $request = $request->withAttribute( RequestAttribute::USER_ID , $userId ) ;
        }

        return $request ;
    }

    /**
     * Build a CapabilityEnforcer whose underlying Casbin Enforcer returns the
     * given allow/deny behaviour.
     *
     * @param bool                        $allow
     * @param array<int,array<int,mixed>> $implicitPermissions
     */
    private function makeEnforcer( bool $allow , array $implicitPermissions = [] ) : CapabilityEnforcer
    {
        $casbin = $this->createStub( Enforcer::class ) ;
        $casbin->method( 'enforce' )->willReturn( $allow ) ;
        $casbin->method( 'getImplicitPermissionsForUser' )->willReturn( $implicitPermissions ) ;

        return new CapabilityEnforcer( $casbin , self::DOMAIN ) ;
    }

    /**
     * Builds the standard REQUIRE config used across the happy-path tests.
     *
     * @return array<array-key,mixed>
     */
    private function requireInit( string $policy = CapabilityPolicy::SILENT_DOWNGRADE ) : array
    {
        return
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT    => self::OBJECT ,
                ControllerParam::SKIN =>
                [
                    Capability::POLICY   => $policy ,
                    Capability::FALLBACK => self::SKIN_DEFAULT ,
                    Capability::VALUES   =>
                    [
                        self::SKIN_FULL => self::SUBJECT_FULL ,
                    ],
                ],
            ],
        ] ;
    }

    // -------------------------------------------------------------------------
    // No-op cases (retrocompat)
    // -------------------------------------------------------------------------

    /**
     * No CAPABILITIES block → value is passed through unchanged.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testNoConfigurationIsNoOp() : void
    {
        $fixture = new CapabilityGuardFixture( [] , null ) ;

        $result = $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL ) ;

        $this->assertSame( self::SKIN_FULL , $result ) ;
    }

    /**
     * Kill-switch disables enforcement even when block is present.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testKillSwitchDisablesEnforcement() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            array_merge
            (
                $this->requireInit() ,
                [ ControllerParam::CAPABILITIES_ENABLED => false ]
            ) ,
            $this->makeEnforcer( allow : false )
        ) ;

        $result = $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL ) ;

        $this->assertSame( self::SKIN_FULL , $result ) ;
    }

    /**
     * No enforcer injected (auth disabled) → value is passed through.
     * @return void
     * @throws Error403
     * @throws CasbinException
     */
    public function testNoEnforcerIsNoOp() : void
    {
        $fixture = new CapabilityGuardFixture( $this->requireInit() , null ) ;

        $result = $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL ) ;

        $this->assertSame( self::SKIN_FULL , $result ) ;
    }

    /**
     * Value not present in VALUES mapping → passed through (not gated).
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testUnmappedValueIsPassedThrough() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->requireInit() ,
            $this->makeEnforcer( allow : false )
        ) ;

        $result = $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , 'list' ) ;

        $this->assertSame( 'list' , $result ) ;
    }

    // -------------------------------------------------------------------------
    // REQUIRE mode
    // -------------------------------------------------------------------------

    /**
     * REQUIRE + allowed user → value kept.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testRequireAllowsAuthorizedUser() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->requireInit() ,
            $this->makeEnforcer( allow : true )
        ) ;

        $result = $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL ) ;

        $this->assertSame( self::SKIN_FULL , $result ) ;
    }

    /**
     * REQUIRE + denied user + SILENT_DOWNGRADE → returns fallback.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testRequireSilentDowngradeReturnsFallback() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->requireInit() ,
            $this->makeEnforcer( allow : false )
        ) ;

        $result = $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL ) ;

        $this->assertSame( self::SKIN_DEFAULT , $result ) ;
    }

    /**
     * REQUIRE + denied user + STRICT → throws 403.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testRequireStrictThrowsForbidden() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->requireInit( CapabilityPolicy::STRICT ) ,
            $this->makeEnforcer( allow : false )
        ) ;

        $this->expectException( Error403::class ) ;

        $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL ) ;
    }

    /**
     * REQUIRE + anonymous request (no userId) + SILENT_DOWNGRADE → returns fallback.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testRequireAnonymousFallsBackToDefault() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->requireInit() ,
            $this->makeEnforcer( allow : true )
        ) ;

        $result = $fixture->enforceParam( $this->makeRequest( null ) , ControllerParam::SKIN , self::SKIN_FULL ) ;

        $this->assertSame( self::SKIN_DEFAULT , $result ) ;
    }

    // -------------------------------------------------------------------------
    // DENY mode
    // -------------------------------------------------------------------------

    /**
     * DENY + user without deny policy → value kept (open-by-default).
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testDenyAllowsWhenUserHasNoDenyPolicy() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT    => self::OBJECT ,
                ControllerParam::SKIN =>
                [
                    Capability::POLICY   => CapabilityPolicy::SILENT_DOWNGRADE ,
                    Capability::FALLBACK => self::SKIN_DEFAULT ,
                    Capability::VALUES   =>
                    [
                        self::SKIN_SPECIAL => [ Capability::DENY => self::SUBJECT_SPECIAL ] ,
                    ],
                ],
            ],
        ] ;

        $fixture = new CapabilityGuardFixture( $init , $this->makeEnforcer( allow : false ) ) ;

        $result = $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_SPECIAL ) ;

        $this->assertSame( self::SKIN_SPECIAL , $result ) ;
    }

    /**
     * DENY + user carrying a matching deny policy → downgrade.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testDenyBlocksUserWithDenyPolicy() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT    => self::OBJECT ,
                ControllerParam::SKIN =>
                [
                    Capability::POLICY   => CapabilityPolicy::SILENT_DOWNGRADE ,
                    Capability::FALLBACK => self::SKIN_DEFAULT ,
                    Capability::VALUES   =>
                    [
                        self::SKIN_SPECIAL => [ Capability::DENY => self::SUBJECT_SPECIAL ] ,
                    ],
                ],
            ],
        ] ;

        $enforcer = $this->makeEnforcer
        (
            allow : false ,
            implicitPermissions :
            [
                [ 'guest' , self::DOMAIN , self::OBJECT , self::ACTION_SPECIAL , 'deny' ] ,
            ]
        ) ;

        $fixture = new CapabilityGuardFixture( $init , $enforcer ) ;

        $result = $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_SPECIAL ) ;

        $this->assertSame( self::SKIN_DEFAULT , $result ) ;
    }

    // -------------------------------------------------------------------------
    // hasCapability()
    // -------------------------------------------------------------------------

    /**
     * hasCapability returns true when no config is declared (no-op baseline).
     * @return void
     * @throws CasbinException
     */
    public function testHasCapabilityReturnsTrueWhenNotConfigured() : void
    {
        $fixture = new CapabilityGuardFixture( [] , null ) ;

        $this->assertTrue( $fixture->hasCapability( $this->makeRequest() , 'export' ) ) ;
    }

    /**
     * hasCapability honours a SUBJECT-only entry when the user is authorized.
     * @return void
     * @throws CasbinException
     */
    public function testHasCapabilityReturnsTrueForAuthorizedUser() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT => self::OBJECT ,
                'export'           =>
                [
                    Capability::SUBJECT => 'products:export' ,
                ],
            ],
        ] ;

        $fixture = new CapabilityGuardFixture( $init , $this->makeEnforcer( allow : true ) ) ;

        $this->assertTrue( $fixture->hasCapability( $this->makeRequest() , 'export' ) ) ;
    }

    /**
     * hasCapability returns false when the user fails the REQUIRE check.
     * @return void
     * @throws CasbinException
     */
    public function testHasCapabilityReturnsFalseForUnauthorizedUser() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT => self::OBJECT ,
                'export'           =>
                [
                    Capability::SUBJECT => 'products:export' ,
                ],
            ],
        ] ;

        $fixture = new CapabilityGuardFixture( $init , $this->makeEnforcer( allow : false ) ) ;

        $this->assertFalse( $fixture->hasCapability( $this->makeRequest() , 'export' ) ) ;
    }

    // -------------------------------------------------------------------------
    // enforceFilterKeys()
    // -------------------------------------------------------------------------

    /**
     * Build a filter CAPABILITIES block gating one key via REQUIRE.
     *
     * @return array<array-key,mixed>
     */
    private function filterKeysInit( string $policy = CapabilityPolicy::SILENT_DOWNGRADE ) : array
    {
        return
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT      => self::OBJECT ,
                ControllerParam::FILTER =>
                [
                    Capability::POLICY => $policy ,
                    Capability::KEYS   =>
                    [
                        'costPrice' => 'products:filter.costPrice' ,
                    ],
                ],
            ],
        ] ;
    }

    /**
     * No config → filter payload returned unchanged.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysNoOpWithoutConfig() : void
    {
        $fixture = new CapabilityGuardFixture( [] , null ) ;
        $filters = [ [ 'key' => 'costPrice' , 'op' => 'gt' , 'val' => 100 ] ] ;

        $this->assertSame( $filters , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    /**
     * Allowed key is kept.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysKeepsAllowedKey() : void
    {
        $fixture = new CapabilityGuardFixture( $this->filterKeysInit() , $this->makeEnforcer( allow : true ) ) ;
        $filters = [ [ 'key' => 'costPrice' , 'op' => 'gt' , 'val' => 100 ] ] ;

        $this->assertSame( $filters , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    /**
     * Key not listed is kept (not gated).
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysKeepsUnmappedKey() : void
    {
        $fixture = new CapabilityGuardFixture( $this->filterKeysInit() , $this->makeEnforcer( allow : false ) ) ;
        $filters = [ [ 'key' => 'name' , 'op' => 'eq' , 'val' => 'X' ] ] ;

        $this->assertSame( $filters , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    /**
     * Forbidden key + SILENT_DOWNGRADE → clause is silently dropped.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysSilentDowngradeDropsForbiddenClause() : void
    {
        $fixture = new CapabilityGuardFixture( $this->filterKeysInit() , $this->makeEnforcer( allow : false ) ) ;
        $filters =
        [
            [ 'key' => 'costPrice' , 'op' => 'gt' , 'val' => 100 ] ,    // forbidden
            [ 'key' => 'name'      , 'op' => 'eq' , 'val' => 'X' ] ,    // kept
        ] ;

        $result = $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ;

        $this->assertCount( 1 , $result ) ;
        $kept = $result[ 0 ] ?? null ;
        $this->assertIsArray( $kept ) ;
        $this->assertSame( 'name' , $kept[ 'key' ] ?? null ) ;
    }

    /**
     * Forbidden key + STRICT → throws 403.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysStrictThrowsForbidden() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->filterKeysInit( CapabilityPolicy::STRICT ) ,
            $this->makeEnforcer( allow : false )
        ) ;

        $filters = [ [ 'key' => 'costPrice' , 'op' => 'gt' , 'val' => 100 ] ] ;

        $this->expectException( Error403::class ) ;
        $this->expectExceptionMessage( "Forbidden filter key: 'costPrice'" ) ;

        $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ;
    }

    /**
     * Single-clause (associative) input shape is preserved.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysPreservesSingleClauseShape() : void
    {
        $fixture = new CapabilityGuardFixture( $this->filterKeysInit() , $this->makeEnforcer( allow : true ) ) ;
        $filters = [ 'key' => 'costPrice' , 'op' => 'gt' , 'val' => 100 ] ;

        $this->assertSame( $filters , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    /**
     * Single forbidden clause + SILENT_DOWNGRADE → returns empty array (no clauses left).
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysSingleForbiddenClauseBecomesEmpty() : void
    {
        $fixture = new CapabilityGuardFixture( $this->filterKeysInit() , $this->makeEnforcer( allow : false ) ) ;
        $filters = [ 'key' => 'costPrice' , 'op' => 'gt' , 'val' => 100 ] ;

        $this->assertSame( [] , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    /**
     * Malformed clauses (missing key, non-string key, non-array) pass through unchanged.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysPassesThroughMalformedClauses() : void
    {
        $fixture = new CapabilityGuardFixture( $this->filterKeysInit() , $this->makeEnforcer( allow : false ) ) ;
        $filters =
        [
            [ 'op' => 'eq' , 'val' => 'X' ] ,            // missing 'key'
            [ 'key' => 42 , 'op' => 'eq' , 'val' => 1 ] , // non-string key
            'malformed-string-clause' ,                   // not an array
        ] ;

        $this->assertSame( $filters , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    /**
     * DENY mode: key without matching deny policy → kept.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysDenyAllowsWithoutDenyPolicy() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT      => self::OBJECT ,
                ControllerParam::FILTER =>
                [
                    Capability::POLICY => CapabilityPolicy::SILENT_DOWNGRADE ,
                    Capability::KEYS   =>
                    [
                        'costPrice' => [ Capability::DENY => 'products:filter.costPrice' ] ,
                    ],
                ],
            ],
        ] ;

        $fixture = new CapabilityGuardFixture( $init , $this->makeEnforcer( allow : false ) ) ;
        $filters = [ [ 'key' => 'costPrice' , 'op' => 'gt' , 'val' => 100 ] ] ;

        $this->assertSame( $filters , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    /**
     * DENY mode: key with matching deny policy → dropped.
     * @return void
     * @throws CasbinException
     * @throws Error403
     */
    public function testEnforceFilterKeysDenyBlocksWithDenyPolicy() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT      => self::OBJECT ,
                ControllerParam::FILTER =>
                [
                    Capability::POLICY => CapabilityPolicy::SILENT_DOWNGRADE ,
                    Capability::KEYS   =>
                    [
                        'costPrice' => [ Capability::DENY => 'products:filter.costPrice' ] ,
                    ],
                ],
            ],
        ] ;

        $enforcer = $this->makeEnforcer
        (
            allow : false ,
            implicitPermissions :
            [
                [ 'guest' , self::DOMAIN , self::OBJECT , 'PARAM:filter.costPrice' , 'deny' ] ,
            ]
        ) ;

        $fixture = new CapabilityGuardFixture( $init , $enforcer ) ;
        $filters = [ [ 'key' => 'costPrice' , 'op' => 'gt' , 'val' => 100 ] ] ;

        $this->assertSame( [] , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    // -------------------------------------------------------------------------
    // FALLBACKS cascade
    // -------------------------------------------------------------------------

    /**
     * Builds an enforcer whose underlying Casbin returns `true` only for the
     * actions present (with `true`) in $permissionsByAction (REQUIRE mode),
     * and exposes $implicitPermissions for the DENY mode (which calls
     * getImplicitPermissionsForUser instead of enforce).
     *
     * @param array<string,bool>          $permissionsByAction Map `PARAM:<discriminator> => bool` for REQUIRE mode.
     * @param array<int,array<int,mixed>> $implicitPermissions Standard Casbin tuples used by DENY mode.
     */
    private function makeEnforcerByAction( array $permissionsByAction , array $implicitPermissions = [] ) : CapabilityEnforcer
    {
        $casbin = $this->createStub( Enforcer::class ) ;
        $casbin->method( 'enforce' )->willReturnCallback
        (
            fn( string $userId , string $domain , string $object , string $action ) :bool
                => $permissionsByAction[ $action ] ?? false
        ) ;
        $casbin->method( 'getImplicitPermissionsForUser' )->willReturn( $implicitPermissions ) ;

        return new CapabilityEnforcer( $casbin , self::DOMAIN ) ;
    }

    /**
     * Builds the standard cascade config used across the FALLBACKS tests.
     *
     * Three tiers — offers.full → offers → default(ungated).
     *
     * @return array<array-key,mixed>
     */
    private function cascadeInit() : array
    {
        return
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT    => self::OBJECT ,
                ControllerParam::SKIN =>
                [
                    Capability::POLICY    => CapabilityPolicy::SILENT_DOWNGRADE ,
                    Capability::FALLBACK  => 'default' ,
                    Capability::FALLBACKS =>
                    [
                        self::SKIN_FULL    => self::SKIN_DEFAULT , // offers.full → offers
                        self::SKIN_DEFAULT => 'default' ,           // offers      → default (ungated)
                    ] ,
                    Capability::VALUES =>
                    [
                        self::SKIN_FULL    => self::SUBJECT_FULL ,
                        self::SKIN_DEFAULT => 'products:skin.offers' ,
                        // 'default' intentionally absent from VALUES → ungated tier
                    ],
                ],
            ],
        ] ;
    }

    /**
     * Top tier denied, second tier granted → returns the second tier.
     */
    public function testFallbacksReturnsFirstGrantedTier() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->cascadeInit() ,
            $this->makeEnforcerByAction
            ([
                'PARAM:skin.offers.full' => false ,
                'PARAM:skin.offers'      => true  ,
            ])
        ) ;

        $this->assertSame
        (
            self::SKIN_DEFAULT ,
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    /**
     * Every gated tier denied → cascade ends on the ungated 'default' bucket.
     */
    public function testFallbacksReturnsUngatedTierWhenAllGatedDenied() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->cascadeInit() ,
            $this->makeEnforcerByAction
            ([
                'PARAM:skin.offers.full' => false ,
                'PARAM:skin.offers'      => false ,
            ])
        ) ;

        $this->assertSame
        (
            'default' ,
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    /**
     * Top tier granted → no cascade walked, value kept as-is.
     */
    public function testFallbacksNotConsultedWhenInitialCheckPasses() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->cascadeInit() ,
            $this->makeEnforcerByAction
            ([
                'PARAM:skin.offers.full' => true ,
                'PARAM:skin.offers'      => false , // unused
            ])
        ) ;

        $this->assertSame
        (
            self::SKIN_FULL ,
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    /**
     * Cycle in the FALLBACKS table → cascade short-circuits and the standard
     * Capability::FALLBACK is returned.
     */
    public function testFallbacksCycleFallsBackOnPolicy() : void
    {
        $init = $this->cascadeInit() ;
        $init[ ControllerParam::CAPABILITIES ][ ControllerParam::SKIN ][ Capability::FALLBACKS ] =
        [
            self::SKIN_FULL    => self::SKIN_DEFAULT ,
            self::SKIN_DEFAULT => self::SKIN_FULL ,  // closes the loop
        ] ;

        $fixture = new CapabilityGuardFixture
        (
            $init ,
            $this->makeEnforcerByAction
            ([
                'PARAM:skin.offers.full' => false ,
                'PARAM:skin.offers'      => false ,
            ])
        ) ;

        $this->assertSame
        (
            'default' , // Capability::FALLBACK from cascadeInit
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    /**
     * No FALLBACKS declared → behaviour matches the legacy Capability::FALLBACK
     * single-step downgrade.
     */
    public function testFallbacksAbsentBehavesLikeLegacyFallback() : void
    {
        // requireInit() declares Capability::FALLBACK = SKIN_DEFAULT but no
        // FALLBACKS table at all.
        $fixture = new CapabilityGuardFixture
        (
            $this->requireInit() ,
            $this->makeEnforcer( allow : false )
        ) ;

        $this->assertSame
        (
            self::SKIN_DEFAULT ,
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    /**
     * Cascade exhausted (no entry for the current tier) → standard policy.
     */
    public function testFallbacksExhaustedFallsBackOnPolicy() : void
    {
        $init = $this->cascadeInit() ;
        // Only one hop declared, then the chain stops.
        $init[ ControllerParam::CAPABILITIES ][ ControllerParam::SKIN ][ Capability::FALLBACKS ] =
        [
            self::SKIN_FULL => self::SKIN_DEFAULT ,
        ] ;

        $fixture = new CapabilityGuardFixture
        (
            $init ,
            $this->makeEnforcerByAction
            ([
                'PARAM:skin.offers.full' => false ,
                'PARAM:skin.offers'      => false , // second tier denied too
            ])
        ) ;

        $this->assertSame
        (
            'default' , // Capability::FALLBACK
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    // -------------------------------------------------------------------------
    // FALLBACKS cascade — for Capability::KEYS (filter keys)
    // -------------------------------------------------------------------------

    /**
     * Builds a filter CAPABILITIES block with a two-tier cascade :
     * `salary` (precise) → `salary_range` (coarser, listed in KEYS) →
     * `salary_bucket` (ungated alternative, not listed in KEYS so it acts as
     * the cascade floor).
     *
     * @return array<array-key,mixed>
     */
    private function keysCascadeInit( string $policy = CapabilityPolicy::SILENT_DOWNGRADE ) : array
    {
        return
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT      => self::OBJECT ,
                ControllerParam::FILTER =>
                [
                    Capability::POLICY    => $policy ,
                    Capability::KEYS      =>
                    [
                        'salary'       => 'users:filter.salary' ,
                        'salary_range' => 'users:filter.salary_range' ,
                        // 'salary_bucket' intentionally absent → ungated tier
                    ] ,
                    Capability::FALLBACKS =>
                    [
                        'salary'       => 'salary_range' ,
                        'salary_range' => 'salary_bucket' ,
                    ] ,
                ] ,
            ] ,
        ] ;
    }

    /**
     * Forbidden top key + granted second tier → clause's `key` is substituted
     * in place, every other field of the clause is preserved.
     */
    public function testKeysFallbacksSubstitutesWithFirstGrantedAlternative() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->keysCascadeInit() ,
            $this->makeEnforcerByAction
            ([
                'PARAM:filter.salary'       => false ,
                'PARAM:filter.salary_range' => true  ,
            ])
        ) ;

        $filters = [ [ 'key' => 'salary' , 'op' => 'gt' , 'val' => 50000 , 'alt' => 'lower' ] ] ;

        $result = $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ;

        $this->assertCount( 1 , $result ) ;
        $kept = $result[ 0 ] ?? null ;
        $this->assertIsArray( $kept ) ;
        $this->assertSame( 'salary_range' , $kept[ 'key' ] ?? null ) ;
        $this->assertSame( 'gt'           , $kept[ 'op'  ] ?? null ) ;
        $this->assertSame( 50000          , $kept[ 'val' ] ?? null ) ;
        $this->assertSame( 'lower'        , $kept[ 'alt' ] ?? null ) ;
    }

    /**
     * Every gated tier denied → cascade lands on the ungated tier listed only
     * in FALLBACKS (not in KEYS), which is accepted directly.
     */
    public function testKeysFallbacksReturnsUngatedTierWhenAllGatedDenied() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->keysCascadeInit() ,
            $this->makeEnforcerByAction
            ([
                'PARAM:filter.salary'       => false ,
                'PARAM:filter.salary_range' => false ,
            ])
        ) ;

        $filters = [ [ 'key' => 'salary' , 'op' => 'gt' , 'val' => 50000 ] ] ;

        $result = $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ;

        $this->assertCount( 1 , $result ) ;
        $this->assertSame( 'salary_bucket' , $result[ 0 ][ 'key' ] ?? null ) ;
    }

    /**
     * Top key granted → no cascade walked, clause kept untouched.
     */
    public function testKeysFallbacksNotConsultedWhenInitialCheckPasses() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->keysCascadeInit() ,
            $this->makeEnforcerByAction
            ([
                'PARAM:filter.salary'       => true  ,
                'PARAM:filter.salary_range' => false , // unused
            ])
        ) ;

        $filters = [ [ 'key' => 'salary' , 'op' => 'gt' , 'val' => 50000 ] ] ;

        $result = $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ;

        $this->assertSame( $filters , $result ) ;
    }

    /**
     * Cycle in the FALLBACKS table → cascade short-circuits, the standard
     * SILENT_DOWNGRADE policy applies (clause silently dropped).
     */
    public function testKeysFallbacksCycleFallsBackOnPolicy() : void
    {
        $init = $this->keysCascadeInit() ;
        $init[ ControllerParam::CAPABILITIES ][ ControllerParam::FILTER ][ Capability::FALLBACKS ] =
        [
            'salary'       => 'salary_range' ,
            'salary_range' => 'salary' ,        // closes the loop
        ] ;

        $fixture = new CapabilityGuardFixture
        (
            $init ,
            $this->makeEnforcerByAction
            ([
                'PARAM:filter.salary'       => false ,
                'PARAM:filter.salary_range' => false ,
            ])
        ) ;

        $filters = [ [ 'key' => 'salary' , 'op' => 'gt' , 'val' => 50000 ] ] ;

        $this->assertSame( [] , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    /**
     * Cascade exhausted (no entry for the current tier) → standard policy
     * applies (clause dropped under SILENT_DOWNGRADE).
     */
    public function testKeysFallbacksExhaustedFallsBackOnPolicy() : void
    {
        $init = $this->keysCascadeInit() ;
        $init[ ControllerParam::CAPABILITIES ][ ControllerParam::FILTER ][ Capability::FALLBACKS ] =
        [
            'salary' => 'salary_range' , // single hop, then chain stops
        ] ;

        $fixture = new CapabilityGuardFixture
        (
            $init ,
            $this->makeEnforcerByAction
            ([
                'PARAM:filter.salary'       => false ,
                'PARAM:filter.salary_range' => false ,
            ])
        ) ;

        $filters = [ [ 'key' => 'salary' , 'op' => 'gt' , 'val' => 50000 ] ] ;

        $this->assertSame( [] , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    /**
     * STRICT policy + cascade exhausted → throws 403, with the *original*
     * forbidden key surfaced in the message (not the cascade target).
     */
    public function testKeysFallbacksStrictThrowsWhenCascadeExhausted() : void
    {
        $fixture = new CapabilityGuardFixture
        (
            $this->keysCascadeInit( CapabilityPolicy::STRICT ) ,
            $this->makeEnforcerByAction
            ([
                'PARAM:filter.salary'       => false ,
                'PARAM:filter.salary_range' => false ,
            ])
        ) ;

        $filters = [ [ 'key' => 'salary' , 'op' => 'gt' , 'val' => 50000 ] ] ;

        // Note: this cascade lands on the ungated 'salary_bucket' tier so
        // STRICT does **not** throw — it's the legitimate substitution path.
        $result = $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ;
        $this->assertSame( 'salary_bucket' , $result[ 0 ][ 'key' ] ?? null ) ;

        // Now break the ungated escape — both tiers gated and denied, no floor.
        $init = $this->keysCascadeInit( CapabilityPolicy::STRICT ) ;
        $init[ ControllerParam::CAPABILITIES ][ ControllerParam::FILTER ][ Capability::FALLBACKS ] =
        [
            'salary' => 'salary_range' , // single hop, no ungated floor
        ] ;

        $fixture = new CapabilityGuardFixture
        (
            $init ,
            $this->makeEnforcerByAction
            ([
                'PARAM:filter.salary'       => false ,
                'PARAM:filter.salary_range' => false ,
            ])
        ) ;

        $this->expectException( Error403::class ) ;
        $this->expectExceptionMessage( "Forbidden filter key: 'salary'" ) ;
        $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ;
    }

    /**
     * Malformed FALLBACKS entry (non-string target) → cascade bails out, the
     * standard policy applies.
     */
    public function testKeysFallbacksMalformedTargetFallsBackOnPolicy() : void
    {
        $init = $this->keysCascadeInit() ;
        $init[ ControllerParam::CAPABILITIES ][ ControllerParam::FILTER ][ Capability::FALLBACKS ] =
        [
            'salary' => 42 , // non-string target
        ] ;

        $fixture = new CapabilityGuardFixture
        (
            $init ,
            $this->makeEnforcerByAction
            ([
                'PARAM:filter.salary'       => false ,
                'PARAM:filter.salary_range' => true  ,
            ])
        ) ;

        $filters = [ [ 'key' => 'salary' , 'op' => 'gt' , 'val' => 50000 ] ] ;

        $this->assertSame( [] , $fixture->enforceFilterKeys( $this->makeRequest() , ControllerParam::FILTER , $filters ) ) ;
    }

    // -------------------------------------------------------------------------
    // Multi-permissions per value (REQUIRE OR / DENY OR)
    // -------------------------------------------------------------------------

    /**
     * Builds a config where SKIN_FULL is gated behind a list of subjects (OR).
     *
     * @param array<int,string>|array<string,mixed> $entry The VALUES entry for SKIN_FULL.
     */
    private function multiPermInit( mixed $entry ) : array
    {
        return
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT    => self::OBJECT ,
                ControllerParam::SKIN =>
                [
                    Capability::POLICY   => CapabilityPolicy::SILENT_DOWNGRADE ,
                    Capability::FALLBACK => self::SKIN_DEFAULT ,
                    Capability::VALUES   =>
                    [
                        self::SKIN_FULL => $entry ,
                    ],
                ],
            ],
        ] ;
    }

    /**
     * REQUIRE OR via positional list — at least one subject granted = allowed.
     */
    public function testRequireOrPositionalListGrantsIfAnyMatches() : void
    {
        $entry   = [ self::SUBJECT_FULL , 'products:skin.premium' ] ;
        $fixture = new CapabilityGuardFixture
        (
            $this->multiPermInit( $entry ) ,
            $this->makeEnforcerByAction
            ([
                'PARAM:skin.offers.full' => false ,
                'PARAM:skin.premium'     => true  ,
            ])
        ) ;

        $this->assertSame
        (
            self::SKIN_FULL ,
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    /**
     * REQUIRE OR via positional list — every subject denied = downgrade to fallback.
     */
    public function testRequireOrPositionalListDeniesIfNoneMatches() : void
    {
        $entry   = [ self::SUBJECT_FULL , 'products:skin.premium' ] ;
        $fixture = new CapabilityGuardFixture
        (
            $this->multiPermInit( $entry ) ,
            $this->makeEnforcerByAction
            ([
                'PARAM:skin.offers.full' => false ,
                'PARAM:skin.premium'     => false ,
            ])
        ) ;

        $this->assertSame
        (
            self::SKIN_DEFAULT ,
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    /**
     * REQUIRE OR via long form `[ Capability::REQUIRE => [ ... ] ]`.
     */
    public function testRequireOrLongFormGrantsIfAnyMatches() : void
    {
        $entry = [ Capability::REQUIRE => [ self::SUBJECT_FULL , 'products:skin.premium' ] ] ;

        $fixture = new CapabilityGuardFixture
        (
            $this->multiPermInit( $entry ) ,
            $this->makeEnforcerByAction
            ([
                'PARAM:skin.offers.full' => true ,
                'PARAM:skin.premium'     => false ,
            ])
        ) ;

        $this->assertSame
        (
            self::SKIN_FULL ,
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    /**
     * DENY OR — value is blocked when at least one DENY subject matches.
     *
     * DENY mode reads getImplicitPermissionsForUser (not enforce) and looks
     * for tuples whose effect is `deny`. We simulate "user has an explicit
     * deny on products:skin.locked" with one such tuple.
     */
    public function testDenyOrBlocksIfAnyDeniesMatches() : void
    {
        $entry = [ Capability::DENY => [ self::SUBJECT_SPECIAL , 'products:skin.locked' ] ] ;

        $fixture = new CapabilityGuardFixture
        (
            $this->multiPermInit( $entry ) ,
            $this->makeEnforcerByAction
            (
                permissionsByAction : [] ,
                implicitPermissions :
                [
                    // user has a deny policy targeting skin.locked
                    [ self::USER_ID , self::DOMAIN , self::OBJECT , 'PARAM:skin.locked' , 'deny' ] ,
                ]
            )
        ) ;

        $this->assertSame
        (
            self::SKIN_DEFAULT , // downgraded
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }

    /**
     * DENY OR — value is allowed when no DENY subject matches.
     */
    public function testDenyOrAllowsWhenNoSubjectMatches() : void
    {
        $entry = [ Capability::DENY => [ self::SUBJECT_SPECIAL , 'products:skin.locked' ] ] ;

        $fixture = new CapabilityGuardFixture
        (
            $this->multiPermInit( $entry ) ,
            // No implicit deny on either subject → both checks pass → allowed
            $this->makeEnforcerByAction
            (
                permissionsByAction : [] ,
                implicitPermissions : []
            )
        ) ;

        $this->assertSame
        (
            self::SKIN_FULL ,
            $fixture->enforceParam( $this->makeRequest() , ControllerParam::SKIN , self::SKIN_FULL )
        ) ;
    }
}
