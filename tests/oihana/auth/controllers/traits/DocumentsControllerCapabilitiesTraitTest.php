<?php

namespace tests\oihana\auth\controllers\traits;

use Casbin\Enforcer;
use Casbin\Exceptions\CasbinException;

use oihana\auth\casbin\CapabilityEnforcer;
use oihana\auth\enums\Capability;
use oihana\auth\enums\CapabilityPolicy;
use oihana\auth\controllers\traits\DocumentsControllerCapabilitiesTrait;
use oihana\enums\http\RequestAttribute;
use oihana\controllers\enums\ControllerParam;
use oihana\exceptions\http\Error403;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;

use Psr\Http\Message\ServerRequestInterface as Request;

use Slim\Psr7\Factory\ServerRequestFactory;

/**
 * Named fixture exposing the capability-aware overrides. The three vendor
 * `prepareXxxBase` methods are redefined as class methods (class methods win
 * over trait methods) so the test drives their return value directly and the
 * override logic is exercised in isolation from the vendor PrepareXxx chain.
 */
class DocumentsCapabilitiesFixture
{
    use DocumentsControllerCapabilitiesTrait
    {
        prepareFilter          as public ;
        prepareSearch          as public ;
        prepareSkin            as public ;
        initializeCapabilities as public ;
    }

    /**
     * Canned return values for the base prepare methods.
     */
    public mixed $filterBaseReturn = null ;
    public mixed $searchBaseReturn = null ;
    public mixed $skinBaseReturn   = null ;

    /**
     * @param array<array-key,mixed>  $init
     * @param CapabilityEnforcer|null $enforcer
     */
    public function __construct( array $init = [] , ?CapabilityEnforcer $enforcer = null )
    {
        $this->initializeCapabilities( $init , $enforcer ) ;
    }

    /**
     * @param array<array-key,mixed>      $args
     * @param array<array-key,mixed>|null $params
     *
     * @return array<array-key,mixed>|null
     */
    protected function prepareFilterBase( ?Request $request , array $args = [] , ?array &$params = null ) : ?array
    {
        return $this->filterBaseReturn ;
    }

    /**
     * @param array<array-key,mixed>      $args
     * @param array<array-key,mixed>|null $params
     */
    protected function prepareSearchBase( ?Request $request , array $args = [] , ?array &$params = null ) : ?string
    {
        return $this->searchBaseReturn ;
    }

    /**
     * @param array<string,mixed>      $init
     * @param array<string,mixed>|null $params
     */
    protected function prepareSkinBase( ?Request $request , array $init = [] , ?array &$params = null , ?string $method = null ) : ?string
    {
        return $this->skinBaseReturn ;
    }
}

#[CoversTrait( DocumentsControllerCapabilitiesTrait::class )]
class DocumentsControllerCapabilitiesTraitTest extends TestCase
{
    private const string USER_ID = 'user-doc-001' ;
    private const string DOMAIN  = 'my-api' ;
    private const string OBJECT  = '/products' ;

    private function makeRequest( ?string $userId = self::USER_ID ) : Request
    {
        $request = new ServerRequestFactory()->createServerRequest( 'GET' , '/products' ) ;

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

    // -------------------------------------------------------------------------
    // prepareFilter()
    // -------------------------------------------------------------------------

    public function testPrepareFilterReturnsNullWhenBaseIsNotArray() : void
    {
        $fixture = new DocumentsCapabilitiesFixture( [] , null ) ;
        $fixture->filterBaseReturn = null ;

        $this->assertNull( $fixture->prepareFilter( $this->makeRequest() , [] ) ) ;
    }

    public function testPrepareFilterPassesThroughWhenNoEnforcement() : void
    {
        $fixture = new DocumentsCapabilitiesFixture( [] , null ) ; // no enforcer → no-op
        $filters = [ [ 'key' => 'name' , 'op' => 'eq' , 'val' => 'X' ] ] ;
        $fixture->filterBaseReturn = $filters ;

        $params = [ ControllerParam::FILTER => 'whatever' ] ;
        $result = $fixture->prepareFilter( $this->makeRequest() , [] , $params ) ;

        $this->assertSame( $filters , $result ) ;
        // payload unchanged → params not re-encoded
        $this->assertSame( 'whatever' , $params[ ControllerParam::FILTER ] ) ;
    }

    public function testPrepareFilterReencodesParamsWhenClauseDropped() : void
    {
        $init =
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT      => self::OBJECT ,
                ControllerParam::FILTER =>
                [
                    Capability::POLICY => CapabilityPolicy::SILENT_DOWNGRADE ,
                    Capability::KEYS   => [ 'costPrice' => 'products:filter.costPrice' ] ,
                ],
            ],
        ] ;

        $fixture = new DocumentsCapabilitiesFixture( $init , $this->makeEnforcer( false ) ) ;

        $filters =
        [
            [ 'key' => 'costPrice' , 'op' => 'gt' , 'val' => 100 ] , // dropped
            [ 'key' => 'name'      , 'op' => 'eq' , 'val' => 'X' ] , // kept
        ] ;
        $fixture->filterBaseReturn = $filters ;

        $params = [ ControllerParam::FILTER => json_encode( $filters ) ] ;
        $result = $fixture->prepareFilter( $this->makeRequest() , [] , $params ) ;

        $this->assertCount( 1 , $result ) ;
        $this->assertSame( 'name' , $result[ 0 ][ 'key' ] ?? null ) ;
        // params re-encoded to the effective (reduced) payload
        $this->assertSame( json_encode( $result ) , $params[ ControllerParam::FILTER ] ) ;
    }

    // -------------------------------------------------------------------------
    // prepareSearch()
    // -------------------------------------------------------------------------

    public function testPrepareSearchReturnsBaseWhenEmpty() : void
    {
        $fixture = new DocumentsCapabilitiesFixture( [] , null ) ;
        $fixture->searchBaseReturn = '' ;

        $this->assertSame( '' , $fixture->prepareSearch( $this->makeRequest() , [] ) ) ;
    }

    public function testPrepareSearchReturnsBaseWhenNull() : void
    {
        $fixture = new DocumentsCapabilitiesFixture( [] , null ) ;
        $fixture->searchBaseReturn = null ;

        $this->assertNull( $fixture->prepareSearch( $this->makeRequest() , [] ) ) ;
    }

    public function testPrepareSearchKeepsValueWhenAllowed() : void
    {
        $init = $this->searchInit( CapabilityPolicy::SILENT_DOWNGRADE ) ;
        $fixture = new DocumentsCapabilitiesFixture( $init , $this->makeEnforcer( true ) ) ;
        $fixture->searchBaseReturn = 'phone' ;

        $this->assertSame( 'phone' , $fixture->prepareSearch( $this->makeRequest() , [] ) ) ;
    }

    public function testPrepareSearchDowngradesToFallbackAndUpdatesParams() : void
    {
        $init = $this->searchInit( CapabilityPolicy::SILENT_DOWNGRADE , 'safe-search' ) ;
        $fixture = new DocumentsCapabilitiesFixture( $init , $this->makeEnforcer( false ) ) ;
        $fixture->searchBaseReturn = 'phone' ;

        $params = [ ControllerParam::SEARCH => 'phone' ] ;
        $result = $fixture->prepareSearch( $this->makeRequest() , [] , $params ) ;

        $this->assertSame( 'safe-search' , $result ) ;
        $this->assertSame( 'safe-search' , $params[ ControllerParam::SEARCH ] ) ;
    }

    public function testPrepareSearchDowngradesToNullWithoutParams() : void
    {
        // No FALLBACK → applyCapabilityPolicy returns null ; params is null so
        // the registered-value update is skipped.
        $init = $this->searchInit( CapabilityPolicy::SILENT_DOWNGRADE ) ;
        $fixture = new DocumentsCapabilitiesFixture( $init , $this->makeEnforcer( false ) ) ;
        $fixture->searchBaseReturn = 'phone' ;

        $this->assertNull( $fixture->prepareSearch( $this->makeRequest() , [] ) ) ;
    }

    public function testPrepareSearchStrictThrows() : void
    {
        $init = $this->searchInit( CapabilityPolicy::STRICT ) ;
        $fixture = new DocumentsCapabilitiesFixture( $init , $this->makeEnforcer( false ) ) ;
        $fixture->searchBaseReturn = 'phone' ;

        $this->expectException( Error403::class ) ;

        $fixture->prepareSearch( $this->makeRequest() , [] ) ;
    }

    // -------------------------------------------------------------------------
    // prepareSkin()
    // -------------------------------------------------------------------------

    public function testPrepareSkinKeepsValueWhenAllowed() : void
    {
        $init = $this->skinInit() ;
        $fixture = new DocumentsCapabilitiesFixture( $init , $this->makeEnforcer( true ) ) ;
        $fixture->skinBaseReturn = 'offers.full' ;

        $params = [ ControllerParam::SKIN => 'offers.full' ] ;
        $result = $fixture->prepareSkin( $this->makeRequest() , [] , $params ) ;

        $this->assertSame( 'offers.full' , $result ) ;
        $this->assertSame( 'offers.full' , $params[ ControllerParam::SKIN ] ) ;
    }

    public function testPrepareSkinDowngradesAndUpdatesParams() : void
    {
        $init = $this->skinInit() ;
        $fixture = new DocumentsCapabilitiesFixture( $init , $this->makeEnforcer( false ) ) ;
        $fixture->skinBaseReturn = 'offers.full' ;

        $params = [ ControllerParam::SKIN => 'offers.full' ] ;
        $result = $fixture->prepareSkin( $this->makeRequest() , [] , $params ) ;

        $this->assertSame( 'offers' , $result ) ; // downgraded to FALLBACK
        $this->assertSame( 'offers' , $params[ ControllerParam::SKIN ] ) ;
    }

    // -------------------------------------------------------------------------
    // Config builders
    // -------------------------------------------------------------------------

    /**
     * @return array<array-key,mixed>
     */
    private function searchInit( string $policy , ?string $fallback = null ) : array
    {
        $config =
        [
            Capability::POLICY  => $policy ,
            Capability::SUBJECT => 'products:search' ,
        ] ;

        if ( $fallback !== null )
        {
            $config[ Capability::FALLBACK ] = $fallback ;
        }

        return
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT      => self::OBJECT ,
                ControllerParam::SEARCH => $config ,
            ],
        ] ;
    }

    /**
     * @return array<array-key,mixed>
     */
    private function skinInit() : array
    {
        return
        [
            ControllerParam::CAPABILITIES =>
            [
                Capability::OBJECT    => self::OBJECT ,
                ControllerParam::SKIN =>
                [
                    Capability::POLICY   => CapabilityPolicy::SILENT_DOWNGRADE ,
                    Capability::FALLBACK => 'offers' ,
                    Capability::VALUES   => [ 'offers.full' => 'products:skin.offers.full' ] ,
                ],
            ],
        ] ;
    }
}
