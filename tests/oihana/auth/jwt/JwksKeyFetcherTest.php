<?php

namespace tests\oihana\auth\jwt;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

use Memcached;

use oihana\auth\jwt\JwksKeyFetcher;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use Throwable;

#[CoversClass( JwksKeyFetcher::class )]
class JwksKeyFetcherTest extends TestCase
{
    /**
     * A valid JWKS JSON response for testing.
     */
    private const string JWKS_JSON = '{"keys":[{"kty":"RSA","use":"sig","kid":"test-key-1","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256"}]}' ;

    /**
     * Another valid key set, as the endpoint serves it once its keys were rotated.
     */
    private const string ROTATED_JSON = '{"keys":[{"kty":"RSA","use":"sig","kid":"test-key-2","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256"}]}' ;

    private const string URI = 'https://example.com/.well-known/jwks.json' ;

    /**
     * A Memcached double backed by an array : what one fetcher writes, another one
     * reads — which is the whole point of keeping the markers in the cache.
     *
     * `add()` behaves as the real one does : it writes nothing, and answers false,
     * when the key is already there.
     *
     * @param array<string,mixed> $store The entries, shared with the test.
     */
    private function cache( array &$store ) :Memcached
    {
        $cache = $this->createStub( Memcached::class ) ;

        $cache->method( 'get' )->willReturnCallback
        (
            function( $key ) use ( &$store ) : mixed { return $store[ $key ] ?? false ; }
        ) ;

        $cache->method( 'set' )->willReturnCallback
        (
            function( $key , $value ) use ( &$store ) : bool { $store[ $key ] = $value ; return true ; }
        ) ;

        $cache->method( 'add' )->willReturnCallback
        (
            function( $key , $value ) use ( &$store ) : bool
            {
                if ( array_key_exists( $key , $store ) )
                {
                    return false ;
                }

                $store[ $key ] = $value ;

                return true ;
            }
        ) ;

        $cache->method( 'delete' )->willReturnCallback
        (
            function( $key ) use ( &$store ) : bool { unset( $store[ $key ] ) ; return true ; }
        ) ;

        return $cache ;
    }

    /**
     * An endpoint that is out of reach.
     */
    private function refused() :ConnectException
    {
        return new ConnectException( 'connection refused' , new Request( 'GET' , self::URI ) ) ;
    }

    /**
     * Builds a Guzzle client answering the given results in order, and counts the
     * calls it received.
     *
     * @param array<int,Response|Throwable> $results What the endpoint answers, call after call.
     * @param int                           $calls   Incremented on every call made.
     */
    private function endpoint( array $results , ?int &$calls = 0 ) :Client
    {
        $calls = 0 ;

        $stack = HandlerStack::create( new MockHandler( $results ) ) ;

        $stack->push( function( callable $handler ) use ( &$calls ) : callable
        {
            return function( $request , array $options ) use ( $handler , &$calls )
            {
                $calls++ ;

                return $handler( $request , $options ) ;
            } ;
        }) ;

        return new Client([ 'handler' => $stack ]) ;
    }

    // ------------------------------------------------------------------
    // getKeys()
    // ------------------------------------------------------------------

    /**
     * Tests that getKeys returns cached data when available.
     */
    public function testGetKeysReturnsCachedKeys() :void
    {
        $store = [ JwksKeyFetcher::CACHE_KEY => self::JWKS_JSON ] ;

        $fetcher = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint( [] , $calls ) ) ;

        $keys = $fetcher->getKeys() ;

        $this->assertArrayHasKey( 'test-key-1' , $keys ) ;
        $this->assertSame( 0 , $calls , 'cached keys are served without a call' ) ;
    }

    /**
     * Tests that getKeys fetches from the endpoint on a cache miss and caches
     * the raw JSON before parsing it.
     */
    public function testGetKeysFetchesAndCachesOnCacheMiss() :void
    {
        $stored = null ;

        $cache = $this->createStub( Memcached::class ) ;
        $cache->method( 'get' )->willReturn( false ) ;
        $cache->method( 'set' )->willReturnCallback
        (
            function ( $key , $value , $ttl ) use ( &$stored ) : bool
            {
                $stored = [ $key , $value , $ttl ] ;
                return true ;
            }
        ) ;

        $client = $this->mockClient( new Response( 200 , [] , self::JWKS_JSON ) ) ;

        $fetcher = new JwksKeyFetcher( $cache , self::URI , null , $client ) ;

        $keys = $fetcher->getKeys() ;

        $this->assertArrayHasKey( 'test-key-1' , $keys ) ;
        $this->assertSame
        (
            [ JwksKeyFetcher::CACHE_KEY , self::JWKS_JSON , JwksKeyFetcher::CACHE_TTL ] ,
            $stored
        ) ;
    }

    /**
     * Tests that getKeys returns empty array when cache is empty and fetch fails.
     */
    public function testGetKeysReturnsEmptyOnCacheMissAndFetchFailure() :void
    {
        $store = [] ;

        $fetcher = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ $this->refused() ]) ) ;

        $this->assertSame( [] , $fetcher->getKeys() ) ;
    }

    /**
     * A failed call is remembered for {@see JwksKeyFetcher::FAILURE_TTL} seconds,
     * under its own key and with that lifetime.
     */
    public function testAFailedFetchIsRememberedForAShortWhile() :void
    {
        $stored = [] ;

        $cache = $this->createStub( Memcached::class ) ;
        $cache->method( 'get' )->willReturn( false ) ;
        $cache->method( 'set' )->willReturnCallback
        (
            function ( $key , $value , $ttl ) use ( &$stored ) : bool
            {
                $stored[ $key ] = $ttl ;
                return true ;
            }
        ) ;

        new JwksKeyFetcher( $cache , self::URI , null , $this->endpoint([ $this->refused() ]) )->getKeys() ;

        $this->assertSame( [ JwksKeyFetcher::UNAVAILABLE_KEY => JwksKeyFetcher::FAILURE_TTL ] , $stored ) ;
    }

    /**
     * 🚨 Every request builds its own fetcher. The second one, a moment after a
     * failed call, must not call again and wait for the same timeout : it answers
     * at once from what the first one left in the cache.
     */
    public function testARememberedFailureSparesTheNextRequestTheCall() :void
    {
        $store = [] ;

        new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ $this->refused() ]) )->getKeys() ;

        // A second request, a second object — and an endpoint that would answer if it were asked.
        $second = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ new Response( 200 , [] , self::JWKS_JSON ) ] , $calls ) ) ;

        $this->assertSame( [] , $second->getKeys() ) ;
        $this->assertSame( 0 , $calls , 'the endpoint is not called again while the failure is remembered' ) ;
    }

    /**
     * The remembered failure says the endpoint is down, not that the keys are
     * gone : keys that are cached are still served.
     */
    public function testARememberedFailureDoesNotHideCachedKeys() :void
    {
        $store = [ JwksKeyFetcher::CACHE_KEY => self::JWKS_JSON , JwksKeyFetcher::UNAVAILABLE_KEY => time() ] ;

        $fetcher = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint( [] ) ) ;

        $this->assertArrayHasKey( 'test-key-1' , $fetcher->getKeys() ) ;
    }

    /**
     * An endpoint that answers nothing has not answered : nothing is cached as
     * the keys, and the failure is remembered.
     */
    public function testAnEmptyAnswerIsAFailure() :void
    {
        $store = [] ;

        $fetcher = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ new Response( 200 , [] , '' ) ]) ) ;

        $this->assertSame( [] , $fetcher->getKeys() ) ;
        $this->assertArrayNotHasKey( JwksKeyFetcher::CACHE_KEY , $store ) ;
        $this->assertArrayHasKey( JwksKeyFetcher::UNAVAILABLE_KEY , $store ) ;
    }

    // ------------------------------------------------------------------
    // refreshKeys()
    // ------------------------------------------------------------------

    /**
     * A rotation : the endpoint serves new keys, which replace the cached ones.
     */
    public function testRefreshKeysReplacesTheCachedKeys() :void
    {
        $store = [ JwksKeyFetcher::CACHE_KEY => self::JWKS_JSON ] ;

        $fetcher = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ new Response( 200 , [] , self::ROTATED_JSON ) ] , $calls ) ) ;

        $keys = $fetcher->refreshKeys() ;

        $this->assertSame( 1 , $calls , 'the endpoint is called whatever the cache holds' ) ;
        $this->assertArrayHasKey( 'test-key-2' , $keys ) ;
        $this->assertSame( self::ROTATED_JSON , $store[ JwksKeyFetcher::CACHE_KEY ] ) ;
        $this->assertArrayHasKey( JwksKeyFetcher::REFRESHED_KEY , $store ) ;
    }

    /**
     * 🚨 The cached keys are not dropped before the new ones are in hand. A
     * refresh that fails answers nothing — the caller could not be given keys it
     * has just found wanting — and leaves the cache as it was, for everybody else.
     */
    public function testAFailedRefreshKeepsTheCachedKeysAndAnswersNothing() :void
    {
        $store = [ JwksKeyFetcher::CACHE_KEY => self::JWKS_JSON ] ;

        $fetcher = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ $this->refused() ]) ) ;

        $this->assertSame( [] , $fetcher->refreshKeys() ) ;

        $this->assertSame( self::JWKS_JSON , $store[ JwksKeyFetcher::CACHE_KEY ] , 'the cached keys survive a failed refresh' ) ;

        // The next request still verifies its tokens, from the cache.
        $next = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint( [] ) ) ;

        $this->assertArrayHasKey( 'test-key-1' , $next->getKeys() ) ;
    }

    /**
     * 🔑 The cooldown belongs to a refresh that succeeded. A failed one must not
     * hold it : the tokens signed by a new key would be refused for a minute.
     */
    public function testAFailedRefreshDoesNotStartTheCooldown() :void
    {
        $store = [ JwksKeyFetcher::CACHE_KEY => self::JWKS_JSON ] ;

        new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ $this->refused() ]) )->refreshKeys() ;

        $this->assertArrayNotHasKey( JwksKeyFetcher::REFRESHED_KEY , $store ) ;
        $this->assertArrayHasKey( JwksKeyFetcher::UNAVAILABLE_KEY , $store ) ;
    }

    /**
     * While a failure is remembered, a refresh makes no call either, and still
     * answers nothing.
     */
    public function testARefreshMakesNoCallWhileAFailureIsRemembered() :void
    {
        $store = [ JwksKeyFetcher::CACHE_KEY => self::JWKS_JSON , JwksKeyFetcher::UNAVAILABLE_KEY => time() ] ;

        $fetcher = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ new Response( 200 , [] , self::ROTATED_JSON ) ] , $calls ) ) ;

        $this->assertSame( [] , $fetcher->refreshKeys() ) ;
        $this->assertSame( 0 , $calls ) ;
        $this->assertSame( self::JWKS_JSON , $store[ JwksKeyFetcher::CACHE_KEY ] ) ;
    }

    /**
     * 🚨 The limit holds **from one object to the next** : under a
     * process-per-request runtime a limit kept in a property starts again from
     * zero with every request, and a stream of tokens with a wrong signature
     * would call the endpoint once each.
     */
    public function testRefreshKeysIsLimitedAcrossFetchers() :void
    {
        $store = [ JwksKeyFetcher::CACHE_KEY => self::JWKS_JSON ] ;

        new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ new Response( 200 , [] , self::ROTATED_JSON ) ] , $first ) )->refreshKeys() ;

        // Another request, another object, the same cache : the cooldown is seen.
        $second = new JwksKeyFetcher( $this->cache( $store ) , self::URI , null , $this->endpoint([ new Response( 200 , [] , self::JWKS_JSON ) ] , $calls ) ) ;

        $keys = $second->refreshKeys() ;

        $this->assertSame( 1 , $first ) ;
        $this->assertSame( 0 , $calls , 'a refresh inside the cooldown makes no call' ) ;
        $this->assertArrayHasKey( 'test-key-2' , $keys , 'and serves the keys the last refresh cached' ) ;
    }

    /**
     * The cooldown is claimed with its own key and lifetime.
     */
    public function testTheCooldownIsClaimedForItsDuration() :void
    {
        $claimed = null ;

        $cache = $this->createStub( Memcached::class ) ;
        $cache->method( 'get' )->willReturn( false ) ;
        $cache->method( 'set' )->willReturn( true ) ;
        $cache->method( 'add' )->willReturnCallback
        (
            function ( $key , $value , $ttl ) use ( &$claimed ) : bool
            {
                $claimed = [ $key , $ttl ] ;
                return true ;
            }
        ) ;

        new JwksKeyFetcher( $cache , self::URI , null , $this->mockClient( new Response( 200 , [] , self::JWKS_JSON ) ) )->refreshKeys() ;

        $this->assertSame( [ JwksKeyFetcher::REFRESHED_KEY , JwksKeyFetcher::REFRESH_COOLDOWN ] , $claimed ) ;
    }

    // ------------------------------------------------------------------
    // The durations, and how a subclass changes them
    // ------------------------------------------------------------------

    /**
     * Tests the cache key constant.
     */
    public function testCacheKeyConstant() :void
    {
        $this->assertSame( 'jwks:keys' , JwksKeyFetcher::CACHE_KEY ) ;
    }

    /**
     * Tests the cache TTL constant.
     */
    public function testCacheTtlConstant() :void
    {
        $this->assertSame( 3600 , JwksKeyFetcher::CACHE_TTL ) ;
    }

    /**
     * The two markers, their keys and their lifetimes.
     */
    public function testMarkerConstants() :void
    {
        $this->assertSame( 'jwks:refreshed'   , JwksKeyFetcher::REFRESHED_KEY ) ;
        $this->assertSame( 'jwks:unavailable' , JwksKeyFetcher::UNAVAILABLE_KEY ) ;
        $this->assertSame( 60 , JwksKeyFetcher::REFRESH_COOLDOWN ) ;
        $this->assertSame( 5  , JwksKeyFetcher::FAILURE_TTL ) ;
    }

    /**
     * 🔑 The durations are read through `static::` : a subclass redefining a
     * constant changes how long a failure is remembered without rewriting a method.
     */
    public function testASubclassChangesTheDurationOfARememberedFailure() :void
    {
        $stored = [] ;

        $cache = $this->createStub( Memcached::class ) ;
        $cache->method( 'get' )->willReturn( false ) ;
        $cache->method( 'set' )->willReturnCallback
        (
            function ( $key , $value , $ttl ) use ( &$stored ) : bool
            {
                $stored[ $key ] = $ttl ;
                return true ;
            }
        ) ;

        $patient = new class( $cache , self::URI , null , $this->endpoint([ $this->refused() ]) ) extends JwksKeyFetcher
        {
            public const int FAILURE_TTL = 30 ;
        } ;

        $patient->getKeys() ;

        $this->assertSame( [ JwksKeyFetcher::UNAVAILABLE_KEY => 30 ] , $stored ) ;
    }

    /**
     * Builds a Guzzle client whose single queued result is the given response
     * or exception, so the JWKS fetch path runs without touching the network.
     *
     * @param Response|\Throwable $result
     */
    private function mockClient( $result ) :Client
    {
        return new Client( [ 'handler' => HandlerStack::create( new MockHandler( [ $result ] ) ) ] ) ;
    }
}
