<?php

namespace tests\oihana\auth\jwt;

use Memcached;

use oihana\auth\jwt\JwksKeyFetcher;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass( JwksKeyFetcher::class )]
class JwksKeyFetcherTest extends TestCase
{
    /**
     * A valid JWKS JSON response for testing.
     */
    private const string JWKS_JSON = '{"keys":[{"kty":"RSA","use":"sig","kid":"test-key-1","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256"}]}' ;

    /**
     * Tests that getKeys returns cached data when available.
     */
    public function testGetKeysReturnsCachedKeys() :void
    {
        $cache = $this->createStub( Memcached::class ) ;

        $cache->method( 'get' )->willReturn( self::JWKS_JSON ) ;

        $fetcher = new JwksKeyFetcher( $cache , 'https://example.com/.well-known/jwks.json' ) ;

        $keys = $fetcher->getKeys() ;

        $this->assertNotEmpty( $keys ) ;
        $this->assertArrayHasKey( 'test-key-1' , $keys ) ;
    }

    /**
     * Tests that getKeys returns empty array when cache is empty and fetch fails.
     */
    public function testGetKeysReturnsEmptyOnCacheMissAndFetchFailure() :void
    {
        $cache = $this->createStub( Memcached::class ) ;

        $cache->method( 'get' )->willReturn( false ) ;

        // Invalid URI will cause Guzzle to fail
        $fetcher = new JwksKeyFetcher( $cache , 'https://invalid.nonexistent.localhost/jwks' ) ;

        $keys = $fetcher->getKeys() ;

        $this->assertEmpty( $keys ) ;
    }

    /**
     * Tests that refreshKeys deletes cache and refetches.
     */
    public function testRefreshKeysDeletesCache() :void
    {
        $deleted = false ;

        $cache = $this->createStub( Memcached::class ) ;

        $cache->method( 'delete' )->willReturnCallback( function() use ( &$deleted )
        {
            $deleted = true ;
            return true ;
        }) ;

        $cache->method( 'get' )->willReturn( self::JWKS_JSON ) ;

        $fetcher = new JwksKeyFetcher( $cache , 'https://example.com/.well-known/jwks.json' ) ;

        $keys = $fetcher->refreshKeys() ;

        $this->assertTrue( $deleted ) ;
        $this->assertNotEmpty( $keys ) ;
    }

    /**
     * Tests that refreshKeys is rate-limited by cooldown.
     */
    public function testRefreshKeysRateLimited() :void
    {
        $deleteCount = 0 ;

        $cache = $this->createStub( Memcached::class ) ;

        $cache->method( 'delete' )->willReturnCallback( function() use ( &$deleteCount )
        {
            $deleteCount++ ;
            return true ;
        }) ;

        $cache->method( 'get' )->willReturn( self::JWKS_JSON ) ;

        $fetcher = new JwksKeyFetcher( $cache , 'https://example.com/.well-known/jwks.json' ) ;

        // First refresh should work
        $fetcher->refreshKeys() ;

        // Second refresh within cooldown should not delete cache again
        $fetcher->refreshKeys() ;

        $this->assertSame( 1 , $deleteCount ) ;
    }

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
}
