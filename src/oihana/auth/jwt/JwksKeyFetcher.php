<?php

namespace oihana\auth\jwt;

use Firebase\JWT\JWK;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

use oihana\enums\http\GuzzleOption;
use xyz\oihana\schema\constants\JWTAlgorithm;

use Memcached;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Fetches and caches JWKS public keys from a Zitadel (or any OIDC) endpoint.
 *
 * Uses Memcached to cache the raw JWKS JSON and provides parsed keys
 * compatible with firebase/php-jwt for JWT signature verification.
 *
 * Three entries are kept in the cache, and each answers one question :
 *
 * | Key | Lifetime | What it says |
 * | :-- | :-- | :-- |
 * | {@see self::CACHE_KEY} | {@see self::CACHE_TTL} | the keys themselves |
 * | {@see self::REFRESHED_KEY} | {@see self::REFRESH_COOLDOWN} | a forced refresh succeeded a moment ago |
 * | {@see self::UNAVAILABLE_KEY} | {@see self::FAILURE_TTL} | the last call to the endpoint failed |
 *
 * 🚨 **An empty array means « no key could be served », never « no key exists ».**
 * Neither method throws when the endpoint is out of reach : both answer `[]`, and
 * a caller that decodes against it would get an error the token has nothing to do
 * with. Read `[]` as « the signature could not be checked », not as « refused ».
 *
 * 🚨 **What is cached is what was read.** An answer of the endpoint is parsed
 * before it is kept : a body that yields no key — the error page of a proxy, a
 * truncated document, an empty key set — is a failure of the call, never an
 * entry that would then fail every verification until it expires.
 *
 * 🔑 **The two markers live in the cache, not in the object.** Under a
 * process-per-request runtime every request builds its own fetcher : a limit
 * kept in a property would start again from zero each time, and limit nothing.
 *
 * 🔑 **The durations are read through `static::`**, so a subclass redefining a
 * constant changes the behaviour without rewriting a method.
 *
 * @package oihana\auth\jwt
 * @author  Marc Alcaraz
 */
class JwksKeyFetcher
{
    /**
     * Creates a new JwksKeyFetcher instance.
     *
     * @param Memcached            $cache      Cache backend for the raw JWKS JSON.
     * @param string               $jwksUri    The JWKS endpoint URL.
     * @param LoggerInterface|null $logger     Optional logger.
     * @param Client|null          $httpClient Optional Guzzle client (defaults to a TLS-verifying client with a 10s timeout); injectable for testing.
     */
    public function __construct
    (
        protected Memcached          $cache ,
        protected string             $jwksUri ,
        protected ?LoggerInterface   $logger     = null ,
        protected ?Client            $httpClient = null
    )
    {
        $this->httpClient ??= new Client([ GuzzleOption::TIMEOUT => 10 , GuzzleOption::VERIFY => true ]) ;
    }

    /**
     * Memcached cache key for JWKS data.
     */
    public const string CACHE_KEY = 'jwks:keys' ;

    /**
     * Default cache TTL in seconds (1 hour).
     */
    public const int CACHE_TTL = 3600 ;

    /**
     * How long, in seconds, a failed call to the endpoint is remembered : until
     * then no other call is made, and the keys that are not cached are answered
     * as unavailable at once.
     *
     * Short on purpose. It is there so that a queue of requests does not each
     * wait for the timeout of an endpoint that is down — not to delay the moment
     * the endpoint is seen back.
     */
    public const int FAILURE_TTL = 5 ;

    /**
     * Minimum interval between forced refreshes (in seconds).
     */
    public const int REFRESH_COOLDOWN = 60 ;

    /**
     * Memcached cache key marking that a forced refresh succeeded less than
     * {@see self::REFRESH_COOLDOWN} seconds ago.
     */
    public const string REFRESHED_KEY = 'jwks:refreshed' ;

    /**
     * Memcached cache key marking that the last call to the endpoint failed, less
     * than {@see self::FAILURE_TTL} seconds ago.
     */
    public const string UNAVAILABLE_KEY = 'jwks:unavailable' ;

    /**
     * Returns the parsed JWKS public keys.
     *
     * Fetches from cache first, then from the JWKS endpoint if not cached. A call
     * that failed a moment ago is not made again ({@see self::FAILURE_TTL}).
     *
     * @return array Parsed key set compatible with Firebase\JWT\JWT::decode(), or
     * an empty array when the keys are neither cached nor reachable.
     */
    public function getKeys() :array
    {
        $json = $this->cache->get( static::CACHE_KEY ) ;

        if( is_string( $json ) && $json !== '' )
        {
            $keys = $this->parse( $json ) ;

            if( $keys !== [] )
            {
                return $keys ;
            }

            // An entry that no longer parses is worth nothing, and would fail every
            // verification until it expires : dropped, and read again from the endpoint.
            $this->logger?->warning( 'JwksKeyFetcher: the cached JWKS cannot be read, dropped' ) ;

            $this->cache->delete( static::CACHE_KEY ) ;
        }

        $keys = $this->fetch() ;

        if( $keys === [] )
        {
            $this->logger?->error( 'JwksKeyFetcher: failed to fetch JWKS keys' ) ;
        }

        return $keys ;
    }

    /**
     * Fetches the JWKS keys again, whatever the cache holds — what a caller asks
     * for when a signature does not match the keys it has, which is how a key
     * rotation shows.
     *
     * 🚨 **The cached keys are never dropped before the new ones are in hand.**
     * They used to be deleted first : a refresh that then failed left no key at
     * all, for anybody, so that one token with a wrong signature was enough to
     * turn an endpoint that was down into an outage of every request.
     *
     * Three answers :
     *
     * - **a refresh succeeded a moment ago** ({@see self::REFRESH_COOLDOWN}) : the
     *   cached keys, and no call. The marker is claimed with an atomic `add()`, so
     *   two requests arriving together do not both refresh ;
     * - **the endpoint answers** : the cached keys are replaced, and the new ones
     *   returned ;
     * - **the endpoint does not answer** : an empty array — the caller has just
     *   found that the cached keys do not verify its token, and handing them back
     *   would have it conclude « refused » of a token a new key may have signed.
     *   The cached keys stay where they are, for every other request.
     *
     * 🔑 The cooldown is kept only by a refresh that succeeded. Kept by a failed
     * one too, it would refuse for a whole minute the tokens signed by a new key ;
     * repeated failures are bounded by {@see self::FAILURE_TTL} instead.
     *
     * @return array Parsed key set, or an empty array when the keys could not be refreshed.
     */
    public function refreshKeys() :array
    {
        if( !$this->cache->add( static::REFRESHED_KEY , time() , static::REFRESH_COOLDOWN ) )
        {
            $this->logger?->warning( 'JwksKeyFetcher: refresh cooldown active, using cached keys' ) ;
            return $this->getKeys() ;
        }

        $this->logger?->info( 'JwksKeyFetcher: forced refresh of JWKS keys' ) ;

        $keys = $this->fetch() ;

        if( $keys === [] )
        {
            $this->cache->delete( static::REFRESHED_KEY ) ;

            $this->logger?->error( 'JwksKeyFetcher: the JWKS keys could not be refreshed, the cached ones are kept' ) ;
        }

        return $keys ;
    }

    /**
     * Calls the JWKS endpoint, caches what it answers, and remembers a failure.
     *
     * Shared by a first read and by a forced refresh : the cache entry of the keys
     * is only ever **written** here, so a call that fails leaves what was cached
     * untouched.
     *
     * 🚨 **The answer is parsed before it is kept.** A body that yields no key is a
     * failure like a call that did not go through : nothing is cached, and the
     * failure is remembered. Cached first and parsed afterwards, such a body would
     * fail every verification for a whole {@see self::CACHE_TTL}, long after the
     * endpoint had started answering properly again.
     *
     * @return array The parsed key set, or an empty array when the endpoint gave no
     * key — it did not answer, answered something that is not a key set, or failed
     * less than {@see self::FAILURE_TTL} seconds ago.
     */
    private function fetch() :array
    {
        if( $this->cache->get( static::UNAVAILABLE_KEY ) )
        {
            return [] ;
        }

        try
        {
            $json = $this->httpClient->get( $this->jwksUri )->getBody()->getContents() ;
        }
        catch( GuzzleException $e )
        {
            $this->logger?->error( "JwksKeyFetcher: failed to fetch JWKS: {$e->getMessage()}" ) ;
            $json = '' ;
        }

        $keys = $json === '' ? [] : $this->parse( $json ) ;

        if( $keys === [] )
        {
            $this->cache->set( static::UNAVAILABLE_KEY , time() , static::FAILURE_TTL ) ;
            return [] ;
        }

        $this->logger?->info( "JwksKeyFetcher: fetched JWKS from $this->jwksUri" ) ;

        $this->cache->set( static::CACHE_KEY , $json , static::CACHE_TTL ) ;

        return $keys ;
    }

    /**
     * Parses a raw JWKS JSON into the key set `Firebase\JWT\JWT::decode()` reads.
     *
     * 🔑 **What cannot be read yields no key, and says so in the logs.** The
     * parser raises on a document that is not a key set — and PHP itself on a
     * body that is not even a document ; here both are one more way of having no
     * key to serve, which both callers already know how to answer.
     *
     * @param string $json The raw JWKS JSON.
     *
     * @return array Parsed key set, or an empty array when the document holds none.
     */
    private function parse( string $json ) :array
    {
        try
        {
            return JWK::parseKeySet( json_decode( $json , true ) , JWTAlgorithm::RS256 ) ;
        }
        catch( Throwable $e )
        {
            $this->logger?->error( "JwksKeyFetcher: the JWKS cannot be parsed: {$e->getMessage()}" ) ;
            return [] ;
        }
    }
}
