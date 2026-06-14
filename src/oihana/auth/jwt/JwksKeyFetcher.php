<?php

namespace oihana\auth\jwt;

use Firebase\JWT\JWK;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

use oihana\enums\http\GuzzleOption;
use xyz\oihana\schema\constants\JWTAlgorithm;

use Memcached;
use Psr\Log\LoggerInterface;

/**
 * Fetches and caches JWKS public keys from a Zitadel (or any OIDC) endpoint.
 *
 * Uses Memcached to cache the raw JWKS JSON and provides parsed keys
 * compatible with firebase/php-jwt for JWT signature verification.
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
     * Minimum interval between forced refreshes (in seconds).
     */
    public const int REFRESH_COOLDOWN = 60 ;

    /**
     * Timestamp of the last forced refresh.
     */
    private int $lastRefresh = 0 ;

    /**
     * Returns the parsed JWKS public keys.
     *
     * Fetches from cache first, then from the JWKS endpoint if not cached.
     *
     * @return array Parsed key set compatible with Firebase\JWT\JWT::decode()
     */
    public function getKeys() :array
    {
        $json = $this->cache->get( self::CACHE_KEY ) ;

        if( !$json )
        {
            try
            {
                $json = $this->httpClient->get( $this->jwksUri )->getBody()->getContents() ;
                $this->logger?->info( "JwksKeyFetcher: fetched JWKS from $this->jwksUri" ) ;
                $this->cache->set( self::CACHE_KEY , $json , self::CACHE_TTL ) ;
            }
            catch( GuzzleException $e )
            {
                $this->logger?->error( "JwksKeyFetcher: failed to fetch JWKS: {$e->getMessage()}" ) ;
                $json = null ;
            }
        }

        if( !$json )
        {
            $this->logger?->error( 'JwksKeyFetcher: failed to fetch JWKS keys' ) ;
            return [] ;
        }

        $keySet = json_decode( $json , true ) ;

        return JWK::parseKeySet( $keySet , JWTAlgorithm::RS256 ) ;
    }

    /**
     * Forces a refresh of the cached JWKS keys.
     *
     * Rate-limited to prevent abuse (max once per REFRESH_COOLDOWN seconds).
     *
     * @return array Parsed key set
     */
    public function refreshKeys() :array
    {
        $now = time() ;

        if( ( $now - $this->lastRefresh ) < self::REFRESH_COOLDOWN )
        {
            $this->logger?->warning( 'JwksKeyFetcher: refresh cooldown active, using cached keys' ) ;
            return $this->getKeys() ;
        }

        $this->lastRefresh = $now ;

        $this->cache->delete( self::CACHE_KEY ) ;

        $this->logger?->info( 'JwksKeyFetcher: forced refresh of JWKS keys' ) ;

        return $this->getKeys() ;
    }
}
