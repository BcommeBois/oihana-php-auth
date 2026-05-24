<?php

namespace oihana\auth\jwt ;

use Firebase\JWT\ExpiredException ;
use Firebase\JWT\JWT ;
use Firebase\JWT\SignatureInvalidException ;

use oihana\auth\exceptions\IdTokenValidationException ;

use Psr\Log\LoggerInterface ;

use Throwable ;

/**
 * Validates an OIDC id_token (signed JWT, RS256) forwarded by the
 * NextJS-server wrapper through the `X-Id-Token` header.
 *
 * Reuses the shared `JwksKeyFetcher` (Memcached-cached JWKS) so no
 * extra round trip is incurred per request.
 *
 * Performed checks:
 *
 * - Signature (via JWKS, with retry on key rotation)
 * - `exp` (delegated to firebase/php-jwt)
 * - `iss` matches the expected issuer
 * - `sub` matches the access token's sub claim
 *
 * Note on audience: the id_token's `aud` contains the OIDC client_id
 * (e.g. NextJS app), which differs from the access token's audience
 * (Zitadel project id). Since the signature already proves the token
 * was minted by the expected issuer, and the `sub` match anchors it
 * to the same principal as the access token, audience enforcement
 * is intentionally omitted here. Hardening can add it later by
 * passing the expected client_id to validate().
 *
 * @package oihana\auth\jwt
 * @author  Marc Alcaraz
 */
class IdTokenValidator
{
    /**
     * Creates a new IdTokenValidator instance.
     *
     * @param JwksKeyFetcher       $fetcher        Shared JWKS fetcher for signature verification.
     * @param string               $expectedIssuer Expected `iss` claim (Zitadel instance URL).
     * @param LoggerInterface|null $logger         Optional logger.
     */
    public function __construct
    (
        protected JwksKeyFetcher     $fetcher ,
        protected string             $expectedIssuer ,
        protected ?LoggerInterface   $logger = null
    ) {}

    /**
     * Validates the id_token end-to-end: signature, expiration,
     * issuer and sub-match.
     *
     * @param string $idToken     The raw id_token JWT.
     * @param string $expectedSub The sub claim from the access token (must match).
     *
     * @return object Decoded claims (firebase/php-jwt object form).
     *
     * @throws IdTokenValidationException When any check fails.
     */
    public function validate( string $idToken , string $expectedSub ) :object
    {
        $decoded = $this->decode( $idToken ) ;

        if( $decoded === null )
        {
            throw new IdTokenValidationException( 'id_token signature or format invalid' ) ;
        }

        $this->validateClaims( $decoded , $expectedSub ) ;

        return $decoded ;
    }

    /**
     * Validates the decoded claims (issuer + sub match).
     *
     * Exposed publicly so the claim checks can be unit-tested without
     * forging a signed JWT.
     *
     * @param object $decoded     Decoded id_token claims.
     * @param string $expectedSub The sub claim from the access token.
     *
     * @throws IdTokenValidationException When iss or sub mismatch.
     */
    public function validateClaims( object $decoded , string $expectedSub ) :void
    {
        $iss = is_string( $decoded->iss ?? null ) ? $decoded->iss : '' ;

        if( $iss !== $this->expectedIssuer )
        {
            throw new IdTokenValidationException
            (
                "id_token issuer mismatch: expected $this->expectedIssuer, got $iss"
            ) ;
        }

        $sub = is_string( $decoded->sub ?? null ) ? $decoded->sub : '' ;

        if( $sub === '' || $sub !== $expectedSub )
        {
            throw new IdTokenValidationException
            (
                'id_token sub does not match the access token sub'
            ) ;
        }
    }

    // =========================================================================
    // Private
    // =========================================================================

    /**
     * Decode the id_token using cached JWKS, with one retry on key rotation.
     *
     * @param string $idToken The raw id_token JWT.
     *
     * @return object|null The decoded claims, or null on signature/format failure.
     */
    private function decode( string $idToken ) :?object
    {
        try
        {
            return JWT::decode( $idToken , $this->fetcher->getKeys() ) ;
        }
        catch( SignatureInvalidException )
        {
            try
            {
                return JWT::decode( $idToken , $this->fetcher->refreshKeys() ) ;
            }
            catch( Throwable $e )
            {
                $this->logger?->warning
                (
                    "IdTokenValidator: decode failed after key refresh: {$e->getMessage()}"
                ) ;
                return null ;
            }
        }
        catch( ExpiredException )
        {
            return null ;
        }
        catch( Throwable $e )
        {
            $this->logger?->warning
            (
                "IdTokenValidator: decode failed: {$e->getMessage()}"
            ) ;
            return null ;
        }
    }
}
