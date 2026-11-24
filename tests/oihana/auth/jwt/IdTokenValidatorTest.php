<?php

namespace tests\oihana\auth\jwt ;

use Firebase\JWT\JWT ;
use Firebase\JWT\Key ;

use oihana\auth\exceptions\IdTokenUnverifiableException ;
use oihana\auth\exceptions\IdTokenValidationException ;
use oihana\auth\jwt\IdTokenValidator ;
use oihana\auth\jwt\JwksKeyFetcher ;

use PHPUnit\Framework\Attributes\CoversClass ;
use PHPUnit\Framework\TestCase ;

use RuntimeException ;
use stdClass ;

#[CoversClass( IdTokenValidator::class )]
class IdTokenValidatorTest extends TestCase
{
    private const string EXPECTED_ISSUER = 'https://issuer.example.com' ;
    private const string EXPECTED_SUB    = 'user-123' ;

    /**
     * validate() rejects a malformed id_token (decode failure). The keys are
     * there : this is a token that was checked, and turned down.
     */
    public function testValidateRejectsMalformedIdToken() :void
    {
        [ , $public ] = $this->makeKeyPair() ;

        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys' )->willReturn( [ 'test-kid' => new Key( $public , 'RS256' ) ] ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        $this->expectException( IdTokenValidationException::class ) ;
        $this->expectExceptionMessage( 'signature or format invalid' ) ;

        $validator->validate( 'not-a-jwt' , self::EXPECTED_SUB ) ;
    }

    /**
     * validateClaims() accepts a payload whose iss + sub match expectations.
     */
    public function testValidateClaimsAcceptsMatchingIssuerAndSub() :void
    {
        $validator = $this->makeValidator() ;
        $decoded   = $this->makeClaims( self::EXPECTED_ISSUER , self::EXPECTED_SUB ) ;

        $validator->validateClaims( $decoded , self::EXPECTED_SUB ) ;

        $this->expectNotToPerformAssertions() ;
    }

    /**
     * validateClaims() rejects an issuer mismatch.
     */
    public function testValidateClaimsRejectsIssuerMismatch() :void
    {
        $validator = $this->makeValidator() ;
        $decoded   = $this->makeClaims( 'https://attacker.example.com' , self::EXPECTED_SUB ) ;

        $this->expectException( IdTokenValidationException::class ) ;
        $this->expectExceptionMessage( 'id_token issuer mismatch' ) ;

        $validator->validateClaims( $decoded , self::EXPECTED_SUB ) ;
    }

    /**
     * validateClaims() rejects a payload missing the `iss` claim.
     */
    public function testValidateClaimsRejectsMissingIssuer() :void
    {
        $validator = $this->makeValidator() ;
        $decoded   = new stdClass() ;
        $decoded->sub = self::EXPECTED_SUB ;

        $this->expectException( IdTokenValidationException::class ) ;
        $this->expectExceptionMessage( 'id_token issuer mismatch' ) ;

        $validator->validateClaims( $decoded , self::EXPECTED_SUB ) ;
    }

    /**
     * validateClaims() rejects a payload missing the `sub` claim.
     */
    public function testValidateClaimsRejectsMissingSub() :void
    {
        $validator = $this->makeValidator() ;
        $decoded   = new stdClass() ;
        $decoded->iss = self::EXPECTED_ISSUER ;

        $this->expectException( IdTokenValidationException::class ) ;
        $this->expectExceptionMessage( 'sub does not match' ) ;

        $validator->validateClaims( $decoded , self::EXPECTED_SUB ) ;
    }

    /**
     * validateClaims() rejects a sub mismatch.
     */
    public function testValidateClaimsRejectsSubMismatch() :void
    {
        $validator = $this->makeValidator() ;
        $decoded   = $this->makeClaims( self::EXPECTED_ISSUER , 'attacker-sub' ) ;

        $this->expectException( IdTokenValidationException::class ) ;
        $this->expectExceptionMessage( 'sub does not match' ) ;

        $validator->validateClaims( $decoded , self::EXPECTED_SUB ) ;
    }

    // =========================================================================
    // End-to-end validate() over a real RS256 signature
    // =========================================================================

    private const string KID = 'test-kid' ;

    /**
     * validate() accepts a correctly signed token whose iss + sub match.
     */
    public function testValidateAcceptsSignedTokenWithMatchingClaims() :void
    {
        [ $private , $public ] = $this->makeKeyPair() ;

        $jwt = $this->signJwt( $this->jwtPayload() , $private ) ;

        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys' )->willReturn( [ self::KID => new Key( $public , 'RS256' ) ] ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        $decoded = $validator->validate( $jwt , self::EXPECTED_SUB ) ;

        $this->assertSame( self::EXPECTED_SUB    , $decoded->sub ) ;
        $this->assertSame( self::EXPECTED_ISSUER , $decoded->iss ) ;
    }

    /**
     * validate() recovers when the cached key is stale: the first decode fails
     * with a signature error, the refreshed key set then verifies the token.
     */
    public function testValidateRetriesWithRefreshedKeysOnSignatureFailure() :void
    {
        [ $private , $public ]   = $this->makeKeyPair() ;
        [ , $otherPublic ]       = $this->makeKeyPair() ; // wrong key → signature failure

        $jwt = $this->signJwt( $this->jwtPayload() , $private ) ;

        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys'     )->willReturn( [ self::KID => new Key( $otherPublic , 'RS256' ) ] ) ;
        $fetcher->method( 'refreshKeys' )->willReturn( [ self::KID => new Key( $public      , 'RS256' ) ] ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        $decoded = $validator->validate( $jwt , self::EXPECTED_SUB ) ;

        $this->assertSame( self::EXPECTED_SUB , $decoded->sub ) ;
    }

    /**
     * validate() gives up (and logs) when even the refreshed key set cannot
     * verify the signature.
     */
    public function testValidateRejectsWhenRefreshedKeysStillFail() :void
    {
        [ $private ]       = $this->makeKeyPair() ;
        [ , $otherPublic ] = $this->makeKeyPair() ;

        $jwt = $this->signJwt( $this->jwtPayload() , $private ) ;

        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys'     )->willReturn( [ self::KID => new Key( $otherPublic , 'RS256' ) ] ) ;
        $fetcher->method( 'refreshKeys' )->willReturn( [ self::KID => new Key( $otherPublic , 'RS256' ) ] ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        $this->expectException( IdTokenValidationException::class ) ;
        $this->expectExceptionMessage( 'signature or format invalid' ) ;

        $validator->validate( $jwt , self::EXPECTED_SUB ) ;
    }

    /**
     * validate() rejects an expired token (decode short-circuits to null).
     */
    public function testValidateRejectsExpiredToken() :void
    {
        [ $private , $public ] = $this->makeKeyPair() ;

        $jwt = $this->signJwt( $this->jwtPayload( expiresAt : 1_000_000 ) , $private ) ; // long past

        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys' )->willReturn( [ self::KID => new Key( $public , 'RS256' ) ] ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        $this->expectException( IdTokenValidationException::class ) ;
        $this->expectExceptionMessage( 'signature or format invalid' ) ;

        $validator->validate( $jwt , self::EXPECTED_SUB ) ;
    }

    // =========================================================================
    // A token that could not be checked is not a token that failed
    // =========================================================================

    /**
     * 🚨 The fetcher answers an empty set when the keys are neither cached nor
     * reachable. Nothing is known of the token — which is correctly signed here —
     * and it is not reported as invalid.
     */
    public function testValidateDoesNotJudgeATokenWithoutAnyKey() :void
    {
        [ $private ] = $this->makeKeyPair() ;

        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys' )->willReturn( [] ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        $this->expectException( IdTokenUnverifiableException::class ) ;
        $this->expectExceptionMessage( IdTokenUnverifiableException::MESSAGE ) ;

        $validator->validate( $this->signJwt( $this->jwtPayload() , $private ) , self::EXPECTED_SUB ) ;
    }

    /**
     * Keys that cannot be read at all are not a refusal either, and what stopped
     * the read is kept.
     */
    public function testValidateDoesNotJudgeATokenWhenTheKeysCannotBeRead() :void
    {
        [ $private ] = $this->makeKeyPair() ;

        $failure = new RuntimeException( 'the cache is down' ) ;

        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys' )->willThrowException( $failure ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        try
        {
            $validator->validate( $this->signJwt( $this->jwtPayload() , $private ) , self::EXPECTED_SUB ) ;

            $this->fail( 'The token was judged without a key' ) ;
        }
        catch( IdTokenUnverifiableException $exception )
        {
            $this->assertSame( $failure , $exception->getPrevious() ) ;
        }
    }

    /**
     * 🚨 A rotation whose new keys cannot be fetched : the cached keys did not
     * verify the token, and the fresh ones are out of reach. The token may be
     * signed by a new key — it is not turned down.
     */
    public function testValidateDoesNotJudgeATokenWhenARotationCannotBeFollowed() :void
    {
        [ $private ]       = $this->makeKeyPair() ;
        [ , $otherPublic ] = $this->makeKeyPair() ;

        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys'     )->willReturn( [ self::KID => new Key( $otherPublic , 'RS256' ) ] ) ;
        $fetcher->method( 'refreshKeys' )->willReturn( [] ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        $this->expectException( IdTokenUnverifiableException::class ) ;

        $validator->validate( $this->signJwt( $this->jwtPayload() , $private ) , self::EXPECTED_SUB ) ;
    }

    /**
     * 🔑 Code written before the new exception existed catches the parent, and
     * keeps behaving as it did : telling the two apart is opt-in.
     */
    public function testAnOutageIsStillCaughtByCodeThatCatchesTheParent() :void
    {
        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys' )->willReturn( [] ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        $caught = null ;

        try
        {
            $validator->validate( 'any.token.here' , self::EXPECTED_SUB ) ;
        }
        catch( IdTokenValidationException $exception )
        {
            $caught = $exception ;
        }

        $this->assertInstanceOf( IdTokenUnverifiableException::class , $caught ) ;
    }

    /**
     * What does not change : a token checked against the keys and turned down is
     * the parent exception, and only that.
     */
    public function testATokenTurnedDownIsNotAnOutage() :void
    {
        [ $private , $public ] = $this->makeKeyPair() ;

        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys' )->willReturn( [ self::KID => new Key( $public , 'RS256' ) ] ) ;

        $validator = new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;

        try
        {
            $validator->validate( $this->signJwt( $this->jwtPayload( expiresAt : 1_000_000 ) , $private ) , self::EXPECTED_SUB ) ;

            $this->fail( 'An expired token was accepted' ) ;
        }
        catch( IdTokenValidationException $exception )
        {
            $this->assertNotInstanceOf( IdTokenUnverifiableException::class , $exception ) ;
        }
    }

    // =========================================================================
    // Private
    // =========================================================================

    private function makeClaims( string $iss , string $sub ) :stdClass
    {
        $claims = new stdClass() ;
        $claims->iss = $iss ;
        $claims->sub = $sub ;

        return $claims ;
    }

    private function makeValidator() :IdTokenValidator
    {
        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;

        return new IdTokenValidator( $fetcher , self::EXPECTED_ISSUER ) ;
    }

    /**
     * Generates a fresh 2048-bit RSA key pair.
     *
     * @return array{0:string,1:string} [ privateKeyPem , publicKeyPem ]
     */
    private function makeKeyPair() :array
    {
        $res = openssl_pkey_new
        ([
            'private_key_bits' => 2048 ,
            'private_key_type' => OPENSSL_KEYTYPE_RSA ,
        ]) ;

        openssl_pkey_export( $res , $private ) ;
        $public = openssl_pkey_get_details( $res )[ 'key' ] ;

        return [ $private , $public ] ;
    }

    /**
     * Builds a standard id_token payload.
     *
     * @return array<string,mixed>
     */
    private function jwtPayload( ?int $expiresAt = null ) :array
    {
        return
        [
            'iss' => self::EXPECTED_ISSUER ,
            'sub' => self::EXPECTED_SUB ,
            'iat' => 1_000 ,
            'exp' => $expiresAt ?? ( time() + 3600 ) ,
        ] ;
    }

    /**
     * Signs a payload as an RS256 JWT carrying the test kid.
     *
     * @param array<string,mixed> $payload
     */
    private function signJwt( array $payload , string $privateKey ) :string
    {
        return JWT::encode( $payload , $privateKey , 'RS256' , self::KID ) ;
    }
}
