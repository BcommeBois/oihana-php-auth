<?php

namespace tests\oihana\auth\jwt ;

use oihana\auth\exceptions\IdTokenValidationException ;
use oihana\auth\jwt\IdTokenValidator ;
use oihana\auth\jwt\JwksKeyFetcher ;

use PHPUnit\Framework\Attributes\CoversClass ;
use PHPUnit\Framework\TestCase ;

use stdClass ;

#[CoversClass( IdTokenValidator::class )]
class IdTokenValidatorTest extends TestCase
{
    private const string EXPECTED_ISSUER = 'https://issuer.example.com' ;
    private const string EXPECTED_SUB    = 'user-123' ;

    /**
     * validate() rejects a malformed id_token (decode failure).
     */
    public function testValidateRejectsMalformedIdToken() :void
    {
        $fetcher = $this->createStub( JwksKeyFetcher::class ) ;
        $fetcher->method( 'getKeys'     )->willReturn( [] ) ;
        $fetcher->method( 'refreshKeys' )->willReturn( [] ) ;

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
}
