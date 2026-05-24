<?php

namespace tests\oihana\auth\jwt\helpers ;

use PHPUnit\Framework\TestCase ;
use stdClass ;

use function oihana\auth\jwt\helpers\extractSidFromClaims ;

/**
 * Unit coverage for {@see extractSidFromClaims()}.
 *
 * The helper must always observe its documented contract: return a
 * non-empty string when a usable `sid` claim is present, `null` in every
 * other case (missing, empty, non-string).
 */
class ExtractSidFromClaimsTest extends TestCase
{
    public function testNullClaimsYieldsNull() :void
    {
        $this->assertNull( extractSidFromClaims( null ) ) ;
    }

    public function testMissingSidOnArrayYieldsNull() :void
    {
        $this->assertNull( extractSidFromClaims( [ 'sub' => 'user-1' ] ) ) ;
    }

    public function testMissingSidOnObjectYieldsNull() :void
    {
        $claims      = new stdClass() ;
        $claims->sub = 'user-1' ;

        $this->assertNull( extractSidFromClaims( $claims ) ) ;
    }

    public function testNullSidYieldsNull() :void
    {
        $this->assertNull( extractSidFromClaims( [ 'sid' => null ] ) ) ;
    }

    public function testEmptyStringSidYieldsNull() :void
    {
        // Defensive against an IdP misbehaving — empty string is filtered out.
        $this->assertNull( extractSidFromClaims( [ 'sid' => '' ] ) ) ;
    }

    public function testIntegerSidYieldsNull() :void
    {
        // Non-conformant per OIDC; the helper refuses to coerce so callers
        // never receive a value that violates the `?string` return type.
        $this->assertNull( extractSidFromClaims( [ 'sid' => 12345 ] ) ) ;
    }

    public function testBooleanSidYieldsNull() :void
    {
        $this->assertNull( extractSidFromClaims( [ 'sid' => true ] ) ) ;
    }

    public function testArraySidYieldsNull() :void
    {
        $this->assertNull( extractSidFromClaims( [ 'sid' => [ 'a' , 'b' ] ] ) ) ;
    }

    public function testValidSidOnArrayYieldsSid() :void
    {
        $this->assertSame
        (
            '373157825397949622' ,
            extractSidFromClaims( [ 'sid' => '373157825397949622' ] ) ,
        ) ;
    }

    public function testValidSidOnObjectYieldsSid() :void
    {
        $claims      = new stdClass() ;
        $claims->sid = '373157825397949622' ;

        $this->assertSame( '373157825397949622' , extractSidFromClaims( $claims ) ) ;
    }
}
