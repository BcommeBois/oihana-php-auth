<?php

namespace tests\oihana\auth\jwt\helpers ;

use PHPUnit\Framework\TestCase ;
use stdClass ;

use function oihana\auth\jwt\helpers\extractFromClaims ;

/**
 * Unit coverage for {@see extractFromClaims()}.
 */
class ExtractFromClaimsTest extends TestCase
{
    public function testNullClaimsYieldsNull() :void
    {
        $this->assertNull( extractFromClaims( 'sub' , null ) ) ;
    }

    public function testMissingKeyOnArrayYieldsNull() :void
    {
        $this->assertNull( extractFromClaims( 'sid' , [ 'sub' => 'user-1' ] ) ) ;
    }

    public function testMissingKeyOnObjectYieldsNull() :void
    {
        $claims      = new stdClass() ;
        $claims->sub = 'user-1' ;

        $this->assertNull( extractFromClaims( 'sid' , $claims ) ) ;
    }

    public function testReturnsStringValueFromArray() :void
    {
        $this->assertSame( 'session-abc' , extractFromClaims( 'sid' , [ 'sid' => 'session-abc' ] ) ) ;
    }

    public function testReturnsStringValueFromObject() :void
    {
        $claims      = new stdClass() ;
        $claims->sid = 'session-abc' ;

        $this->assertSame( 'session-abc' , extractFromClaims( 'sid' , $claims ) ) ;
    }

    public function testReturnsIntegerValueUntouched() :void
    {
        // auth_time and iat are integers — the helper must not coerce.
        $this->assertSame( 1778915402 , extractFromClaims( 'auth_time' , [ 'auth_time' => 1778915402 ] ) ) ;
    }

    public function testReturnsBooleanValueUntouched() :void
    {
        $this->assertTrue( extractFromClaims( 'email_verified' , [ 'email_verified' => true ] ) ) ;
    }

    public function testReturnsArrayValueUntouched() :void
    {
        // aud is sometimes an array (multi-audience tokens).
        $this->assertSame
        (
            [ 'app-a' , 'app-b' ] ,
            extractFromClaims( 'aud' , [ 'aud' => [ 'app-a' , 'app-b' ] ] ) ,
        ) ;
    }

    public function testReturnsEmptyStringUntouched() :void
    {
        // Filtering empty strings is the caller's job (e.g. extractSidFromClaims).
        $this->assertSame( '' , extractFromClaims( 'sid' , [ 'sid' => '' ] ) ) ;
    }

    public function testReturnsNullValueWhenKeyExistsButValueIsNull() :void
    {
        $this->assertNull( extractFromClaims( 'sid' , [ 'sid' => null ] ) ) ;
    }
}
