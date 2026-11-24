<?php

namespace tests\oihana\auth\exceptions ;

use oihana\auth\exceptions\IdTokenUnverifiableException ;
use oihana\auth\exceptions\IdTokenValidationException ;

use PHPUnit\Framework\Attributes\CoversClass ;
use PHPUnit\Framework\TestCase ;

use RuntimeException ;

#[CoversClass( IdTokenUnverifiableException::class )]
class IdTokenUnverifiableExceptionTest extends TestCase
{
    /**
     * 🔑 It is a validation exception : a `catch` of the parent, written before
     * this class existed, still catches it.
     */
    public function testItIsAValidationException() :void
    {
        $this->assertInstanceOf( IdTokenValidationException::class , new IdTokenUnverifiableException() ) ;
    }

    /**
     * The sentence is fixed, and names no endpoint.
     */
    public function testItCarriesItsFixedSentence() :void
    {
        $exception = new IdTokenUnverifiableException() ;

        $this->assertSame( IdTokenUnverifiableException::MESSAGE , $exception->getMessage() ) ;
        $this->assertSame( 'id_token could not be verified: the signing keys are out of reach' , $exception->getMessage() ) ;
        $this->assertNull( $exception->getPrevious() ) ;
    }

    /**
     * What stopped the keys from being read travels with it, for the logs.
     */
    public function testItKeepsWhatStoppedTheRead() :void
    {
        $cause = new RuntimeException( 'the cache is down' ) ;

        $exception = new IdTokenUnverifiableException( $cause ) ;

        $this->assertSame( $cause , $exception->getPrevious() ) ;
        $this->assertSame( IdTokenUnverifiableException::MESSAGE , $exception->getMessage() ) ;
    }
}
