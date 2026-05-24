<?php

namespace tests\oihana\auth\helpers;

use PHPUnit\Framework\TestCase;

use function oihana\auth\helpers\casbinSafeSubject;

/**
 * Unit coverage for {@see \oihana\auth\helpers\casbinSafeSubject()}.
 *
 * The helper guards Casbin against PHP's silent coercion of purely
 * numeric string keys to `int` in associative arrays. The contract is
 * narrow but load-bearing : every purely numeric subject must be
 * prefixed with `n_`, every other subject must pass through untouched,
 * and the function must be idempotent.
 */
class CasbinSafeSubjectTest extends TestCase
{
    public function testPurelyNumericSubjectGetsNumericPrefix() :void
    {
        $this->assertSame( 'n_364646423545321675' , casbinSafeSubject( '364646423545321675' ) ) ;
        $this->assertSame( 'n_42' , casbinSafeSubject( '42' ) ) ;
        $this->assertSame( 'n_0' , casbinSafeSubject( '0' ) ) ;
    }

    public function testNonNumericSubjectPassesThrough() :void
    {
        $this->assertSame( 'role_42' , casbinSafeSubject( 'role_42' ) ) ;
        $this->assertSame( 'admin' , casbinSafeSubject( 'admin' ) ) ;
        $this->assertSame( 'service:abc123' , casbinSafeSubject( 'service:abc123' ) ) ;
        $this->assertSame( '364646423545321675@example.com' , casbinSafeSubject( '364646423545321675@example.com' ) ) ;
    }

    public function testEmptyStringPassesThrough() :void
    {
        // ctype_digit returns false on empty strings, so an empty
        // input is left as-is — no defensive throwing here, the helper
        // is a pure value transform.
        $this->assertSame( '' , casbinSafeSubject( '' ) ) ;
    }

    public function testIsIdempotent() :void
    {
        $once  = casbinSafeSubject( '12345' ) ;
        $twice = casbinSafeSubject( $once ) ;

        $this->assertSame( 'n_12345' , $once ) ;
        $this->assertSame( $once , $twice , 'casbinSafeSubject must be idempotent' ) ;
    }

    public function testMixedAlphanumericPassesThrough() :void
    {
        // ctype_digit only matches strings made exclusively of digits,
        // so anything carrying a single non-digit character (letters,
        // dashes, dots, …) falls into the pass-through branch.
        $this->assertSame( '12345a' , casbinSafeSubject( '12345a' ) ) ;
        $this->assertSame( 'a12345' , casbinSafeSubject( 'a12345' ) ) ;
        $this->assertSame( '123-456' , casbinSafeSubject( '123-456' ) ) ;
    }
}
