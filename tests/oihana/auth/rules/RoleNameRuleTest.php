<?php

namespace tests\oihana\auth\rules;

use oihana\auth\rules\RoleNameRule;
use PHPUnit\Framework\TestCase;

/**
 * RoleNameRule expects the value to already be canonical (trim + lowercase).
 * The controller is responsible for that transformation; this rule just
 * confirms the regex shape: 2-70 ASCII characters in `[a-z0-9 _-]`.
 */
final class RoleNameRuleTest extends TestCase
{
    private RoleNameRule $rule ;

    protected function setUp() :void
    {
        $this->rule = new RoleNameRule() ;
    }

    public function testAcceptsLowercaseAlphanumeric() :void
    {
        $this->assertTrue( $this->rule->check( 'editor' ) ) ;
        $this->assertTrue( $this->rule->check( 'admin2' ) ) ;
        $this->assertTrue( $this->rule->check( 'role123' ) ) ;
    }

    public function testAcceptsHyphenAndUnderscore() :void
    {
        $this->assertTrue( $this->rule->check( 'manager-com' ) ) ;
        $this->assertTrue( $this->rule->check( 'content_editor' ) ) ;
        $this->assertTrue( $this->rule->check( 'a-b_c' ) ) ;
    }

    public function testAcceptsInternalSpaces() :void
    {
        $this->assertTrue( $this->rule->check( 'role name' ) ) ;
        $this->assertTrue( $this->rule->check( 'a b c d' ) ) ;
    }

    public function testRejectsUppercase() :void
    {
        // The rule is the last guard, not a transformer. Uppercase reaching
        // this point means the controller forgot to canonicalise — fail loud.
        $this->assertFalse( $this->rule->check( 'Editor' ) ) ;
        $this->assertFalse( $this->rule->check( 'EDITOR' ) ) ;
    }

    public function testRejectsAccentsAndNonAscii() :void
    {
        // ASCII-only first iteration. Accents like "éditeur" must go through
        // the i18n `description` field instead.
        $this->assertFalse( $this->rule->check( 'éditeur' ) ) ;
        $this->assertFalse( $this->rule->check( 'café' ) ) ;
        $this->assertFalse( $this->rule->check( 'role™' ) ) ;
    }

    public function testRejectsSpecialCharacters() :void
    {
        $this->assertFalse( $this->rule->check( 'bad@name' ) ) ;
        $this->assertFalse( $this->rule->check( 'role!' ) ) ;
        $this->assertFalse( $this->rule->check( 'role/with/slash' ) ) ;
        $this->assertFalse( $this->rule->check( 'role.dot' ) ) ;
    }

    public function testRejectsTooShort() :void
    {
        $this->assertFalse( $this->rule->check( '' ) ) ;
        $this->assertFalse( $this->rule->check( 'a' ) ) ;
    }

    public function testAcceptsExactlyMinLength() :void
    {
        $this->assertTrue( $this->rule->check( 'ab' ) ) ;
    }

    public function testAcceptsExactlyMaxLength() :void
    {
        $this->assertTrue( $this->rule->check( str_repeat( 'a' , 70 ) ) ) ;
    }

    public function testRejectsTooLong() :void
    {
        $this->assertFalse( $this->rule->check( str_repeat( 'a' , 71 ) ) ) ;
    }

    public function testRejectsTrailingNewline() :void
    {
        // The strict `\z` anchor (vs `$`) refuses a trailing newline that
        // would otherwise slip through `^...$`. Leading/trailing spaces are
        // intentionally NOT covered by the regex — the controller's
        // canonicalisation step (mb_strtolower + trim) handles them, and
        // the regex permits internal spaces (e.g. "role name") so trying
        // to reject only edge spaces would compromise that.
        $this->assertFalse( $this->rule->check( "editor\n" ) ) ;
        $this->assertFalse( $this->rule->check( "editor\r\n" ) ) ;
    }

    public function testRejectsNonStringValues() :void
    {
        $this->assertFalse( $this->rule->check( null ) ) ;
        $this->assertFalse( $this->rule->check( 42 ) ) ;
        $this->assertFalse( $this->rule->check( [ 'editor' ] ) ) ;
        $this->assertFalse( $this->rule->check( true ) ) ;
    }
}
