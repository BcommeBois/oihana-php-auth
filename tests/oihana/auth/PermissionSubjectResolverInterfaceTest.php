<?php

namespace tests\oihana\auth;

use oihana\auth\PermissionSubjectResolverInterface;
use oihana\interfaces\Invalidable;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

use ReflectionClass;

/**
 * Contract test: the resolver interface is the shape implementors must honor.
 *
 * It is deliberately reflection-based — the interface carries no behavior, so
 * what is worth locking down is the surface itself: the `Invalidable`
 * inheritance (a resolver caches its map and must be able to drop it) and the
 * signatures downstream code binds to.
 *
 * `CoversNothing` is deliberate: an interface holds no executable line, so it
 * is not a valid code-coverage target — declaring it as one raises a PHPUnit
 * warning that `failOnWarning` turns into a failed suite.
 */
#[CoversNothing]
final class PermissionSubjectResolverInterfaceTest extends TestCase
{
    public function testExtendsInvalidable() : void
    {
        $this->assertContains
        (
            Invalidable::class ,
            class_implements( PermissionSubjectResolverInterface::class ) ,
            'A permission subject resolver must expose invalidate() so a policy change can drop its cached map.'
        ) ;
    }

    public function testDeclaresTheExpectedMethods() : void
    {
        $reflection = new ReflectionClass( PermissionSubjectResolverInterface::class ) ;

        $this->assertTrue( $reflection->isInterface() ) ;

        $this->assertTrue( $reflection->hasMethod( 'getMap'     ) ) ;
        $this->assertTrue( $reflection->hasMethod( 'resolve'    ) ) ;
        $this->assertTrue( $reflection->hasMethod( 'invalidate' ) ) ;
    }

    public function testInvalidateIsInheritedFromInvalidableAndReturnsVoid() : void
    {
        $method = new ReflectionClass( PermissionSubjectResolverInterface::class )->getMethod( 'invalidate' ) ;

        $this->assertSame( Invalidable::class , $method->getDeclaringClass()->getName() ) ;
        $this->assertSame( 'void' , (string) $method->getReturnType() ) ;
        $this->assertSame( 0 , $method->getNumberOfParameters() ) ;
    }

    /**
     * A double built against the interface must be able to satisfy the full
     * contract — this is what broke every consumer test when `Invalidable`
     * was added without widening the mocked method list.
     */
    public function testADoubleCanSatisfyTheWholeContract() : void
    {
        $resolver = $this->createMock( PermissionSubjectResolverInterface::class ) ;

        $resolver->expects( $this->once() )->method( 'invalidate' ) ;

        $resolver->invalidate() ;

        $this->assertInstanceOf( Invalidable::class , $resolver ) ;
    }
}
