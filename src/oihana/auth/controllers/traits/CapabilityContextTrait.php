<?php

namespace oihana\auth\controllers\traits;

use Casbin\Exceptions\CasbinException;

use oihana\auth\CapabilityEnforcerInterface;
use oihana\auth\enums\Capability;
use oihana\auth\enums\CapabilityAction;
use oihana\auth\enums\CapabilityMode;
use oihana\auth\enums\CapabilityPolicy;
use oihana\controllers\enums\ControllerParam;
use oihana\enums\Char;
use oihana\enums\http\RequestAttribute;
use oihana\exceptions\http\Error403;

use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Shared lifecycle and private helpers for every capability enforcement trait.
 *
 * Carries the runtime state (`$capabilities`, kill-switch, injected enforcer,
 * route scope) and exposes the low-level helpers that the feature traits
 * ({@see CapabilityParamTrait}, {@see CapabilityFilterKeysTrait},
 * {@see CapabilityBinaryTrait}) consume via abstract declarations.
 *
 * A Controller that wants any capability enforcement must always `use` this
 * trait first — either directly or through the {@see CapabilityGuardTrait}
 * facade.
 *
 * @package oihana\auth\controllers\traits
 * @author  Marc Alcaraz
 */
trait CapabilityContextTrait
{
    /**
     * Raw capabilities configuration, as passed in `$init`.
     *
     * @var array<array-key,mixed>
     */
    protected array $capabilities = [] ;

    /**
     * Kill-switch. When false, the trait becomes a complete no-op even if the
     * block is declared. Useful for dev/test/rollback scenarios.
     */
    protected bool $capabilitiesEnabled = true ;

    /**
     * Injected at init time. When null (auth disabled, no DI registration),
     * every check falls through to a no-op.
     */
    protected ?CapabilityEnforcerInterface $capabilityEnforcer = null ;

    /**
     * Route scope shared by every capability in the block (Casbin `object`).
     * Resolved from `Capability::OBJECT` at init time.
     */
    protected string $capabilityObject = '' ;

    /**
     * Initialize the trait from a controller `$init` array.
     *
     * @param array<array-key,mixed>           $init     Same array passed to the controller constructor.
     * @param CapabilityEnforcerInterface|null $enforcer Optional injected enforcer. DI resolution is the caller's responsibility.
     *
     * @return static
     */
    protected function initializeCapabilities( array $init , ?CapabilityEnforcerInterface $enforcer = null ) : static
    {
        $raw = $init[ ControllerParam::CAPABILITIES ] ?? null ;

        $this->capabilities        = is_array( $raw ) ? $raw : [] ;
        $this->capabilitiesEnabled = (bool) ( $init[ ControllerParam::CAPABILITIES_ENABLED ] ?? true ) ;

        $object = $this->capabilities[ Capability::OBJECT ] ?? '' ;

        $this->capabilityObject   = is_string( $object ) ? $object : '' ;
        $this->capabilityEnforcer = $enforcer ;

        return $this ;
    }

    /**
     * Returns the per-param config array, or null if the capability check
     * should be skipped (kill-switch off, no enforcer, missing entry).
     *
     * @return array<array-key,mixed>|null
     */
    protected function activeParamConfig( string $paramName ) : ?array
    {
        if ( !$this->capabilitiesEnabled || $this->capabilityEnforcer === null )
        {
            return null ;
        }

        $paramConfig = $this->capabilities[ $paramName ] ?? null ;

        return is_array( $paramConfig ) ? $paramConfig : null ;
    }

    /**
     * Apply the declared {@see CapabilityPolicy} when a check fails.
     *
     * @param array<array-key,mixed> $paramConfig
     * @param mixed $value
     *
     * @return mixed
     *
     * @throws Error403 For STRICT policy.
     */
    protected function applyCapabilityPolicy( array $paramConfig , mixed $value ) : mixed
    {
        $policy = $paramConfig[ Capability::POLICY ] ?? CapabilityPolicy::SILENT_DOWNGRADE ;

        if ( $policy === CapabilityPolicy::STRICT )
        {
            $display = is_scalar( $value ) ? (string) $value : gettype( $value ) ;
            throw new Error403( sprintf( "Forbidden capability value: '%s'" , $display ) ) ;
        }

        return $paramConfig[ Capability::FALLBACK ] ?? null ;
    }

    /**
     * Extract the capability discriminator from a permission subject.
     *
     * The subject convention is `<resource>:<discriminator>`, where the
     * discriminator feeds the Casbin action `PARAM:<discriminator>`. For
     * instance `products:skin.offers.full` yields `skin.offers.full`.
     */
    protected function extractCapabilityDiscriminator( string $subject ) : string
    {
        $parts = explode( Char::COLON , $subject , 2 ) ;

        return $parts[ 1 ] ?? $subject ;
    }

    /**
     * Run the Casbin check for a parsed entry.
     *
     * An entry can carry one or several permission subjects ; the multi-subject
     * case is evaluated as a logical OR :
     * - `REQUIRE` : allowed if at least one subject is granted to the user.
     * - `DENY`    : allowed if no subject is explicitly denied (every check passes).
     *
     * Fails open for invalid entries (malformed config should not break
     * requests — it will be caught by tests / review). When no authenticated
     * user is present, REQUIRE fails closed and DENY passes through.
     *
     * @throws CasbinException
     */
    protected function isCapabilityAllowed( ?Request $request , mixed $entry , string $actionPrefix = CapabilityAction::PARAM ) : bool
    {
        [ $mode , $subjects ] = $this->parseCapabilityEntry( $entry ) ;

        if ( $mode === null || $subjects === null || count( $subjects ) === 0 )
        {
            return true ;
        }

        if ( $this->capabilityEnforcer === null )
        {
            return $mode === CapabilityMode::DENY ;
        }

        $userId = $request?->getAttribute( RequestAttribute::USER_ID ) ;

        if ( !is_string( $userId ) || $userId === '' )
        {
            return $mode === CapabilityMode::DENY ;
        }

        foreach ( $subjects as $subject )
        {
            $discriminator = $this->extractCapabilityDiscriminator( $subject ) ;

            $passed = $this->capabilityEnforcer->check
            (
                $userId ,
                $this->capabilityObject ,
                $discriminator ,
                $mode ,
                $actionPrefix
            ) ;

            if ( $mode === CapabilityMode::REQUIRE && $passed )
            {
                return true ;  // REQUIRE OR : one granted permission is enough
            }

            if ( $mode === CapabilityMode::DENY && !$passed )
            {
                return false ; // DENY OR : one explicitly denied permission blocks
            }
        }

        // Loop ended without short-circuit :
        // - REQUIRE → no subject granted → forbidden
        // - DENY    → no subject denied  → allowed
        return $mode === CapabilityMode::DENY ;
    }

    /**
     * Resolve the (mode, subjects) pair from a VALUES/KEYS/SUBJECT entry.
     *
     * Accepted shapes :
     * - `'subject'`                                              — REQUIRE singleton (shortcut)
     * - `[ 's1' , 's2' ]` (positional list of strings)            — REQUIRE OR
     * - `[ Capability::REQUIRE => 's' ]`                          — REQUIRE singleton (long form)
     * - `[ Capability::REQUIRE => [ 's1' , 's2' ] ]`              — REQUIRE OR
     * - `[ Capability::DENY    => 's' ]`                          — DENY singleton
     * - `[ Capability::DENY    => [ 's1' , 's2' ] ]`              — DENY OR
     *
     * @return array{0: string|null, 1: array<int,string>|null}
     */
    protected function parseCapabilityEntry( mixed $entry ) : array
    {
        if ( is_string( $entry ) )
        {
            return [ CapabilityMode::REQUIRE , [ $entry ] ] ;
        }

        if ( is_array( $entry ) )
        {
            // Positional list of strings → REQUIRE OR
            if ( array_is_list( $entry ) && count( $entry ) > 0 )
            {
                $subjects = array_values( array_filter( $entry , 'is_string' ) ) ;
                if ( count( $subjects ) === count( $entry ) )
                {
                    return [ CapabilityMode::REQUIRE , $subjects ] ;
                }
            }

            $require = $entry[ Capability::REQUIRE ] ?? null ;
            if ( is_string( $require ) )
            {
                return [ CapabilityMode::REQUIRE , [ $require ] ] ;
            }
            if ( is_array( $require ) )
            {
                $subjects = array_values( array_filter( $require , 'is_string' ) ) ;
                if ( count( $subjects ) > 0 )
                {
                    return [ CapabilityMode::REQUIRE , $subjects ] ;
                }
            }

            $deny = $entry[ Capability::DENY ] ?? null ;
            if ( is_string( $deny ) )
            {
                return [ CapabilityMode::DENY , [ $deny ] ] ;
            }
            if ( is_array( $deny ) )
            {
                $subjects = array_values( array_filter( $deny , 'is_string' ) ) ;
                if ( count( $subjects ) > 0 )
                {
                    return [ CapabilityMode::DENY , $subjects ] ;
                }
            }
        }

        return [ null , null ] ;
    }
}
