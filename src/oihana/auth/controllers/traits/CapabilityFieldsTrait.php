<?php

namespace oihana\auth\controllers\traits;

use Casbin\Exceptions\CasbinException;

use oihana\auth\enums\Capability;
use oihana\auth\enums\CapabilityAction;
use oihana\auth\enums\CapabilityPolicy;
use oihana\exceptions\http\Error403;

use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Capability enforcement for body fields of write requests (PATCH / POST / PUT).
 *
 * Provides {@see self::enforceFields()} which gates the keys present in the
 * parsed request body against a permission map declared under
 * `Capability::FIELDS` in the controller capabilities block.
 *
 * The map is read in the **inverse direction** of {@see CapabilityParamTrait}:
 * each entry is `permission => field(s)` instead of `value => permission`.
 * This shape makes the seed match (one permission line per resource group)
 * and lets a single permission gate several fields without repetition. A
 * field listed under several permissions is granted as long as the caller
 * holds at least one of them (logical OR).
 *
 * Policy:
 * - `STRICT` (default for fields): rejects the request with {@see Error403}
 *   on the first forbidden field. The body is never modified.
 * - `SILENT_DOWNGRADE`: drops the forbidden field from the returned body and
 *   continues. Use sparingly on body fields — silent drops on a write are
 *   often more harmful than an explicit 403 (the admin assumes the change
 *   went through).
 *
 * Fields not listed in any permission entry are passed through unchanged
 * (open access — typical for free-form metadata or always-writable scalars).
 *
 * Casbin action prefix is {@see CapabilityAction::FIELDS} (e.g.
 * `FIELDS:status.update`), distinct from the `PARAM:` prefix used by query
 * param capabilities. Permission seeds must mirror this convention.
 *
 * Requires {@see CapabilityContextTrait} to be `use`d alongside — the
 * consumer must provide the helpers declared abstract below.
 *
 * @package oihana\auth\controllers\traits
 * @author  Marc Alcaraz
 */
trait CapabilityFieldsTrait
{
    /**
     * Provided by {@see CapabilityContextTrait::activeParamConfig()}.
     *
     * @return array<array-key,mixed>|null
     */
    abstract protected function activeParamConfig( string $paramName ) : ?array ;

    /**
     * Enforce the `Capability::FIELDS` block against the keys carried by a
     * PATCH / POST / PUT body.
     *
     * Walks the configured `permission => field(s)` map, builds the inverse
     * `field => [permissions]` lookup, then for every key actually present
     * in the body :
     *
     * - If the key is not gated, it is left untouched.
     * - If the key is gated and the caller holds at least one matching
     *   permission, it is left untouched.
     * - If the key is gated and the caller holds none of the permissions :
     *     - `STRICT` policy : throws {@see Error403} naming the field.
     *     - `SILENT_DOWNGRADE` policy : the key is removed from the returned
     *       body. The validator and downstream Arango layer will simply not
     *       see that field, as if the client had not sent it.
     *
     * Field values that resolve to a single permission as a bare string and
     * field values listed as a list of fields under one permission are both
     * supported. A scalar string is normalized to a one-entry array.
     *
     * @param Request|null           $request The current PSR-7 request (null in CLI/tests).
     * @param array<array-key,mixed> $body    The parsed request body.
     *
     * @return array<array-key,mixed> The body, possibly with disallowed
     *                                fields stripped under SILENT_DOWNGRADE.
     *
     * @throws Error403       When the policy is STRICT and a forbidden field is present.
     * @throws CasbinException
     */
    protected function enforceFields( ?Request $request , array $body ) : array
    {
        if ( $body === [] )
        {
            return $body ;
        }

        $config = $this->activeParamConfig( Capability::FIELDS ) ;

        if ( $config === null )
        {
            return $body ;
        }

        $values = $config[ Capability::VALUES ] ?? null ;

        if ( !is_array( $values ) || $values === [] )
        {
            return $body ;
        }

        $fieldToSubjects = [] ;

        foreach ( $values as $subject => $fields )
        {
            if ( !is_string( $subject ) || $subject === '' )
            {
                continue ;
            }

            $fieldList = is_array( $fields ) ? $fields : [ $fields ] ;

            foreach ( $fieldList as $field )
            {
                if ( !is_string( $field ) || $field === '' )
                {
                    continue ;
                }

                $fieldToSubjects[ $field ][] = $subject ;
            }
        }

        if ( $fieldToSubjects === [] )
        {
            return $body ;
        }

        $policy = $config[ Capability::POLICY ] ?? CapabilityPolicy::STRICT ;

        foreach ( array_keys( $body ) as $field )
        {
            if ( !is_string( $field ) || !isset( $fieldToSubjects[ $field ] ) )
            {
                continue ;
            }

            $subjects = $fieldToSubjects[ $field ] ;

            if ( $this->isCapabilityAllowed( $request , $subjects , CapabilityAction::FIELDS ) )
            {
                continue ;
            }

            if ( $policy === CapabilityPolicy::STRICT )
            {
                throw new Error403( sprintf( "Forbidden field: '%s'" , $field ) ) ;
            }

            unset( $body[ $field ] ) ;
        }

        return $body ;
    }

    /**
     * Provided by {@see CapabilityContextTrait::isCapabilityAllowed()}.
     *
     * @throws CasbinException
     */
    abstract protected function isCapabilityAllowed( ?Request $request , mixed $entry , string $actionPrefix = CapabilityAction::PARAM ) : bool ;
}
