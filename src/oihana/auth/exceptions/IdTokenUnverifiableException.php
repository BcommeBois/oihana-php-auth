<?php

namespace oihana\auth\exceptions ;

use Throwable ;

/**
 * Thrown by IdTokenValidator when the id_token **could not be checked** : the
 * signing keys are neither cached nor reachable, so nothing is known of the
 * token — it may be perfectly good.
 *
 * 🚨 **This is not a token that failed its validation.** Answering it as one
 * tells the caller its token is wrong while the identity provider is merely out
 * of reach. An application should map it to a `503`, and keep the session.
 *
 * 🔑 **It extends {@see IdTokenValidationException} on purpose.** Code written
 * before this class existed catches the parent and keeps behaving as it did ;
 * telling the two apart is opt-in, by catching this one **first** :
 *
 * ```php
 * try
 * {
 *     $claims = $validator->validate( $idToken , $sub ) ;
 * }
 * catch ( IdTokenUnverifiableException $e )
 * {
 *     // 503 — the keys are out of reach, try again in a moment
 * }
 * catch ( IdTokenValidationException $e )
 * {
 *     // 401 — the token was checked and turned down
 * }
 * ```
 *
 * @package oihana\auth\exceptions
 * @author  Marc Alcaraz
 */
class IdTokenUnverifiableException extends IdTokenValidationException
{
    /**
     * Creates a new IdTokenUnverifiableException instance.
     *
     * @param Throwable|null $previous What stopped the keys from being read, when something raised.
     */
    public function __construct( ?Throwable $previous = null )
    {
        parent::__construct( self::MESSAGE , 0 , $previous ) ;
    }

    /**
     * The sentence the exception carries. Fixed : it names no endpoint.
     */
    public const string MESSAGE = 'id_token could not be verified: the signing keys are out of reach' ;
}
