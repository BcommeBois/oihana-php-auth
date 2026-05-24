<?php

namespace oihana\auth\jwt\helpers ;

use function oihana\core\accessors\getKeyValue ;

/**
 * Extracts a single claim value from decoded JWT claims regardless of
 * their shape (object from firebase/php-jwt or array from a manual
 * decode). Delegates to `oihana\core\accessors\getKeyValue` so the
 * array/object dispatch lives in a single battle-tested helper.
 *
 * Returns the raw claim value untouched. The caller is responsible for
 * type-casting / validation (sid as non-empty string, auth_time as int,
 * etc.). Missing claim or null input both yield `null`.
 *
 * @param string            $key    The claim name (e.g. `sid`, `auth_time`).
 * @param object|array|null $claims The decoded claims.
 *
 * @return mixed The raw claim value, or null when absent.
 */
function extractFromClaims( string $key , object|array|null $claims ) :mixed
{
    if( $claims === null )
    {
        return null ;
    }

    return getKeyValue( $claims , $key ) ;
}