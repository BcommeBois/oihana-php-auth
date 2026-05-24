<?php

namespace oihana\auth\jwt\helpers ;

use xyz\oihana\schema\constants\JwtClaim ;

/**
 * Extracts the `sid` claim from id_token claims regardless of their shape
 * (object from firebase/php-jwt or array from a manual decode).
 *
 * Filters the raw claim value to ensure callers always observe the
 * documented contract: a non-empty string or `null`. A numeric or empty
 * `sid` (non-conformant per OIDC but defensible) is coerced to `null`
 * to keep the type-safe `?string` return.
 *
 * @param object|array|null $claims Decoded id_token claims, or null when no id_token was attached.
 *
 * @return string|null The `sid` claim when present and a non-empty string, null otherwise.
 */
function extractSidFromClaims( object|array|null $claims ) :?string
{
    $sid = extractFromClaims( JwtClaim::SESSION_ID , $claims ) ;

    return ( is_string( $sid ) && $sid !== '' ) ? $sid : null ;
}