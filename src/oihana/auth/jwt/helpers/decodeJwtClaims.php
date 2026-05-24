<?php

namespace oihana\auth\jwt\helpers ;

/**
 * Decodes the claim section of a compact-serialized JWT without verifying
 * its signature.
 *
 * Purely a client-side inspection utility — never use the returned claims
 * to make trust decisions. The signature is NOT validated against any key,
 * any `iss` / `aud` mismatch is silently passed through, and an expired
 * token is decoded just like a fresh one.
 *
 * Use this helper when you need to look up the structural shape of a token
 * (sub, aud, iss, scope, custom claims) for diagnostics, logging, smoke
 * tests or PoC scripts. For authentication / authorisation, route the
 * token through a JWKS-aware verifier (e.g. the API middleware
 * `CheckJwtAuthentication`).
 *
 * The function tolerates URL-safe base64 (`-` / `_` aliases for `+` / `/`)
 * which Zitadel and most other OIDC providers emit.
 *
 * @example
 * ```php
 * use function oihana\auth\jwt\helpers\decodeJwtClaims ;
 *
 * $claims = decodeJwtClaims( $accessToken ) ;
 * $sub    = $claims[ 'sub' ] ?? null ;
 * ```
 *
 * @param string $jwt The compact-serialized JWT (`header.payload.signature`).
 *
 * @return array<string, mixed>|null The decoded claim set as an associative
 *                                    array, or `null` when the token is not
 *                                    well-formed (wrong segment count, bad
 *                                    base64, non-JSON payload, or non-object
 *                                    JSON).
 *
 * @package oihana\auth\jwt\helpers
 * @author  Marc Alcaraz
 */
function decodeJwtClaims( string $jwt ) :?array
{
    $parts = explode( '.' , $jwt ) ;

    if( count( $parts ) !== 3 )
    {
        return null ;
    }

    $payload = base64_decode( strtr( $parts[ 1 ] , '-_' , '+/' ) , true ) ;

    if( !is_string( $payload ) )
    {
        return null ;
    }

    $decoded = json_decode( $payload , true ) ;

    return is_array( $decoded ) ? $decoded : null ;
}
