# Error handling

This page lists the exceptions thrown by the library and the recommended way to catch them.

> 🇫🇷 [Version française](../fr/error-handling.md)

## Overview

| Exception | Origin | Recovery |
|---|---|---|
| [`IdTokenValidationException`](../../src/oihana/auth/exceptions/IdTokenValidationException.php) | Library `oihana/php-auth` | Return a **401 Unauthorized** |
| [`Casbin\Exceptions\CasbinException`](https://github.com/php-casbin/php-casbin) | External `casbin/casbin` | Return **500 Internal Server Error** (fail-closed) |

## IdTokenValidationException

Thrown by [`IdTokenValidator::validate()`](../../src/oihana/auth/jwt/IdTokenValidator.php) in 4 cases:

| Case | Message |
|---|---|
| Invalid signature or malformed JWT | `id_token signature or format invalid` |
| `iss` does not match `expectedIssuer` | `id_token issuer mismatch: expected …, got …` |
| `sub` missing or different from `expectedSub` | `id_token sub does not match the access token sub` |
| Expired JWT (`exp` claim) | Delegated to `firebase/php-jwt` — propagates `ExpiredException` |

### Catch pattern

```php
use Firebase\JWT\ExpiredException ;

use oihana\auth\exceptions\IdTokenValidationException ;

try
{
    $claims = $validator->validate( $idToken , expectedSub: $userId ) ;
}
catch ( ExpiredException $e )
{
    // Token expired — return 401 with reason: token_expired
}
catch ( IdTokenValidationException $e )
{
    // Invalid signature or claims — return 401 with reason: invalid_token
}
```

## CasbinException

Thrown by [`CapabilityEnforcer`](../../src/oihana/auth/casbin/CapabilityEnforcer.php) methods when the underlying Casbin enforcer fails (malformed policy, unavailable adapter, etc.).

**Recommended doctrine: fail-closed** — any `CasbinException` must cause the check to fail (= access denied), never let it through.

```php
use Casbin\Exceptions\CasbinException ;

try
{
    $allowed = $enforcer->check( $userId , $object , $capability , $mode ) ;
}
catch ( CasbinException $e )
{
    // Log for investigation
    $logger->error( 'Casbin enforce failed' , [ 'exception' => $e ] ) ;

    // Fail-closed: deny
    $allowed = false ;
}
```

The [`PermissionAuthorizerTrait`](../../src/oihana/auth/controllers/traits/PermissionAuthorizerTrait.php) already implements this pattern: the returned closure catches `CasbinException` and returns `false`.

## Silent JWKS fetch failure

By design, [`JwksKeyFetcher::getKeys()`](../../src/oihana/auth/jwt/JwksKeyFetcher.php) **does not throw** when the cache is empty and the HTTP fetch fails: it returns an empty array `[]`.

This is intentional: a transient network blip should not bring down the authentication layer. But with no keys, JWT validation will later fail with `IdTokenValidationException` (invalid signature).

An internal rate-limit (`REFRESH_COOLDOWN = 60 s`) prevents back-to-back refresh attempts.

## JWT helpers — no exceptions

The function helpers in the `oihana\auth\jwt\helpers` namespace return `null` on error, they never throw:

| Helper | Return on failure |
|---|---|
| `decodeJwtClaims( string $token )` | `null` (malformed JWT) |
| `extractFromClaims( ?array $claims , string $key )` | `null` (missing claim) |
| `extractSidFromClaims( ?array $claims )` | `null` (sid absent) |

Chain without try/catch:

```php
use function oihana\auth\jwt\helpers\decodeJwtClaims ;
use function oihana\auth\jwt\helpers\extractFromClaims ;

$claims = decodeJwtClaims( $accessToken ) ;
$sub    = extractFromClaims( $claims , 'sub' ) ;

if ( $sub === null )
{
    // missing claim — application-level decision
}
```
