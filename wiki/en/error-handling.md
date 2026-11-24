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

By design, [`JwksKeyFetcher`](../../src/oihana/auth/jwt/JwksKeyFetcher.php) **does not throw** when the endpoint does not answer: `getKeys()` and `refreshKeys()` return an empty array `[]`.

This is intentional: a transient network blip should not bring down the authentication layer. But with no keys, JWT validation will later fail with `IdTokenValidationException` (invalid signature).

🚨 **`[]` means "no key could be served", never "this token is refused".** An application decoding with these keys itself must read `[]` as "the signature could not be checked" — a service that is unavailable, not a session that is over.

What the two methods return:

| Situation | `getKeys()` | `refreshKeys()` |
|---|---|---|
| Keys in the cache | the keys, no call | see the rows below |
| A refresh succeeded less than `REFRESH_COOLDOWN` (60 s) ago | — | the cached keys, no call |
| The endpoint answers | the keys, now cached | the new keys, which **replace** the cached ones |
| The endpoint does not answer | `[]` | `[]` — **the cached keys stay in place** for the other requests |
| A call failed less than `FAILURE_TTL` (5 s) ago | `[]` when nothing is cached, no call | `[]`, no call |

Three entries live in the cache: `jwks:keys` (the keys), `jwks:refreshed` (a refresh just succeeded) and `jwks:unavailable` (the last call failed). Both markers are kept **in the cache, not in the object**: under a process-per-request runtime, a limit kept in a property would start again from zero with every request.

- **A refresh never drops the keys before the new ones are in hand.** A token with a wrong signature therefore cannot empty the cache while the endpoint is out of reach.
- **The cooldown is held by a refresh that succeeded only.** A failed refresh does not block the next one for a minute; repeated failures are bounded by `FAILURE_TTL`.
- **The durations are read through `static::`**: a subclass redefining `FAILURE_TTL`, `REFRESH_COOLDOWN` or `CACHE_TTL` changes the behaviour without rewriting a method.

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
