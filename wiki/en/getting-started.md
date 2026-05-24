# Getting started

This page shows how to install **`oihana/php-auth`**, validate a first JWT, then perform a first Casbin capability check, in under 2 minutes.

> 🇫🇷 [Version française](../fr/getting-started.md)

## 1. Requirements

- [PHP 8.4+](https://www.php.net/releases/)
- [Composer](https://getcomposer.org/)
- The `ext-memcached` extension (for JWKS key caching)
- A reachable [Memcached](https://memcached.org/) server
- A **JWKS** endpoint URL from your IdP (Zitadel, Auth0, Keycloak, etc.)

## 2. Installation

```bash
composer require oihana/php-auth
```

## 3. Validate a JWT

The [`IdTokenValidator`](../../src/oihana/auth/jwt/IdTokenValidator.php) class verifies the signature, the issuer (`iss`) and the subject (`sub`) of a JWT. It relies on [`JwksKeyFetcher`](../../src/oihana/auth/jwt/JwksKeyFetcher.php) to fetch and cache the public keys.

```php
use Memcached ;

use oihana\auth\exceptions\IdTokenValidationException ;
use oihana\auth\jwt\IdTokenValidator ;
use oihana\auth\jwt\JwksKeyFetcher ;

$cache = new Memcached() ;
$cache->addServer( '127.0.0.1' , 11211 ) ;

$fetcher = new JwksKeyFetcher
(
    cache   : $cache ,
    jwksUri : 'https://your-idp.example.com/oauth/v2/keys'
) ;

$validator = new IdTokenValidator
(
    fetcher        : $fetcher ,
    expectedIssuer : 'https://your-idp.example.com'
) ;

try
{
    $claims = $validator->validate( $idToken , expectedSub: 'user-123' ) ;
    // $claims is an object holding the decoded JWT claims
}
catch ( IdTokenValidationException $e )
{
    // invalid signature, iss or sub mismatch
    // → return 401 to the client
}
```

See [Error handling](error-handling.md) for the full list of failure cases.

## 4. Enforce a capability with Casbin

The [`CapabilityEnforcer`](../../src/oihana/auth/casbin/CapabilityEnforcer.php) class asks Casbin whether a user is allowed to use a given capability (e.g. access an enriched skin, see a sensitive field, trigger a transversal action).

```php
use Casbin\Enforcer ;

use oihana\auth\casbin\CapabilityEnforcer ;
use oihana\auth\enums\CapabilityMode ;

$casbin = new Enforcer
(
    '/path/to/casbin/model.conf' ,
    '/path/to/casbin/policy.csv'
) ;

$enforcer = new CapabilityEnforcer
(
    enforcer : $casbin ,
    domain   : 'my-api'
) ;

$allowed = $enforcer->check
(
    userId     : 'user-123' ,
    object     : '/products' ,
    capability : 'offers.full' ,
    mode       : CapabilityMode::REQUIRE
) ;

if ( ! $allowed )
{
    // 403 — the user lacks the requested capability
}
```

See [Capabilities](capabilities.md) for the full pattern (REQUIRE vs DENY mode, allowlist/denylist, trait-based integration).

## 5. Going further

| To... | See |
|---|---|
| Understand the overall architecture | [Architecture](auth.md) |
| Restrict `?skin=…`, `?filter=…` request params | [Capabilities](capabilities.md) |
| Hide fields from a response based on the caller | [Field-level gating](field-level-gating.md) |
| Set up the `resource:action` naming convention | [Permissions](permissions.md) |
| Validate request bodies | [Validation rules](rules.md) |
| All best practices | [Tips & best practices](tips.md) |
