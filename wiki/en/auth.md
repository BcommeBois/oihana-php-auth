# Architecture — Authentication & Authorization

> **Definition.** **Authentication** answers *"who are you?"*. **Authorization** answers *"what are you allowed to do?"*. The `oihana/php-auth` library covers both, while staying agnostic about the identity provider and the permission storage.

This page gives the high-level overview. Each sub-mechanism has its own reference page (linked at the end).

> 🇫🇷 [Version française](../fr/auth.md)

## Overview

```text
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  Authentication                         Authorization            │
│  ──────────────                         ─────────────            │
│                                                                  │
│  ┌──────────────────┐                  ┌──────────────────┐      │
│  │ OIDC IdP         │                  │ RBAC policy      │      │
│  │ (Zitadel, Auth0, │                  │ (roles, perms,   │      │
│  │  Keycloak, …)    │                  │  policies)       │      │
│  └────────┬─────────┘                  └────────┬─────────┘      │
│           │                                     │                │
│           │ JWT (id_token)                      │ (object,action)│
│           │                                     │                │
│           ▼                                     ▼                │
│  ┌──────────────────┐                  ┌──────────────────┐      │
│  │ JwksKeyFetcher   │                  │ Casbin\Enforcer  │      │
│  │ + IdTokenValidator                  │ + CapabilityEnforcer    │
│  └────────┬─────────┘                  └────────┬─────────┘      │
│           │                                     │                │
│           │ decoded claims (sub, iss, …)        │ allow/deny     │
│           │                                     │                │
│           └─────────────────┬───────────────────┘                │
│                             │                                    │
│                             ▼                                    │
│                  ┌──────────────────────┐                        │
│                  │ HTTP middleware /    │                        │
│                  │ application controller                        │
│                  └──────────────────────┘                        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

Authentication consumes a signed JWT issued by an OIDC IdP. The signature is verified against the IdP's public keys (JWKS), which are cached through Memcached. The decoded claims (in particular `sub`) identify the user.

Authorization sits on top of [Casbin](https://casbin.org/): an RBAC + domains policy engine that stores `(subject, object, action, effect)` tuples and answers "is this subject allowed to perform this action on this object?".

## Authentication — JWT / JWKS layer

The library exposes two classes:

| Class | Role |
|---|---|
| [`JwksKeyFetcher`](../../src/oihana/auth/jwt/JwksKeyFetcher.php) | Fetches JWKS public keys from an OIDC endpoint. Caches via Memcached with configurable TTL and an anti-flood rate-limit. Fail-soft: returns `[]` when the fetch fails. |
| [`IdTokenValidator`](../../src/oihana/auth/jwt/IdTokenValidator.php) | Validates the signature + issuer (`iss`) + subject (`sub`) of a JWT using `JwksKeyFetcher`. Throws `IdTokenValidationException` on failure. |

### JWT helpers

Three function helpers (autoload `files`) are available for lower-level cases:

| Helper | Role |
|---|---|
| `decodeJwtClaims(string $token)` | Decodes a JWT **without** verifying the signature (useful for debug / quick parsing). Returns `null` if malformed. |
| `extractFromClaims(?array $claims, string $key)` | Extracts a claim by key. Returns `null` if missing. |
| `extractSidFromClaims(?array $claims)` | Specifically extracts the `sid` (session id) claim. |

> ⚠️ `decodeJwtClaims()` does not verify the signature — use only for non-sensitive claims. To authenticate a call, always go through `IdTokenValidator`.

### Error cases

See [Error handling](error-handling.md).

## Authorization — Casbin layer

The library exposes a high-level wrapper on top of `Casbin\Enforcer`:

| Class / Interface | Role |
|---|---|
| [`CapabilityEnforcerInterface`](../../src/oihana/auth/CapabilityEnforcerInterface.php) | Contract exposing `check`, `has`, `isDenied`, `enforceObjectAction`. |
| [`CapabilityEnforcer`](../../src/oihana/auth/casbin/CapabilityEnforcer.php) | Default Casbin implementation. Mode-aware (`REQUIRE` / `DENY`), handles prefixed actions (`PARAM:*`). |
| [`EnforcerTrait`](../../src/oihana/auth/casbin/traits/EnforcerTrait.php) | Trait to include in a class to expose `$enforcer` + configuration helpers. |

The `CapabilityEnforcer` receives the native `Casbin\Enforcer` and the API domain in its constructor. All checks automatically normalise the subject through [`casbinSafeSubject()`](../../src/oihana/auth/helpers/casbinSafeSubject.php) to avoid the `string → int` coercion bug (see [Tips & best practices](tips.md)).

## Fine-grained capabilities

Beyond plain HTTP verbs, the library ships the **fine-grained capability** pattern (`PARAM:*`) to restrict parameter values, filter keys or transversal actions **inside** an already-protected route.

See [Capabilities](capabilities.md) for the full pattern.

## Field-level gating

When a route returns multiple fields and some are sensitive, the library lets you **gate each field individually**: a field is included in the response only if the user owns the permission that covers it. Otherwise the key does not appear in the JSON at all.

See [Field-level gating](field-level-gating.md).

## Validation rules

For create/edit payloads, the library plugs into [Somnambulist Validation](https://github.com/somnambulist-tech/validation) and exposes its own `Rule` classes (currently `RoleNameRule`).

See [Validation rules](rules.md).

## Assembling it in an HTTP middleware

Conceptual outline of a typical auth + authz middleware. The library does not ship the middleware itself (it depends on your framework), but it ships every brick you need.

```php
namespace App\Middleware ;

use Psr\Http\Message\ServerRequestInterface as Request ;
use Psr\Http\Server\MiddlewareInterface ;
use Psr\Http\Server\RequestHandlerInterface ;

use oihana\auth\casbin\CapabilityEnforcer ;
use oihana\auth\jwt\IdTokenValidator ;
use oihana\auth\exceptions\IdTokenValidationException ;
use oihana\enums\http\RequestAttribute ;

use function oihana\auth\jwt\helpers\decodeJwtClaims ;
use function oihana\auth\jwt\helpers\extractFromClaims ;

final class AuthMiddleware implements MiddlewareInterface
{
    public function __construct
    (
        private IdTokenValidator    $validator ,
        private CapabilityEnforcer  $enforcer
    ) {}

    public function process( Request $request , RequestHandlerInterface $handler ) : ResponseInterface
    {
        // 1. Pull the JWT from the Authorization header
        $token = $this->extractBearerToken( $request ) ;

        // 2. Quick-decode to read the sub (no signature check)
        $claims = decodeJwtClaims( $token ) ;
        $sub    = extractFromClaims( $claims , 'sub' ) ;

        // 3. Verify signature + iss + sub
        try
        {
            $this->validator->validate( $token , expectedSub: $sub ) ;
        }
        catch ( IdTokenValidationException $e )
        {
            return $this->unauthorized( $e->getMessage() ) ;
        }

        // 4. Check the Casbin policy on (object, action) = (path, verb)
        $allowed = $this->enforcer->enforceObjectAction
        (
            userId : $sub ,
            object : $request->getUri()->getPath() ,
            action : $request->getMethod()
        ) ;

        if ( ! $allowed )
        {
            return $this->forbidden() ;
        }

        // 5. Stash the user id on the request for controllers downstream
        $request = $request->withAttribute( RequestAttribute::USER_ID , $sub ) ;

        return $handler->handle( $request ) ;
    }

    // ... helpers extractBearerToken / unauthorized / forbidden
}
```

Contract with the controllers: they consume the `RequestAttribute::USER_ID` attribute to know who is calling, and use [`PermissionAuthorizerTrait`](../../src/oihana/auth/controllers/traits/PermissionAuthorizerTrait.php) or the `Capability*Trait` traits for fine-grained checks.

## Security model

| Piece | Responsibility | Fail-mode |
|---|---|---|
| JWKS fetch | Fetch public keys | **Fail-soft** — returns `[]`, JWT validation then fails cleanly |
| JWT validation | Signature + iss + sub | **Fail-loud** — `IdTokenValidationException` |
| Casbin enforce | Policy decision | **Fail-closed recommended** — `CasbinException` → access denied |
| Field-level gating | Selective projection | **Silent fail-closed** — key absent, never a 500 |

## External dependencies

| Library | Role |
|---|---|
| `casbin/casbin` | RBAC + domains engine |
| `firebase/php-jwt` (≥ 7.0) | JWT decoding and signature verification |
| `guzzlehttp/guzzle` | JWKS HTTP fetch |
| `somnambulist/validation` | Validation rule engine |
| `oihana/php-system` | `prepare/*` traits (Filter, Search, Skin) used by controllers |
| PHP `ext-memcached` | Cache for JWKS keys and the subject → `(object, action)` map |

## Going further

- [Getting started](getting-started.md) — install and validate your first JWT.
- [Capabilities](capabilities.md) — restrict parameters / filters / transversal actions.
- [Permissions](permissions.md) — naming convention and typed enums.
- [Field-level gating](field-level-gating.md) — hide sensitive fields from a response.
- [Validation rules](rules.md) — payloads and `body.errors`.
- [Error handling](error-handling.md) — exception catalogue.
- [Tips & best practices](tips.md) — anti-patterns to avoid.
