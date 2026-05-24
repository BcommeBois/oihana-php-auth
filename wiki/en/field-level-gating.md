# Field-level gating

An HTTP route may be authorised for a user (`GET /roles` is accessible) while its response exposes fields that the same user has no right to see (for instance the `permissions[]` array hydrated when requesting `?skin=full`).

**Field-level gating** closes that leak: a projected field is included in the response only if the user owns the permission that covers it. Otherwise the key does not appear in the JSON at all.

> 🇫🇷 [Version française](../fr/field-level-gating.md)

## The problem

Without gating, a user who owns `GET /roles/{id}` can read in the response:

- `permissions[]` — the full list of permissions attached to the role,
- `policies[]` — the full list of policies attached to the role.

…even when they do **not** have the HTTP permissions that cover these details (`roles.permissions:list` and `roles.policies:list`). The UI can hide these sections client-side, but the API already served them — the information has leaked the moment the request hit the server.

Gating closes that hole server-side: the same Casbin rule that protects `GET /roles/{id}/permissions` also protects the `permissions[]` projection when requested via `?skin=full`.

## Pieces shipped by the library

The mechanism relies on two abstractions:

| Piece | Role |
|---|---|
| [`PermissionSubjectResolverInterface`](../../src/oihana/auth/PermissionSubjectResolverInterface.php) | Translates a permission subject (human-readable label, e.g. `roles.permissions:list`) into the `(object, action)` couple that Casbin can evaluate. To be implemented by the consumer on top of their preferred storage. |
| [`PermissionAuthorizerTrait`](../../src/oihana/auth/controllers/traits/PermissionAuthorizerTrait.php) | Trait pluggable into any HTTP controller. Exposes `buildPermissionAuthorizer($request)` which returns a `Closure(string $subject): bool` ready to wire into the projection layer. |

The pipeline:

```text
subject ──► PermissionSubjectResolverInterface ──► (object, action) ──► CapabilityEnforcer::enforceObjectAction() ──► true / false
```

The closure returned by `buildPermissionAuthorizer()` chains the 3 steps and is `null` when the user is not identified (no `userId` attribute on the request) or services are not injected.

## HTTP response behaviour

The contract is simple to read for the UI:

| Case | Presence in the response |
|---|---|
| The user has the permission | Key present, value hydrated |
| The user does not have the permission | **Key absent** — as if the field were not part of the requested projection |
| The user has the permission, but the value is empty | Key present, value `[]` or `null` depending on the context |
| Companion `*Count` field | Visible by default (can be gated separately if needed) |

Choosing "key absent rather than `null` or `[]`" is deliberate: it lets the UI distinguish three cases with a simple `if (data.permissions !== undefined)`.

## Choosing the subject

**Rule**: `Field::REQUIRES` (or its model/ORM equivalent) uses the permission of the dedicated HTTP sub-route for that projection, whether or not the sub-route is already registered.

- The sub-route exists (`GET /roles/{id}/permissions`) → use its dedicated permission (`roles.permissions:list`). Same Casbin rule for the sub-route and the projection.
- The sub-route does not exist yet → still introduce the dedicated permission (`policies.roles:list`) in the seeds with its future `(object, action)` couple. Gating works immediately (Casbin does not depend on the HTTP route existing) and the route can be added later.

### Why not a top-level perm (`services:list`) for an inverse view

The global inventory and the inverse view answer different questions:

| View | Question | Sensitivity |
|---|---|---|
| `GET /services` | "Which services exist?" | Global inventory |
| `services[]` on a policy | "Which services depend on this policy?" | Dependency information |

An auditor may be allowed to list the inventory but not see dependencies. The two rights are orthogonal.

## Implementing `PermissionSubjectResolverInterface`

The interface has 2 methods:

```php
namespace oihana\auth ;

interface PermissionSubjectResolverInterface
{
    /**
     * Returns the (object, action) couple bound to a subject, or null if unknown.
     */
    public function resolve( string $subject ) : ?array ;

    /**
     * Returns the full subject → (object, action) map. Useful for tests and debug.
     */
    public function getMap() : array ;
}
```

A typical consumer implements this interface on top of their permission storage (ArangoDB, MySQL, Redis, a static JSON file), with a memory or Memcached cache of their choice. The library does not prescribe the storage.

## Wiring into a controller

In a controller using `PermissionAuthorizerTrait`, the authorisation closure is built per HTTP request:

```php
use Psr\Http\Message\ServerRequestInterface as Request ;

use oihana\auth\controllers\traits\PermissionAuthorizerTrait ;

class RolesController
{
    use PermissionAuthorizerTrait ;

    // The trait exposes protected ?PermissionSubjectResolverInterface $permissionSubjectResolver
    // and protected ?CapabilityEnforcer $capabilityEnforcer ;
    // Both are injected via DI or via initializePermissionSubjectResolver().

    public function list( Request $request ) : array
    {
        $authorizer = $this->buildPermissionAuthorizer( $request ) ;

        // $authorizer is null when:
        // - no userId attribute on the request
        // - no resolver injected
        // - no enforcer injected
        //
        // Otherwise it is a Closure(string $subject) : bool
        // passed down to the model layer so it can filter the projection.

        return $this->model->list( authorizer: $authorizer ) ;
    }
}
```

The model layer (consumer side) calls the closure for each projected field that carries a permission requirement. When the closure returns `false`, the field is dropped from the projection.

## Difference with fine-grained capabilities

Field-level gating and fine-grained capabilities are **complementary mechanisms**, not to be confused:

| Aspect | Capabilities (`PARAM:` / `FIELDS:`) — see [Capabilities](capabilities.md) | Field-level gating (this page) |
|---|---|---|
| Granularity | Query-param value, filter key, body field | Projected field on GET |
| Casbin action | `PARAM:<discriminator>` or `FIELDS:<discriminator>` | Standard HTTP verb (`GET`, `POST`, …) — reuses the sub-route permission |
| Permissions to seed | New dedicated permissions | Reuses existing HTTP permissions or the future sub-route permission |
| Trait | `CapabilityGuardTrait` / `CapabilityAuthorizerTrait` | `PermissionAuthorizerTrait` |
| Use case | "Can this user use `?skin=offers.full`?" | "Can this user see the `permissions[]` array?" |

Both mechanisms can coexist on the same controller.

## Caching strategies on the consumer side

The subject → `(object, action)` map is read by `resolve()` on every permission check. A consumer typically wants to cache that map to avoid hitting storage on every call.

Recommended (not prescriptive) strategies:

- **Lazy in-memory cache**: load the full map on the first call (`getMap()`) and serve from an internal array.
- **Distributed cache** (Memcached / Redis) with TTL (1 h is a common pick): useful in multi-process deployments.
- **Signal-driven invalidation**: if your storage emits write signals (`afterInsert` / `afterDelete` on the permissions collection), wire a function to purge the resolver cache.

The library imposes none of these — your `PermissionSubjectResolverInterface` implementation is free to combine them as it wants.

## Further reading

- [Permissions](permissions.md) — the `<resource>:<action>` naming convention and typed enums.
- [Capabilities](capabilities.md) — the complementary mechanism for query params, filters, transversal actions.
- [Tips & best practices](tips.md) — always normalise the Casbin subject with `casbinSafeSubject()`.
