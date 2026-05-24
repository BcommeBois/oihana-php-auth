# Permissions

A **permission** is the atomic unit of Casbin access control: a `(subject, object, action)` triple that grants or denies (`effect`) a verb against a target.

This page documents the naming convention recommended by the library and the typed enums exposed under `oihana\auth\enums`.

> 🇫🇷 [Version française](../fr/permissions.md)

## Anatomy of a permission

```text
subject = "products:list"     // logical identifier
object  = "/products"         // target (HTTP path or logical resource)
action  = "GET"               // authorization verb
effect  = "allow"             // allow or deny
```

| Field | Type | Notes |
|---|---|---|
| `subject` | string | Logical identifier, conventionally `<resource>:<action>` (e.g. `products:list`) |
| `object` | string | HTTP path (`/products`, `/products/:id`) **or** a logical resource name for fine-grained capabilities |
| `action` | string | Authorization verb — see [§ `action` values](#action-values) |
| `effect` | string | `"allow"` (default) or `"deny"` — see [`PermissionEffect`](../../src/oihana/auth/enums/PermissionEffect.php) |

## `<resource>:<action>` naming

The recommended `subject` convention is `<resource>` + `:` + `<action>`, e.g. `products:list`, `roles:get`, `me.permissions:list`.

`.` (dot) characters work as a **discriminator** to structure complex capabilities (e.g. `products:skin.offers.full` describes the `skin.offers.full` capability on the `products` resource).

> 💡 See [Tips & best practices](tips.md) — always use typed constants, never magic strings.

## Typed enums

The library ships ready-to-use enums so you never have to spell out a subject as a magic string:

| Enum / trait | Role |
|---|---|
| [`AuthPermissions`](../../src/oihana/auth/enums/AuthPermissions.php) | Catalogue of native RBAC subjects (`me.permissions:list`, `roles:list`, etc.) |
| [`enums/permissions/traits/MePermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/MePermissionsTrait.php) | `/me` self-service subjects |
| [`enums/permissions/traits/PoliciesPermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/PoliciesPermissionsTrait.php) | `policies:*` subjects |
| [`enums/permissions/traits/RolesPermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/RolesPermissionsTrait.php) | `roles:*` subjects |
| [`enums/permissions/traits/ServicesPermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/ServicesPermissionsTrait.php) | `services:*` (M2M) subjects |
| [`enums/permissions/traits/UsersPermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/UsersPermissionsTrait.php) | `users:*` subjects |
| [`PermissionEffect`](../../src/oihana/auth/enums/PermissionEffect.php) | `ALLOW` / `DENY` constants |
| [`CapabilityAction`](../../src/oihana/auth/enums/CapabilityAction.php) | `PARAM:` and other prefixes for fine-grained capabilities |

### Extending the enums

A consuming application typically exposes its own `Permissions` enum that aggregates `AuthPermissions` + its business traits:

```php
namespace MyApp\Enums ;

use oihana\auth\enums\AuthPermissions ;
use oihana\reflect\traits\ConstantsTrait ;

class Permissions extends AuthPermissions
{
    use ConstantsTrait ;

    // Business subjects
    public const string PRODUCTS_LIST   = 'products:list' ;
    public const string PRODUCTS_GET    = 'products:get' ;
    public const string PRODUCTS_CREATE = 'products:create' ;
}
```

## `action` values

The `action` field is not strictly limited to HTTP verbs. Two families coexist:

### 1. HTTP verbs — route permissions

Used to guard classic HTTP endpoints.

| `action` | Usage |
|---|---|
| `GET` | Read (list, get) |
| `POST` | Create |
| `PATCH` | Partial update |
| `PUT` | Full replacement |
| `DELETE` | Remove |

Example:

```text
subject: "products:list"
object:  "/products"
action:  "GET"
```

### 2. Fine-grained capabilities — `PARAM` system

Gate query-param values, filter keys or transversal actions **inside** an already-protected route. The pattern is `PARAM:<capability>`, where `<capability>` identifies the allowed value.

| Example `action` | Usage |
|---|---|
| `PARAM:skin.offers.full` | Allow `?skin=offers.full` on an existing route |
| `PARAM:filter.<key>` | Allow a specific filter |
| `PARAM:export.<format>` | Allow an export format |
| `PARAM:bypass.level.hierarchy` | Override a transversal business rule |

Example:

```text
subject: "products:skin.offers.full"
object:  "/products"
action:  "PARAM:skin.offers.full"
```

See [Capabilities](capabilities.md) for the full semantics (`REQUIRE` / `DENY` modes, enforcement pipeline).

## `allow` vs `deny` effect

The `effect` field (validated by [`PermissionEffect`](../../src/oihana/auth/enums/PermissionEffect.php)) follows Casbin semantics:

- `allow` (default) — the permission **grants** access.
- `deny` — the permission **explicitly denies** access, overriding any other rule that would grant it. Used for denylist policies.

Casbin resolves conflicts according to the matcher defined in the `.conf` model. For the distinction between "no permission" and "explicit deny", see [`CapabilityEnforcer::isDenied()`](../../src/oihana/auth/casbin/CapabilityEnforcer.php).

## Best practices

1. **Always type subjects** via enums (`AuthPermissions::PRODUCTS_LIST`), never a magic string in application code.
2. **Keep seed/code in sync**: if you materialise permissions from a seed file (TOML, JSON, database), add a build-time test that ensures every `Permissions::CONSTANT` PHP has a matching `subject` in the seed.
3. **Normalise Casbin subjects** with [`casbinSafeSubject()`](../../src/oihana/auth/helpers/casbinSafeSubject.php) — see [Tips & best practices](tips.md).
4. **Materialisation strategy** is up to the consumer: the library does not prescribe where to store permissions (ArangoDB, MySQL, static file). It only ships the abstractions to validate, enforce and type them.
