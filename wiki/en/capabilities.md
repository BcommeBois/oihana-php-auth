# Fine-grained capabilities

**Fine-grained capabilities** extend the Casbin vocabulary (which natively understands HTTP verbs `GET`, `POST`, `PATCH`, …) to control access to elements **inside** a route:

- a query-param value (`?skin=offers.full`, `?export=true`),
- a sensitive filter key (`?filter=[{"key":"costPrice",…}]`),
- a field written in a PATCH or POST body (`PATCH /users/{id} { status: "disabled" }`),
- a transversal action (business flag, debug mode, …).

All of this without touching the Casbin engine or the permission storage schema.

> 🇫🇷 [Version française](../fr/capabilities.md)

## Why capabilities?

Without this mechanism, there is only one granularity: *route access*. Any user with `GET /products` can use any `?skin=…`, any filter, any export. Capabilities let you reserve certain values for certain roles without duplicating routes.

## Vocabulary

| Term | Meaning |
|---|---|
| **Capability** | A right targeted at a fragment of a route (param value, filter key, transversal action, body field). |
| **Mode** | Casbin check semantics: `REQUIRE` (closed by default, allowlist) or `DENY` (open by default, denylist). |
| **Policy** | Reaction when the check fails: `SILENT_DOWNGRADE` (replaces the value with a fallback) or `STRICT` (403 Forbidden). |
| **Object** | Route scope shared by every capability of a controller (e.g. `/products`). |
| **Discriminator** | Suffix of the `subject` / `action` that distinguishes two capabilities on the same route (`skin.offers.full` vs `export`). |

## Three action families

The [`CapabilityAction`](../../src/oihana/auth/enums/CapabilityAction.php) enum lists the prefixes:

| Prefix | Constant | Use case |
|---|---|---|
| `PARAM:` | `CapabilityAction::PARAM` | Query-param value, filter key, transversal action. Evaluated in `prepareSkin` / `prepareFilter` / `prepareSearch` hooks. |
| `FIELDS:` | `CapabilityAction::FIELDS` | Field written in a PATCH/POST/PUT body. Evaluated in `preparePayload()` before validation. |
| `FEATURE:` | `CapabilityAction::FEATURE` | Business flag or transversal mode not tied to an HTTP param. |

Sample Casbin permissions:

```text
subject = "products:skin.offers.full"
object  = "/products"
action  = "PARAM:skin.offers.full"
effect  = "allow"
```

```text
subject = "users:status.update"
object  = "/users"
action  = "FIELDS:status.update"
effect  = "allow"
```

## The two modes

The [`CapabilityMode`](../../src/oihana/auth/enums/CapabilityMode.php) enum:

| Mode | Semantics |
|---|---|
| `REQUIRE` | **Allowlist** — the caller must own the permission, otherwise denied. |
| `DENY` | **Denylist** — the caller passes by default, unless an explicit `effect=deny` permission is attached. |

### When to use `REQUIRE`

The normal mode for a **sensitive** capability whose access must be explicitly granted. Examples: `?skin=offers.full` (financial data), `?export=true` (heavy export), `PARAM:bypass.level.hierarchy` (overriding a business rule).

### When to use `DENY`

For a capability **open by default** where you want to occasionally block a subset of users (denylist). Example: `?skin=special` accessible to all except guest accounts that have an explicit `deny`.

### Casbin-side evaluation

| Mode | Logic in `CapabilityEnforcer` |
|---|---|
| `REQUIRE` | `has()` → native Casbin `enforce()` |
| `DENY` | `! isDenied()` → looks for an explicit `effect=deny` tuple |

## The two policies

The [`CapabilityPolicy`](../../src/oihana/auth/enums/CapabilityPolicy.php) enum:

| Policy | Effect when the check fails |
|---|---|
| `SILENT_DOWNGRADE` (default) | Replaces the denied value with a fallback (`Capability::FALLBACK` or `Capability::FALLBACKS`). The user never sees a 403 — they get the degraded response. |
| `STRICT` | Returns `403 Forbidden`. The user knows they attempted something forbidden. |

### When to use `SILENT_DOWNGRADE`

UX-friendly: when a natural fallback exists. Typically `?skin=offers.full` → fallback `?skin=offers` or `default`. The user without the permission silently consumes the degraded version.

### When to use `STRICT`

When no reasonable fallback exists, or for side-effect actions. Typically `PARAM:bypass.level.hierarchy` on `PATCH /users/{id}`: no half-measure, allow or deny.

## Declaring a capability — `Capability::*` block

The [`Capability`](../../src/oihana/auth/enums/Capability.php) enum lists the keys to use in the declaration block:

| Key | Constant | Role |
|---|---|---|
| `object` | `Capability::OBJECT` | Route scope (e.g. `/products`). |
| `subject` | `Capability::SUBJECT` | Casbin subject of the capability (e.g. `products:skin.offers.full`). |
| `mode` | `Capability::REQUIRE` or `Capability::DENY` | Evaluation mode. |
| `policy` | `Capability::POLICY` | `SILENT_DOWNGRADE` or `STRICT`. |
| `fallback` | `Capability::FALLBACK` | Replacement value when the check fails (silent mode). |
| `fallbacks` | `Capability::FALLBACKS` | Ordered cascade of fallbacks to try in order. |
| `keys` | `Capability::KEYS` | List of filter keys / fields the capability applies to. |
| `values` | `Capability::VALUES` | List of values to protect (for scalar PARAM). |
| `fields` | `Capability::FIELDS` | Specific config for FIELDS capabilities. |

### Example: restrict `?skin=offers.full`

```php
use oihana\auth\enums\Capability ;
use oihana\auth\enums\CapabilityAction ;
use oihana\auth\enums\CapabilityMode ;
use oihana\auth\enums\CapabilityPolicy ;

$capabilities =
[
    Capability::OBJECT => '/products' ,
    'skin' =>
    [
        Capability::SUBJECT  => 'products:skin.offers.full' ,
        Capability::REQUIRE  => CapabilityMode::REQUIRE ,
        Capability::POLICY   => CapabilityPolicy::SILENT_DOWNGRADE ,
        Capability::VALUES   => [ 'offers.full' ] ,
        Capability::FALLBACK => 'offers' ,
    ] ,
] ;
```

Reads: "on `/products`, the `?skin=offers.full` value requires the `products:skin.offers.full` permission; otherwise silently replace with `?skin=offers`".

### Example: multi-tier cascade

```php
'skin' =>
[
    Capability::SUBJECT   => 'products:skin.offers.full' ,
    Capability::REQUIRE   => CapabilityMode::REQUIRE ,
    Capability::POLICY    => CapabilityPolicy::SILENT_DOWNGRADE ,
    Capability::VALUES    => [ 'offers.full' ] ,
    Capability::FALLBACKS => [ 'offers' , 'default' ] ,
] ,
```

The caller asks for `offers.full` → check → denied → try `offers` (which may have its own permission) → if still denied → `default`. Enables graceful degradation.

### Example: sensitive field in a PATCH body (FIELDS)

```php
use oihana\auth\enums\CapabilityAction ;

'fields' =>
[
    Capability::SUBJECT => 'users:status.update' ,
    Capability::REQUIRE => CapabilityMode::REQUIRE ,
    Capability::POLICY  => CapabilityPolicy::STRICT ,
    Capability::FIELDS  =>
    [
        'status' => [ 'subject' => 'users:status.update' ] ,
    ] ,
] ,
```

Reads: "if the PATCH body contains the `status` field, the caller must own the `users:status.update` permission, otherwise 403".

## Exposed traits

The library ships several ready-to-use traits to include in an HTTP controller. Each has a precise scope:

| Trait | Scope |
|---|---|
| [`CapabilityGuardTrait`](../../src/oihana/auth/controllers/traits/CapabilityGuardTrait.php) | Base trait: initialises the enforcer and exposes `enforceCapability($subject, $mode)`. |
| [`CapabilityAuthorizerTrait`](../../src/oihana/auth/controllers/traits/CapabilityAuthorizerTrait.php) | Builds a `Closure(string): bool` to inject into the model layer for dynamic checks (capability equivalent of `PermissionAuthorizerTrait`). |
| [`CapabilityParamTrait`](../../src/oihana/auth/controllers/traits/CapabilityParamTrait.php) | Specialised for scalar query params (e.g. `?skin=…`). Handles REQUIRE/DENY + downgrade. |
| [`CapabilityFilterKeysTrait`](../../src/oihana/auth/controllers/traits/CapabilityFilterKeysTrait.php) | Specialised for filter keys `?filter=[{key:…}]`. Filters out forbidden keys. |
| [`CapabilityFieldsTrait`](../../src/oihana/auth/controllers/traits/CapabilityFieldsTrait.php) | Specialised for write body fields (FIELDS). Throws 403 or strips the field. |
| [`CapabilityBinaryTrait`](../../src/oihana/auth/controllers/traits/CapabilityBinaryTrait.php) | Specialised for binary actions (flag present / absent — no value). |
| [`CapabilityContextTrait`](../../src/oihana/auth/controllers/traits/CapabilityContextTrait.php) | Builds a capability context passed to the model layer (current skin, validated filter keys, etc.). |
| [`DocumentsControllerCapabilitiesTrait`](../../src/oihana/auth/controllers/traits/DocumentsControllerCapabilitiesTrait.php) | Composite trait bundling the others — for a CRUD controller that wants everything enabled. |

## Enforcement pipeline (conceptual)

```text
HTTP request
    ↓
Authorized middleware    ──► user owns the HTTP perm, request passes
    ↓
Controller hook prepareSkin / prepareFilter / prepareSearch / preparePayload
    ↓
CapabilityXxxTrait       ──► for each param / filter / field:
                              - lookup the declaration in the Capability::* block
                              - call CapabilityEnforcer::check($userId, $object, $cap, $mode)
                              - on denial:
                                  · policy SILENT_DOWNGRADE → swap with fallback
                                  · policy STRICT           → throw 403
    ↓
Controller business logic
    ↓
Response
```

## Best practices

1. **Always type values** via enums (`CapabilityAction::PARAM`, `CapabilityMode::REQUIRE`, `Capability::SUBJECT`), never magic strings.
2. **Prefer `SILENT_DOWNGRADE`** when a reasonable fallback exists (consistent UX).
3. **Prefer `STRICT`** for side-effect actions (mutation, override).
4. **Normalise Casbin subjects** with `casbinSafeSubject()` — see [Tips & best practices](tips.md).
5. **Document each new capability** in your application's permissions seed (the library does not prescribe a seed format).

## Difference with field-level gating

Capabilities and field-level gating are **complementary**:

| Aspect | Capabilities (this page) | Field-level gating (see [dedicated page](field-level-gating.md)) |
|---|---|---|
| Granularity | Param value, filter key, written field | Projected field on GET |
| When | Before the model layer (`prepareXxx`) | During AQL/ORM projection |
| Effect | Silent downgrade or 403 | Key absent from the response |
| Casbin action | `PARAM:` / `FIELDS:` / `FEATURE:` | Standard HTTP verb (`GET`) |

Both mechanisms can coexist on the same controller.

## Further reading

- [Field-level gating](field-level-gating.md) — gate the GET projection.
- [Permissions](permissions.md) — naming convention and typed enums.
- [Architecture](auth.md) — overview.
- [Tips & best practices](tips.md) — `casbinSafeSubject` is mandatory.
