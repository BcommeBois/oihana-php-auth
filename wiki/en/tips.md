# Tips & best practices

Catalogue of rules to follow when touching code that talks to Casbin through this library.

> 🇫🇷 [Version française](../fr/tips.md)

## Table of contents

- [Always normalise a Casbin subject through `casbinSafeSubject()`](#always-normalise-a-casbin-subject-through-casbinsafesubject)
- [Match the route placeholder name with the Casbin permission `:name`](#match-the-route-placeholder-name-with-the-casbin-permission-name)

---

## Always normalise a Casbin subject through `casbinSafeSubject()`

**Rule.** Any user, service or role identifier flowing into the `Casbin\Enforcer` (read **or** write) must be passed through the helper `oihana\auth\helpers\casbinSafeSubject()` as close to the call site as possible.

### Why

Many OIDC IdPs (Zitadel, Auth0, etc.) emit purely-numeric `sub` claims (e.g. `364646423545321675`). When Casbin stores such a subject as an `array<string, …>` key, PHP silently coerces it to `int` — see [`DefaultRoleManager\Role::$roles`](https://github.com/php-casbin/php-casbin).

On read, the inner `getRoles()` receives an `int` where it expects a `string`, breaking the role manager (key not found, empty result, or fatal `TypeError`).

[`casbinSafeSubject()`](../../src/oihana/auth/helpers/casbinSafeSubject.php) prefixes purely-digital strings with `n_`:

```php
'364646423545321675' → 'n_364646423545321675'
'role_73478334'      → 'role_73478334'   (already prefixed, no-op)
'alice'              → 'alice'           (no-op)
```

The normalisation is **symmetric**: every subject written through one path must be read through the same path. If you write `n_…` and read `…` raw, Casbin returns `[]` with no error — a silent bug.

### Where to apply it

| Direction | Casbin methods |
|---|---|
| Write | `addPolicy`, `removePolicy`, `addGroupingPolicy`, `removeGroupingPolicy`, `deleteRole` |
| Read  | `enforce`, `getImplicitPermissionsForUser`, `getImplicitRolesForUser`, `getRolesForUserInDomain`, `getPermissionsForUserInDomain`, `hasRoleForUser` |

### Pattern

```php
use function oihana\auth\helpers\casbinSafeSubject ;

$subject = casbinSafeSubject( (string) $userId ) ;

$allowed = $this->enforcer->enforce( $subject , $domain , $object , $action ) ;
```

### Symptoms of a missed call

- A protected route works but a capability check silently fails → unexpected fallback.
- An endpoint listing effective permissions shows the expected permission, yet `enforce()` refuses it for the same user on the same route.
- A unit test passes (fixtures use `'alice'` / `'bob'`) but the regression only surfaces in production with real numeric subjects.

### Recommended tests

When new code calls the `Enforcer`, add at least one case with a purely-numeric subject (e.g. `'1234567890'`) alongside the alphabetic fixtures. Backwards compatibility with `'alice'`-style subjects is worthless if it masks the regression on real IdP identifiers.

---

## Match the route placeholder name with the Casbin permission `:name`

**Rule.** When canonicalising an HTTP path into a Casbin pattern, the placeholder name in the path (`{xxx}`) must be **identical** to the one used in the seeded permission (`:xxx`). Otherwise the emitted pattern does not match the stored permission, and access is silently denied with a 403 — even for an administrator.

### Why

Canonicalising a path into a Casbin pattern replaces every segment matching a route argument with `:argName`. The placeholder name is read **as-is** from the route pattern — there is no implicit rename to `:id`.

Example:

```text
// Declared path: '/logs/{file}'
// Request: GET /logs/my-app-2026-05-18.log
// Args: ['file' => 'my-app-2026-05-18.log']
// Canonicalisation: '/logs/:file'

// Seeded permission:
// object = "/logs/:id"
// → silent mismatch → 403 Forbidden
```

### Recommended convention

Use **`{id}`** by default, which produces the `:id` canonicalisation matched by seeded permissions like `/foo/:id`. Rare cases where another name is legitimate (e.g. `{activityId}`, `{targetId}` when two placeholders coexist in the same path) must be documented, and their seeded permission must use the **same name** on the `:` side.

### Symptoms

- A protected route returns 403 even though the user owns the listed permission.
- The E2E test passes in an auth-disabled environment but fails as soon as authorisation is enabled.
- Adding a new route with a placeholder works for `GET /foo` (collection) but fails for `GET /foo/{something}` (single resource).

### Recommended tests

When adding a route with a placeholder:

1. Verify that the placeholder name matches the seeded permission name exactly.
2. Verify that the route returns 200 (not 403) for an admin on a real subject.

In the long run, an automated test can canonicalise every route in the registry and check that each emitted pattern exists in the seeds.
