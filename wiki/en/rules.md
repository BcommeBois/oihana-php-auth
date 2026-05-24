# Validation rules

> **Definition.** A **validation rule** is a declarative constraint that inspects an incoming field and rejects it if malformed.

[`oihana/php-auth`](https://github.com/BcommeBois/oihana-php-auth) relies on [Somnambulist Validation](https://github.com/somnambulist-tech/validation) (package `somnambulist/validation`) for rules, and exposes its own `Rule` classes under the `oihana\auth\rules\` namespace.

> 🇫🇷 [Version française](../fr/rules.md)

## Rules shipped by the library

A single business rule is exposed today:

| Class | Slug | Description |
|---|---|---|
| [`RoleNameRule`](../../src/oihana/auth/rules/RoleNameRule.php) | `auth:role:name` | Validates a canonical role name: 2 to 70 ASCII characters from `[a-z0-9 _-]`. |

This rule is used by the role create/edit flows in the RBAC chain. Covered by [`RoleNameRuleTest`](../../tests/oihana/auth/rules/RoleNameRuleTest.php) (12 cases).

### Direct usage

```php
use oihana\auth\rules\RoleNameRule ;

$rule = new RoleNameRule() ;
$rule->check( 'developer' )    ; // true
$rule->check( 'DeveloPER' )    ; // false — uppercase rejected
$rule->check( 'admin role' )   ; // true — internal spaces OK
$rule->check( 'à' )            ; // false — accent rejected
```

### Wiring into the Somnambulist validator

```php
use Somnambulist\Components\Validation\Factory ;

use oihana\auth\rules\RoleNameRule ;

$validator = new Factory() ;
$validator->setRule( 'auth:role:name' , new RoleNameRule() ) ;

$validation = $validator->validate
(
    [ 'name' => 'My Role' ] ,
    [ 'name' => 'required|string|auth:role:name' ]
) ;

if ( $validation->fails() )
{
    $errors = $validation->errors()->firstOfAll() ;
    // → [ 'name' => 'The Name must be 2-70 lowercase ASCII characters…' ]
}
```

## Catalogue of native Somnambulist rules

Native rules (`required`, `min`, `max`, `email`, `integer`, etc.) come from `somnambulist/validation`. The most common ones used with `oihana/php-auth`:

### Presence and type

| Rule | Description |
|---|---|
| `required` | Field must be present and non-empty. |
| `nullable` | Allows `null` (combine with `required` when `null` must pass). |
| `present` | Key must exist, even at `null`. |
| `string` | Must be a string. |
| `integer` | Must be an integer. |
| `boolean` | Must be a boolean. |

### Format

| Rule | Description |
|---|---|
| `email` | Valid email. |
| `url` | Valid URL. |
| `uuid` | Valid UUID. |
| `regex:<pattern>` | Must match the given regex. |
| `date` | Must be parseable by `strtotime`. |

### Length and bounds

| Rule | Description |
|---|---|
| `min:N` | Minimum length (string) or value (number). |
| `max:N` | Maximum length or value. |
| `between:min,max` | Between two inclusive bounds. |

### Conditional logic

| Rule | Description |
|---|---|
| `required_if:field,value` | Required when another field has a specific value. |
| `required_unless:field,value` | Required unless the condition holds. |
| `required_with:field` | Required when another field is present. |

For the full catalogue (70+ rules), see the [Somnambulist docs](https://github.com/somnambulist-tech/validation?tab=readme-ov-file#available-rules).

## Writing a custom rule

To add your own rule, extend `Somnambulist\Components\Validation\Rule`:

```php
namespace MyApp\Rules ;

use Somnambulist\Components\Validation\Rule ;

class HexColorRule extends Rule
{
    public const string NAME = 'color' ;

    protected string $message = ':attribute must be a valid #RRGGBB color' ;

    private const string PATTERN = '/\A#[0-9A-Fa-f]{6}\z/' ;

    public function check( mixed $value ) : bool
    {
        if ( ! is_string( $value ) )
        {
            return false ;
        }

        return (bool) preg_match( self::PATTERN , $value ) ;
    }
}
```

Then register it on the validator:

```php
$validator->setRule( 'color' , new HexColorRule() ) ;
```

### Tip: stable slug

Pick a short, stable slug (`color`, `auth:role:name`, `geo:latitude`) instead of a context-dependent name. The slug does not appear in the error message (unless you put it explicitly in `$message`) — it identifies the rule for the validator and helps UI-side i18n.

## `body.errors` response shape

When validation fails, the API typically returns a `400 Bad Request` with a normalised envelope:

```json
{
    "status": "error",
    "code": 400,
    "body": {
        "errors": {
            "name":  "The Name must be 2-70 lowercase ASCII characters",
            "color": "The Color is required"
        }
    }
}
```

| Element | Description |
|---|---|
| Map key | Field name that failed (as submitted in the payload). |
| Map value | Human message of the **first rule** that failed on that field. |

> The `body.errors` shape is not imposed by this library — it is a common convention. You are free to aggregate Somnambulist errors (`$validation->errors()->firstOfAll()`) in the shape that fits your frontend.

## Common pitfalls

### `required` in a shared rule breaks PATCH

`required` is a **creation** constraint. On a partial update (PATCH), the absence of a field means "don't touch this value". Do not put `required` in the shared section — declare the rule for the POST method only.

### Validate the same thing only once

If a native rule (`min:2`) already covers length, do not re-validate it in a custom rule. **Structural layer** (native rules) and **business layer** (custom rules) are complementary, not redundant.

### Validator short-circuiting

The Somnambulist engine short-circuits the chain at the first failure. If `string` fails (non-string value), the next custom rule (`auth:role:name`) is never called — it only receives the value once every previous rule passes.

## Tests

Rule tests live under [`tests/oihana/auth/rules/`](../../tests/oihana/auth/rules/):

```bash
# All rule tests
composer test -- --filter='Rule'

# A specific rule
composer test -- --filter='RoleNameRuleTest'
```

## See also

- [Permissions](permissions.md) — subject naming convention.
- [Capabilities](capabilities.md) — fine-grained gating on params / fields.
- [Tips & best practices](tips.md) — conventions and anti-patterns.
- [Somnambulist Validation](https://github.com/somnambulist-tech/validation) — full external reference.
