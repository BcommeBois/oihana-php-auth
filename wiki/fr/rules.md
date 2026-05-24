# Règles de validation

> **Définition.** Une **règle de validation** est une contrainte déclarative qui inspecte un champ entrant et le rejette s'il est mal formé.

La bibliothèque [`oihana/php-auth`](https://github.com/BcommeBois/oihana-php-auth) s'appuie sur [Somnambulist Validation](https://github.com/somnambulist-tech/validation) (paquet `somnambulist/validation`) pour les règles, et expose ses propres classes `Rule` sous le namespace `oihana\auth\rules\`.

> 🇬🇧 [English version](../en/rules.md)

## Règles fournies par la lib

Une seule règle métier est exposée à ce jour :

| Classe | Slug | Description |
|---|---|---|
| [`RoleNameRule`](../../src/oihana/auth/rules/RoleNameRule.php) | `auth:role:name` | Valide un nom de rôle canonique : 2 à 70 caractères ASCII parmi `[a-z0-9 _-]`. |

Cette règle est utilisée par défaut dans les flows de création/édition de rôles RBAC. Elle est testée dans [`RoleNameRuleTest`](../../tests/oihana/auth/rules/RoleNameRuleTest.php) (12 cas couvrants).

### Utilisation directe

```php
use oihana\auth\rules\RoleNameRule ;

$rule = new RoleNameRule() ;
$rule->check( 'developer' )    ; // true
$rule->check( 'DeveloPER' )    ; // false — uppercase rejeté
$rule->check( 'admin role' )   ; // true — espaces internes OK
$rule->check( 'à' )            ; // false — accent rejeté
```

### Intégration au validateur Somnambulist

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

## Catalogue des règles natives Somnambulist

Les règles natives (`required`, `min`, `max`, `email`, `integer`, etc.) sont fournies par `somnambulist/validation`. Voici les plus couramment utilisées avec `oihana/php-auth` :

### Présence et type

| Règle | Description |
|---|---|
| `required` | Le champ doit être présent et non vide. |
| `nullable` | Autorise `null` (à combiner avec `required` quand `null` doit passer). |
| `present` | La clé doit exister, même à `null`. |
| `string` | Doit être une chaîne. |
| `integer` | Doit être un entier. |
| `boolean` | Doit être un booléen. |

### Format

| Règle | Description |
|---|---|
| `email` | Email valide. |
| `url` | URL valide. |
| `uuid` | UUID valide. |
| `regex:<pattern>` | Doit matcher la regex passée en paramètre. |
| `date` | Doit être parseable par `strtotime`. |

### Longueur et bornes

| Règle | Description |
|---|---|
| `min:N` | Longueur (string) ou valeur (number) minimum. |
| `max:N` | Longueur ou valeur maximum. |
| `between:min,max` | Entre deux bornes (inclusives). |

### Logique conditionnelle

| Règle | Description |
|---|---|
| `required_if:field,value` | Obligatoire si un autre champ vaut une valeur précise. |
| `required_unless:field,value` | Obligatoire sauf si la condition est vraie. |
| `required_with:field` | Obligatoire si un autre champ est présent. |

Pour le catalogue complet (70+ règles), voir la [doc Somnambulist](https://github.com/somnambulist-tech/validation?tab=readme-ov-file#available-rules).

## Écrire une règle custom

Pour ajouter sa propre règle, étendre `Somnambulist\Components\Validation\Rule` :

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

Puis l'enregistrer côté validateur :

```php
$validator->setRule( 'color' , new HexColorRule() ) ;
```

### Conseil : slug stable

Privilégier un slug court et stable (`color`, `auth:role:name`, `geo:latitude`) plutôt qu'un nom dépendant du contexte. Le slug n'apparaît pas dans le message d'erreur (sauf si vous le mettez explicitement dans `$message`) — il sert d'identifiant pour le validateur et facilite l'i18n côté UI.

## Format des erreurs `body.errors`

Quand la validation échoue, l'API renvoie typiquement un `400 Bad Request` avec une enveloppe normalisée :

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

| Élément | Description |
|---|---|
| Clé de la map | Nom du champ qui a échoué (tel qu'envoyé dans le payload). |
| Valeur | Message humain de la **première règle** qui a échoué sur ce champ. |

> Le shape `body.errors` n'est pas imposé par cette bibliothèque — c'est une convention répandue. Vous êtes libres d'agréger les erreurs Somnambulist (`$validation->errors()->firstOfAll()`) dans la forme qui correspond à votre frontend.

## Pièges courants

### `required` dans une règle commune casse les PATCH

`required` est une contrainte **de création**. Sur une mise à jour partielle (PATCH), l'absence du champ signifie « ne touche pas à cette valeur ». Ne pas mettre `required` dans la section partagée — déclarer la règle uniquement pour la méthode POST.

### Ne valider la même chose qu'une seule fois

Si une règle native (`min:2`) couvre déjà la longueur, ne pas la redoubler dans une règle custom. **Couche structurelle** (règles natives) et **couche métier** (règles custom) sont complémentaires, pas redondantes.

### Court-circuit du validateur

Le moteur Somnambulist court-circuite la chaîne dès la première erreur. Si `string` échoue (valeur non-string), la règle custom suivante (`auth:role:name`) n'est jamais appelée — elle reçoit la valeur seulement si toutes les règles précédentes passent.

## Tests

Les tests des règles vivent dans [`tests/oihana/auth/rules/`](../../tests/oihana/auth/rules/) :

```bash
# Toutes les règles
composer test -- --filter='Rule'

# Une règle précise
composer test -- --filter='RoleNameRuleTest'
```

## Voir aussi

- [Permissions](permissions.md) — nomenclature des sujets.
- [Capacités](capabilities.md) — contrôle fin au niveau paramètres / champs.
- [Bonnes pratiques](tips.md) — conventions et anti-patterns.
- [Somnambulist Validation](https://github.com/somnambulist-tech/validation) — référence externe complète.
