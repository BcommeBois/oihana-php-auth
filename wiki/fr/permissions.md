# Permissions

Une **permission** est l'unité atomique du contrôle d'accès Casbin : un triplet `(subject, object, action)` qui accorde ou refuse (`effect`) un verbe sur une cible.

Cette page documente la nomenclature recommandée par la bibliothèque et les enums typés exposés sous `oihana\auth\enums`.

> 🇬🇧 [English version](../en/permissions.md)

## Anatomie d'une permission

```text
subject = "products:list"     // identifiant logique
object  = "/products"         // cible (chemin HTTP ou ressource logique)
action  = "GET"               // verbe d'autorisation
effect  = "allow"             // allow ou deny
```

| Champ | Type | Notes |
|---|---|---|
| `subject` | string | Identifiant logique, par convention `<ressource>:<action>` (ex: `products:list`) |
| `object` | string | Chemin HTTP (`/products`, `/products/:id`) **ou** nom d'une ressource logique pour les capacités fines |
| `action` | string | Verbe d'autorisation — voir [§ Valeurs d'`action`](#valeurs-daction) |
| `effect` | string | `"allow"` (défaut) ou `"deny"` — voir [`PermissionEffect`](../../src/oihana/auth/enums/PermissionEffect.php) |

## Nomenclature `<ressource>:<action>`

Convention pour le `subject` : `<resource>` + `:` + `<action>`, par exemple `products:list`, `roles:get`, `me.permissions:list`.

Les `.` (points) servent de **discriminator** pour structurer les capacités complexes (par exemple `products:skin.offers.full` désigne la capacité `skin.offers.full` sur la ressource `products`).

> 💡 Voir [Bonnes pratiques](tips.md) — toujours utiliser des constantes typées, jamais de strings magiques.

## Enums typés

La bibliothèque fournit des enums prêts à l'emploi pour ne jamais avoir à écrire un sujet en string magique :

| Enum / trait | Rôle |
|---|---|
| [`AuthPermissions`](../../src/oihana/auth/enums/AuthPermissions.php) | Catalogue des sujets natifs de la chaîne RBAC (`me.permissions:list`, `roles:list`, etc.) |
| [`enums/permissions/traits/MePermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/MePermissionsTrait.php) | Sujets du surface `/me` (self-service) |
| [`enums/permissions/traits/PoliciesPermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/PoliciesPermissionsTrait.php) | Sujets `policies:*` |
| [`enums/permissions/traits/RolesPermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/RolesPermissionsTrait.php) | Sujets `roles:*` |
| [`enums/permissions/traits/ServicesPermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/ServicesPermissionsTrait.php) | Sujets `services:*` (M2M) |
| [`enums/permissions/traits/UsersPermissionsTrait`](../../src/oihana/auth/enums/permissions/traits/UsersPermissionsTrait.php) | Sujets `users:*` |
| [`PermissionEffect`](../../src/oihana/auth/enums/PermissionEffect.php) | Constantes `ALLOW` / `DENY` |
| [`CapabilityAction`](../../src/oihana/auth/enums/CapabilityAction.php) | Préfixes `PARAM:` et autres pour les capacités fines |

### Étendre les enums

Une application consommatrice expose typiquement son propre enum `Permissions` qui agrège `AuthPermissions` + ses traits métier :

```php
namespace MyApp\Enums ;

use oihana\auth\enums\AuthPermissions ;
use oihana\reflect\traits\ConstantsTrait ;

class Permissions extends AuthPermissions
{
    use ConstantsTrait ;

    // Sujets métier
    public const string PRODUCTS_LIST   = 'products:list' ;
    public const string PRODUCTS_GET    = 'products:get' ;
    public const string PRODUCTS_CREATE = 'products:create' ;
}
```

## Valeurs d'`action`

Le champ `action` n'est pas strictement limité aux verbes HTTP. Deux familles cohabitent :

### 1. Verbes HTTP — permissions de route

Utilisés pour garder des endpoints HTTP classiques.

| `action` | Usage |
|---|---|
| `GET` | Lecture (list, get) |
| `POST` | Création |
| `PATCH` | Mise à jour partielle |
| `PUT` | Remplacement complet |
| `DELETE` | Suppression |

Exemple :

```text
subject: "products:list"
object:  "/products"
action:  "GET"
```

### 2. Capacités fines — système `PARAM`

Gardent des valeurs de query params, des clés de filtre ou des actions transversales **à l'intérieur** d'une route déjà protégée. Le pattern est `PARAM:<capacité>`, où `<capacité>` identifie la valeur autorisée.

| Exemple d'`action` | Usage |
|---|---|
| `PARAM:skin.offers.full` | Autorise `?skin=offers.full` sur une route existante |
| `PARAM:filter.<clé>` | Autorise un filtre spécifique |
| `PARAM:export.<format>` | Autorise un format d'export |
| `PARAM:bypass.level.hierarchy` | Outrepasse une règle métier transversale |

Exemple :

```text
subject: "products:skin.offers.full"
object:  "/products"
action:  "PARAM:skin.offers.full"
```

Voir [Capacités](capabilities.md) pour la sémantique complète (modes `REQUIRE`, `DENY`, pipeline d'enforcement).

## Effet `allow` vs `deny`

Le champ `effect` (validé par [`PermissionEffect`](../../src/oihana/auth/enums/PermissionEffect.php)) suit la sémantique Casbin :

- `allow` (défaut) — la permission **accorde** l'accès.
- `deny` — la permission **refuse** explicitement l'accès, même si une autre règle l'accorderait. Utilisé pour les politiques de denylist.

Casbin résout les conflits selon le matcher défini dans le model `.conf`. Pour la nuance entre "pas de permission" et "deny explicite", voir [`CapabilityEnforcer::isDenied()`](../../src/oihana/auth/casbin/CapabilityEnforcer.php).

## Bonnes pratiques

1. **Toujours typer les sujets** via les enums (`AuthPermissions::PRODUCTS_LIST`), jamais de string magique dans le code applicatif.
2. **Garder la consistance** seed/code : si vous matérialisez les permissions depuis un fichier de seed (TOML, JSON, base), un test au build doit vérifier que chaque `Permissions::CONSTANT` PHP a un `subject` correspondant dans le seed.
3. **Normaliser les sujets Casbin** avec [`casbinSafeSubject()`](../../src/oihana/auth/helpers/casbinSafeSubject.php) — voir [Bonnes pratiques](tips.md).
4. **Stratégie de matérialisation** côté consommateur : la lib ne prescrit pas où stocker les permissions (ArangoDB, MySQL, fichier statique). Elle fournit juste les abstractions pour les valider, les enforcer et les typer.
