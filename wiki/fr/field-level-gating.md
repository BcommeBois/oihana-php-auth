# Restriction au niveau du champ (field-level gating)

Une route HTTP peut être autorisée pour un utilisateur (`GET /roles` accessible) tout en exposant, dans sa réponse, des champs qu'il n'a pas le droit de voir (par exemple le tableau `permissions[]` hydraté quand on demande `?skin=full`).

Le **gating au niveau champ** ferme cette fuite : un champ projeté n'est inclus dans la réponse que si l'utilisateur détient la permission qui couvre ce détail. Sinon, la clé n'apparaît pas du tout dans le JSON.

> 🇬🇧 [English version](../en/field-level-gating.md)

## Le problème

Sans gating, un utilisateur qui a le droit `GET /roles/{id}` peut consulter dans la réponse :

- `permissions[]` — la liste complète des permissions attachées au rôle,
- `policies[]` — la liste complète des policies attachées au rôle.

…même s'il n'a **pas** les permissions HTTP qui couvrent ces détails (`roles.permissions:list` et `roles.policies:list`). L'interface peut masquer ces sections côté UI, mais l'API les a déjà servies — l'information a fuité dès que la requête a été émise.

Le gating ferme ce trou côté serveur : la même règle Casbin qui protège `GET /roles/{id}/permissions` protège aussi la projection `permissions[]` quand elle est demandée via `?skin=full`.

## Pièces du puzzle exposées par la lib

Le mécanisme repose sur deux abstractions :

| Pièce | Rôle |
|---|---|
| [`PermissionSubjectResolverInterface`](../../src/oihana/auth/PermissionSubjectResolverInterface.php) | Traduit un sujet de permission (étiquette lisible, ex: `roles.permissions:list`) vers le couple `(object, action)` que Casbin sait évaluer. À implémenter par le consommateur (au-dessus de sa base de données préférée). |
| [`PermissionAuthorizerTrait`](../../src/oihana/auth/controllers/traits/PermissionAuthorizerTrait.php) | Trait inclus dans n'importe quel contrôleur HTTP. Fournit `buildPermissionAuthorizer($request)` qui construit une `Closure(string $subject): bool` prête à brancher dans la couche de projection. |

Le pipeline :

```text
subject ──► PermissionSubjectResolverInterface ──► (object, action) ──► CapabilityEnforcer::enforceObjectAction() ──► true / false
```

La closure renvoyée par `buildPermissionAuthorizer()` enchaîne ces 3 étapes et est `null` quand l'utilisateur n'est pas identifié (pas d'attribut `userId` sur la requête) ou que les services ne sont pas injectés.

## Comportement côté réponse HTTP

Le contrat est simple à lire pour l'UI :

| Cas | Présence dans la réponse |
|---|---|
| L'utilisateur a la permission | Clé présente, valeur hydratée |
| L'utilisateur n'a pas la permission | **Clé absente** — comme si le champ ne faisait pas partie de la projection demandée |
| L'utilisateur a la permission, mais la valeur est vide | Clé présente, valeur `[]` ou `null` selon le contexte |
| Champ compagnon `*Count` | Visible par défaut (peut être gated séparément si besoin) |

Le choix « clé absente plutôt que `null` ou `[]` » est délibéré : il permet à l'UI de distinguer trois cas avec un simple `if (data.permissions !== undefined)`.

## Choisir le sujet à utiliser

**Règle** : `Field::REQUIRES` (ou l'équivalent côté ORM/modèle) utilise la permission de la sous-route HTTP dédiée à cette projection, qu'elle soit déjà enregistrée côté HTTP ou non.

- La sous-route existe (`GET /roles/{id}/permissions`) → utiliser sa permission dédiée (`roles.permissions:list`). Même règle Casbin pour la sous-route et la projection.
- La sous-route n'existe pas encore → introduire quand même la permission dédiée (`policies.roles:list`) dans les seeds avec son couple `(object, action)` futur. Le gating fonctionne immédiatement (Casbin ne dépend pas de l'existence de la route HTTP) et la route pourra être ajoutée plus tard.

### Pourquoi pas une perm top-level (`services:list`) pour une vue inverse

L'inventaire global et la vue inverse répondent à des questions différentes :

| Vue | Question | Sensibilité |
|---|---|---|
| `GET /services` | « Quels services existent ? » | Inventaire global |
| `services[]` sur une policy | « Quels services dépendent de cette policy ? » | Information de dépendance |

Un auditeur peut avoir le droit de lister l'inventaire sans avoir le droit de voir les dépendances. Les deux droits sont orthogonaux.

## Implémenter `PermissionSubjectResolverInterface`

L'interface a 2 méthodes :

```php
namespace oihana\auth ;

interface PermissionSubjectResolverInterface
{
    /**
     * Retourne le couple (object, action) bound au sujet, ou null si inconnu.
     */
    public function resolve( string $subject ) : ?array ;

    /**
     * Retourne le map complet sujet → (object, action). Utile pour les tests et le debug.
     */
    public function getMap() : array ;
}
```

Un consommateur typique implémente cette interface au-dessus de son stockage de permissions (ArangoDB, MySQL, Redis, fichier JSON statique), avec un cache mémoire ou Memcached à sa convenance. La lib ne prescrit pas le stockage.

## Brancher dans un contrôleur

Dans un contrôleur qui utilise `PermissionAuthorizerTrait`, la closure d'autorisation est créée à chaque requête HTTP :

```php
use Psr\Http\Message\ServerRequestInterface as Request ;

use oihana\auth\controllers\traits\PermissionAuthorizerTrait ;

class RolesController
{
    use PermissionAuthorizerTrait ;

    // Le trait expose protected ?PermissionSubjectResolverInterface $permissionSubjectResolver
    // et protected ?CapabilityEnforcer $capabilityEnforcer ;
    // Les deux sont à injecter via DI ou via initializePermissionSubjectResolver().

    public function list( Request $request ) : array
    {
        $authorizer = $this->buildPermissionAuthorizer( $request ) ;

        // $authorizer est null si :
        // - pas d'attribut userId sur la requête
        // - pas de resolver injecté
        // - pas d'enforcer injecté
        //
        // Sinon, c'est une Closure(string $subject) : bool
        // qu'on passe à la couche modèle pour qu'elle filtre la projection.

        return $this->model->list( authorizer: $authorizer ) ;
    }
}
```

La couche modèle (côté consommateur) consulte la closure pour chaque champ projeté qui porte une exigence de permission. Si la closure retourne `false`, le champ est dropé de la projection.

## Différence avec les capacités fines

Le gating au niveau champ et les capacités fines sont des **mécanismes complémentaires**, à ne pas confondre :

| Aspect | Capacités (`PARAM:` / `FIELDS:`) — voir [Capacités](capabilities.md) | Gating au niveau champ (cette page) |
|---|---|---|
| Granularité | Valeur d'un query param, clé de filtre, champ de body | Champ projeté en GET |
| Action Casbin | `PARAM:<discriminator>` ou `FIELDS:<discriminator>` | Verbe HTTP standard (`GET`, `POST`, …) — réutilise la permission de la sous-route |
| Permissions à seeder | Nouvelles permissions dédiées | Réutilise les permissions HTTP existantes ou de la sous-route future |
| Trait | `CapabilityGuardTrait` / `CapabilityAuthorizerTrait` | `PermissionAuthorizerTrait` |
| Cas d'usage | « Cet utilisateur peut-il consommer `?skin=offers.full` ? » | « Cet utilisateur peut-il voir le tableau `permissions[]` ? » |

Les deux mécanismes peuvent coexister sur le même contrôleur.

## Stratégies de caching côté consommateur

Le mapping sujet → `(object, action)` est lu par `resolve()` à chaque check de permission. En pratique, un consommateur va vouloir cacher ce mapping pour éviter de relire son stockage à chaque appel.

Recommandations (non prescriptives) :

- **Cache RAM lazy** : charger le map complet au premier appel (`getMap()`), puis servir depuis un tableau interne.
- **Cache distribué** (Memcached / Redis) avec TTL (1 h typique) : utile en multi-process.
- **Invalidation par signaux** : si votre stockage publie des signaux à l'écriture (`afterInsert` / `afterDelete` sur la collection permissions), connectez-y une fonction qui purge le cache du resolver.

La lib n'impose aucune de ces stratégies — votre implémentation de `PermissionSubjectResolverInterface` est libre de les combiner comme elle veut.

## Plus loin

- [Permissions](permissions.md) — la nomenclature `<resource>:<action>` et les enums typés.
- [Capacités](capabilities.md) — le mécanisme complémentaire pour les query params, filtres, actions transversales.
- [Bonnes pratiques](tips.md) — toujours normaliser le sujet Casbin via `casbinSafeSubject()`.
