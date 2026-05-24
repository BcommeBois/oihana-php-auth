# Bonnes pratiques & pièges

Catalogue des règles d'or à respecter quand on touche au code qui interagit avec Casbin via cette bibliothèque.

> 🇬🇧 [English version](../en/tips.md)

## Sommaire

- [Toujours normaliser un sujet Casbin via `casbinSafeSubject()`](#toujours-normaliser-un-sujet-casbin-via-casbinsafesubject)
- [Aligner le nom du placeholder de route avec le `:name` de la permission Casbin](#aligner-le-nom-du-placeholder-de-route-avec-le-name-de-la-permission-casbin)

---

## Toujours normaliser un sujet Casbin via `casbinSafeSubject()`

**Règle.** Tout identifiant utilisateur, service ou rôle qui transite vers le `Casbin\Enforcer` (lecture **comme** écriture) doit passer par le helper `oihana\auth\helpers\casbinSafeSubject()` au plus près de l'appel.

### Pourquoi

Beaucoup d'IdP OIDC (Zitadel, Auth0, etc.) émettent des `sub` purement numériques (par exemple `364646423545321675`). Quand Casbin stocke en interne un sujet purement numérique dans un `array<string, …>`, PHP coerce silencieusement la clé en `int` — voir [`DefaultRoleManager\Role::$roles`](https://github.com/php-casbin/php-casbin).

Au moment de la lecture, le `getRoles()` interne reçoit un `int` là où il attend un `string`, le matcher déraille (clé introuvable, retour vide, ou fatal `TypeError`).

[`casbinSafeSubject()`](../../src/oihana/auth/helpers/casbinSafeSubject.php) préfixe les chaînes purement numériques par `n_` :

```php
'364646423545321675' → 'n_364646423545321675'
'role_73478334'      → 'role_73478334'   (déjà préfixé, no-op)
'alice'              → 'alice'           (no-op)
```

La normalisation est **symétrique** : tout sujet écrit par une voie doit être relu par la même voie. Si on écrit `n_…` et qu'on lit `…` brut, Casbin renvoie `[]` sans erreur — c'est un bug silencieux.

### Où l'appliquer

| Direction | Méthodes Casbin concernées |
|---|---|
| Écriture | `addPolicy`, `removePolicy`, `addGroupingPolicy`, `removeGroupingPolicy`, `deleteRole` |
| Lecture | `enforce`, `getImplicitPermissionsForUser`, `getImplicitRolesForUser`, `getRolesForUserInDomain`, `getPermissionsForUserInDomain`, `hasRoleForUser` |

### Pattern à utiliser

```php
use function oihana\auth\helpers\casbinSafeSubject ;

$subject = casbinSafeSubject( (string) $userId ) ;

$allowed = $this->enforcer->enforce( $subject , $domain , $object , $action ) ;
```

### Symptômes d'un oubli

- Une route protégée fonctionne, mais un contrôle de capacité échoue silencieusement → fallback inattendu.
- Une endpoint qui liste les permissions effectives montre la permission attendue, mais `enforce()` la refuse pour le même utilisateur sur la même route.
- Un test unitaire passe (les fixtures utilisent `'alice'` / `'bob'`) mais la régression apparaît uniquement en live avec des sujets numériques.

### Tests recommandés

Dès qu'un nouveau code appelle l'`Enforcer`, ajouter au moins un cas avec un sujet purement numérique (par exemple `'1234567890'`) en plus des fixtures alphabétiques. La compatibilité avec les sujets `'alice'` n'a aucune valeur si elle masque la régression sur les vrais identifiants IdP.

---

## Aligner le nom du placeholder de route avec le `:name` de la permission Casbin

**Règle.** Quand on canonise un chemin HTTP en pattern Casbin, le nom du placeholder dans le path (`{xxx}`) doit être **identique** au nom utilisé dans la permission seed (`:xxx`). Sinon, le pattern produit ne matche pas la permission stockée, et l'accès est refusé silencieusement avec un 403 — même pour un administrateur.

### Pourquoi

La canonisation d'un path en pattern Casbin remplace chaque segment matchant un argument de route par `:argName`. Le nom du placeholder est lu **tel quel** depuis le pattern de route — il n'y a aucun renommage implicite vers `:id`.

Exemple :

```text
// Path déclaré : '/logs/{file}'
// Requête : GET /logs/my-app-2026-05-18.log
// Args : ['file' => 'my-app-2026-05-18.log']
// Canonisation : '/logs/:file'

// Permission seed :
// object = "/logs/:id"
// → mismatch silencieux → 403 Forbidden
```

### Convention recommandée

Utiliser **`{id}`** par défaut, ce qui produit la canonisation `:id` matchée par les permissions seed `/foo/:id`. Les rares cas où un autre nom est légitime (par exemple `{activityId}`, `{targetId}` quand deux placeholders coexistent dans le même path) doivent être documentés et leur permission seed doit utiliser le **même nom** côté `:`.

### Symptômes

- Une route protégée renvoie 403 alors que l'utilisateur a bien la permission listée.
- Le test E2E passe en environnement sans Casbin (auth désactivée) mais échoue dès qu'on active l'autorisation.
- L'ajout d'une nouvelle route avec placeholder fonctionne pour `GET /foo` (collection) mais pas pour `GET /foo/{quelque-chose}` (singleton).

### Tests recommandés

Quand on ajoute une route avec placeholder :

1. Vérifier que le nom du placeholder correspond exactement au nom dans la permission seed.
2. Vérifier que la route répond 200 (et pas 403) pour un admin sur un sujet réel.

À terme, un test automatique peut canoniser toutes les routes du registre et vérifier que chaque pattern produit existe bien dans les seeds.
