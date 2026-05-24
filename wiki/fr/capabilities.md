# Capacités fines

Les **capacités fines** étendent le vocabulaire Casbin (qui gère nativement les verbes HTTP `GET`, `POST`, `PATCH`, …) pour contrôler l'accès à des éléments **à l'intérieur** d'une route :

- la valeur d'un query param (`?skin=offers.full`, `?export=true`),
- une clé de filtre sensible (`?filter=[{"key":"costPrice",…}]`),
- un champ écrit dans un body PATCH ou POST (`PATCH /users/{id} { status: "disabled" }`),
- une action transversale (drapeau métier, mode debug, …).

Tout cela sans toucher au moteur Casbin ni au schéma de stockage des permissions.

> 🇬🇧 [English version](../en/capabilities.md)

## Pourquoi des capacités ?

Sans ce mécanisme, on n'a qu'une seule granularité : *l'accès à la route*. Tout utilisateur qui a `GET /products` peut consommer n'importe quel `?skin=…`, n'importe quel filtre, n'importe quel export. Les capacités permettent de réserver certaines valeurs à certains rôles, sans dupliquer les routes.

## Vocabulaire

| Terme | Sens |
|---|---|
| **Capacité (capability)** | Un droit ciblé sur un fragment d'une route (valeur de param, clé de filtre, action transverse, champ de body). |
| **Mode** | Sémantique du check Casbin : `REQUIRE` (fermé par défaut, allowlist) ou `DENY` (ouvert par défaut, denylist). |
| **Policy** | Réaction quand le check échoue : `SILENT_DOWNGRADE` (remplace la valeur par un fallback) ou `STRICT` (403 Forbidden). |
| **Object** | Le scope de route partagé par toutes les capacités d'un contrôleur (ex: `/products`). |
| **Discriminator** | Suffixe du `subject` / `action` qui distingue deux capacités sur la même route (`skin.offers.full` vs `export`). |

## Trois familles d'actions Casbin

L'enum [`CapabilityAction`](../../src/oihana/auth/enums/CapabilityAction.php) liste les préfixes :

| Préfixe | Constante | Usage |
|---|---|---|
| `PARAM:` | `CapabilityAction::PARAM` | Valeur d'un query param, clé de filtre, action transverse. Évalué dans les hooks `prepareSkin` / `prepareFilter` / `prepareSearch`. |
| `FIELDS:` | `CapabilityAction::FIELDS` | Champ écrit dans le body d'un PATCH/POST/PUT. Évalué dans `preparePayload()` avant la validation. |
| `FEATURE:` | `CapabilityAction::FEATURE` | Drapeau métier ou mode transverse non lié à un param HTTP. |

Exemple de permissions Casbin correspondantes :

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

## Les deux modes

L'enum [`CapabilityMode`](../../src/oihana/auth/enums/CapabilityMode.php) :

| Mode | Sémantique |
|---|---|
| `REQUIRE` | **Allowlist** — le caller doit posséder la permission, sinon refus. |
| `DENY` | **Denylist** — le caller passe par défaut, sauf si une permission `effect=deny` lui est explicitement attachée. |

### Quand utiliser `REQUIRE`

C'est le mode normal pour une capacité **sensible** dont l'accès doit être explicitement accordé. Exemples : `?skin=offers.full` (données financières), `?export=true` (export client lourd), `PARAM:bypass.level.hierarchy` (override d'une règle métier).

### Quand utiliser `DENY`

Pour une capacité **ouverte par défaut** dont on veut pouvoir bloquer ponctuellement un sous-ensemble d'utilisateurs (denylist). Exemple : `?skin=special` accessible à tous sauf aux comptes guest qui ont un `deny` explicite.

### Évaluation côté Casbin

| Mode | Logique côté `CapabilityEnforcer` |
|---|---|
| `REQUIRE` | `has()` → `enforce()` natif Casbin |
| `DENY` | `! isDenied()` → cherche un tuple `effect=deny` explicite |

## Les deux policies

L'enum [`CapabilityPolicy`](../../src/oihana/auth/enums/CapabilityPolicy.php) :

| Policy | Effet quand le check échoue |
|---|---|
| `SILENT_DOWNGRADE` (défaut) | Remplace la valeur refusée par un fallback (`Capability::FALLBACK` ou `Capability::FALLBACKS`). L'utilisateur ne voit pas de 403 — il reçoit la réponse dégradée. |
| `STRICT` | Renvoie `403 Forbidden`. L'utilisateur sait qu'il a tenté quelque chose d'interdit. |

### Quand utiliser `SILENT_DOWNGRADE`

UX-friendly : pour les capacités où une valeur de fallback existe naturellement. Typiquement `?skin=offers.full` → fallback `?skin=offers` ou `default`. L'utilisateur sans la perm consomme la version dégradée sans s'en apercevoir.

### Quand utiliser `STRICT`

Pour les capacités où il n'y a pas de fallback raisonnable, ou pour les actions à effet de bord. Typiquement `PARAM:bypass.level.hierarchy` sur un `PATCH /users/{id}` : pas de demi-mesure, soit on autorise soit on refuse.

## Déclarer une capacité — bloc `Capability::*`

L'enum [`Capability`](../../src/oihana/auth/enums/Capability.php) liste les clés à utiliser dans le bloc de déclaration :

| Clé | Constante | Rôle |
|---|---|---|
| `object` | `Capability::OBJECT` | Le scope de route (ex: `/products`). |
| `subject` | `Capability::SUBJECT` | Le sujet Casbin de la capacité (ex: `products:skin.offers.full`). |
| `mode` | `Capability::REQUIRE` ou `Capability::DENY` | Le mode d'évaluation. |
| `policy` | `Capability::POLICY` | `SILENT_DOWNGRADE` ou `STRICT`. |
| `fallback` | `Capability::FALLBACK` | Valeur de remplacement quand le check échoue (mode silent). |
| `fallbacks` | `Capability::FALLBACKS` | Cascade ordonnée de fallbacks à essayer dans l'ordre. |
| `keys` | `Capability::KEYS` | Liste des clés de filtre / champs concernés (pour filter-keys et FIELDS). |
| `values` | `Capability::VALUES` | Liste des valeurs à protéger (pour PARAM scalaire). |
| `fields` | `Capability::FIELDS` | Configuration spécifique aux capacités FIELDS. |

### Exemple : restreindre `?skin=offers.full`

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

Lecture : « sur `/products`, la valeur `?skin=offers.full` exige la permission `products:skin.offers.full` ; sinon, on remplace silencieusement par `?skin=offers` ».

### Exemple : cascade multi-paliers

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

Le caller demande `offers.full` → check → refusé → essaye `offers` (qui peut avoir sa propre perm) → si encore refusé → `default`. Permet une dégradation gracieuse.

### Exemple : champ sensible dans un PATCH (FIELDS)

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

Lecture : « si le body du PATCH contient le champ `status`, le caller doit posséder la permission `users:status.update`, sinon 403 ».

## Traits exposés

La bibliothèque propose plusieurs traits prêts à l'emploi à inclure dans un contrôleur HTTP. Chacun a un périmètre précis :

| Trait | Périmètre |
|---|---|
| [`CapabilityGuardTrait`](../../src/oihana/auth/controllers/traits/CapabilityGuardTrait.php) | Trait de base : initialise l'enforcer et expose `enforceCapability($subject, $mode)`. |
| [`CapabilityAuthorizerTrait`](../../src/oihana/auth/controllers/traits/CapabilityAuthorizerTrait.php) | Construit une `Closure(string): bool` à injecter dans la couche modèle pour des checks dynamiques (équivalent capability du `PermissionAuthorizerTrait` côté permission). |
| [`CapabilityParamTrait`](../../src/oihana/auth/controllers/traits/CapabilityParamTrait.php) | Spécialisé pour les query params scalaires (ex: `?skin=…`). Gère REQUIRE/DENY + downgrade. |
| [`CapabilityFilterKeysTrait`](../../src/oihana/auth/controllers/traits/CapabilityFilterKeysTrait.php) | Spécialisé pour les clés de filtre `?filter=[{key:…}]`. Filtre les clés interdites. |
| [`CapabilityFieldsTrait`](../../src/oihana/auth/controllers/traits/CapabilityFieldsTrait.php) | Spécialisé pour les champs de body en écriture (FIELDS). Lance 403 ou retire le champ. |
| [`CapabilityBinaryTrait`](../../src/oihana/auth/controllers/traits/CapabilityBinaryTrait.php) | Spécialisé pour les actions binaires (drapeau présent / absent — pas de valeur). |
| [`CapabilityContextTrait`](../../src/oihana/auth/controllers/traits/CapabilityContextTrait.php) | Construit un contexte de capacités passé à la couche modèle (skin courant, filter keys validées, etc.). |
| [`DocumentsControllerCapabilitiesTrait`](../../src/oihana/auth/controllers/traits/DocumentsControllerCapabilitiesTrait.php) | Trait composite intégrant tous les autres — pour un contrôleur CRUD qui veut tout activer. |

## Pipeline d'enforcement (vue conceptuelle)

```text
HTTP request
    ↓
Authorized middleware  ──► l'utilisateur a la perm HTTP, requête laissée passer
    ↓
Controller hook prepareSkin / prepareFilter / prepareSearch / preparePayload
    ↓
CapabilityXxxTrait     ──► pour chaque param/filter/field :
                            - lookup la déclaration dans le bloc Capability::*
                            - appel CapabilityEnforcer::check($userId, $object, $cap, $mode)
                            - si refus :
                                · policy SILENT_DOWNGRADE → remplace par fallback
                                · policy STRICT           → throw 403
    ↓
Controller business logic
    ↓
Response
```

## Bonnes pratiques

1. **Toujours typer les valeurs** via les enums (`CapabilityAction::PARAM`, `CapabilityMode::REQUIRE`, `Capability::SUBJECT`), jamais de string magique.
2. **Préférer `SILENT_DOWNGRADE`** quand un fallback raisonnable existe (UX cohérente).
3. **Préférer `STRICT`** pour les actions à effet de bord (mutation, override).
4. **Normaliser les sujets Casbin** avec `casbinSafeSubject()` — voir [Bonnes pratiques](tips.md).
5. **Documenter chaque nouvelle capacité** dans le seed de permissions de l'application (la lib ne prescrit pas le format de seed).

## Différence avec field-level gating

Les capacités gating sont **complémentaires** au field-level gating :

| Aspect | Capacités (ici) | Field-level gating (voir [page dédiée](field-level-gating.md)) |
|---|---|---|
| Granularité | Valeur de param, clé de filtre, champ écrit | Champ projeté en GET |
| Quand | Avant la couche modèle (prepareXxx) | Pendant la projection AQL/ORM |
| Effet | Downgrade silencieux ou 403 | Clé absente de la réponse |
| Action Casbin | `PARAM:` / `FIELDS:` / `FEATURE:` | Verbe HTTP standard (`GET`) |

Les deux mécanismes peuvent coexister sur le même contrôleur.

## Pour aller plus loin

- [Restriction au niveau du champ](field-level-gating.md) — gating de la projection en GET.
- [Permissions](permissions.md) — nomenclature et enums typés.
- [Architecture](auth.md) — vue d'ensemble.
- [Bonnes pratiques](tips.md) — `casbinSafeSubject` obligatoire.
