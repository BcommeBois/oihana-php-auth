# Architecture — Authentification & Autorisation

> **Définition.** L'**authentification** répond à la question *« qui es-tu ? »*. L'**autorisation** répond à *« qu'as-tu le droit de faire ? »*. La bibliothèque `oihana/php-auth` adresse les deux, en restant agnostique sur le fournisseur d'identité et sur le stockage des permissions.

Cette page donne la vue d'ensemble. Chaque sous-mécanisme a sa propre page de référence (liens en fin).

> 🇬🇧 [English version](../en/auth.md)

## Vue d'ensemble

```text
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  Authentification                       Autorisation             │
│  ─────────────────                      ────────────             │
│                                                                  │
│  ┌──────────────────┐                  ┌──────────────────┐      │
│  │ IdP OIDC         │                  │ Politique RBAC   │      │
│  │ (Zitadel, Auth0, │                  │ (rôles, perms,   │      │
│  │  Keycloak, …)    │                  │  policies)       │      │
│  └────────┬─────────┘                  └────────┬─────────┘      │
│           │                                     │                │
│           │ JWT (id_token)                      │ (object,action)│
│           │                                     │                │
│           ▼                                     ▼                │
│  ┌──────────────────┐                  ┌──────────────────┐      │
│  │ JwksKeyFetcher   │                  │ Casbin\Enforcer  │      │
│  │ + IdTokenValidator                  │ + CapabilityEnforcer    │
│  └────────┬─────────┘                  └────────┬─────────┘      │
│           │                                     │                │
│           │ claims décodés (sub, iss, …)        │ verdict allow/deny
│           │                                     │                │
│           └─────────────────┬───────────────────┘                │
│                             │                                    │
│                             ▼                                    │
│                  ┌──────────────────────┐                        │
│                  │ Middleware HTTP /    │                        │
│                  │ contrôleur applicatif│                        │
│                  └──────────────────────┘                        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

L'authentification consomme un JWT signé émis par un IdP OIDC. La signature est vérifiée contre les clés publiques (JWKS) de l'IdP, cachées via Memcached. Les claims décodés (en particulier `sub`) identifient l'utilisateur.

L'autorisation s'appuie sur [Casbin](https://casbin.org/) : un moteur de politiques RBAC + domaines qui stocke des tuples `(subject, object, action, effect)` et répond à la question « est-ce que ce sujet a le droit de faire cette action sur cet objet ? ».

## Authentification — couche JWT / JWKS

La bibliothèque expose deux classes :

| Classe | Rôle |
|---|---|
| [`JwksKeyFetcher`](../../src/oihana/auth/jwt/JwksKeyFetcher.php) | Récupère les clés publiques JWKS depuis un endpoint OIDC. Cache via Memcached avec TTL configurable + rate-limit anti-flood. Fail-soft : retourne `[]` si le fetch échoue. |
| [`IdTokenValidator`](../../src/oihana/auth/jwt/IdTokenValidator.php) | Valide la signature + l'émetteur (`iss`) + le sujet (`sub`) d'un JWT en utilisant `JwksKeyFetcher`. Lance `IdTokenValidationException` en cas d'échec. |

### Helpers JWT

Trois helpers fonctionnels (autoload `files`) sont disponibles pour des cas de plus bas niveau :

| Helper | Rôle |
|---|---|
| `decodeJwtClaims(string $token)` | Décode un JWT **sans** vérifier la signature (utile en debug / parsing rapide). Retourne `null` si malformé. |
| `extractFromClaims(?array $claims, string $key)` | Extrait un claim par sa clé. Retourne `null` si absent. |
| `extractSidFromClaims(?array $claims)` | Extrait spécifiquement le claim `sid` (session ID). |

> ⚠️ `decodeJwtClaims()` ne vérifie pas la signature — à n'utiliser que pour des claims non-sensibles. Pour authentifier un appel, toujours passer par `IdTokenValidator`.

### Détail des cas d'erreur

Voir [Gestion des erreurs](error-handling.md).

## Autorisation — couche Casbin

La bibliothèque expose un wrapper de haut niveau au-dessus de `Casbin\Enforcer` :

| Classe / Interface | Rôle |
|---|---|
| [`CapabilityEnforcerInterface`](../../src/oihana/auth/CapabilityEnforcerInterface.php) | Contrat exposant `check`, `has`, `isDenied`, `enforceObjectAction`. |
| [`CapabilityEnforcer`](../../src/oihana/auth/casbin/CapabilityEnforcer.php) | Implémentation par défaut sur Casbin. Mode-aware (`REQUIRE` / `DENY`), gère les actions préfixées (`PARAM:*`). |
| [`EnforcerTrait`](../../src/oihana/auth/casbin/traits/EnforcerTrait.php) | Trait à inclure dans une classe pour exposer `$enforcer` + helpers de configuration. |

Le `CapabilityEnforcer` reçoit le `Casbin\Enforcer` natif en constructeur et le domaine de l'API. Toutes les vérifications normalisent automatiquement le sujet via [`casbinSafeSubject()`](../../src/oihana/auth/helpers/casbinSafeSubject.php) pour éviter le bug de coercion `string → int` (voir [Bonnes pratiques](tips.md)).

## Capacités fines

Au-delà des verbes HTTP standard, la bibliothèque propose le pattern **capacités fines** (`PARAM:*`) pour restreindre des valeurs de paramètres, des clés de filtre ou des actions transversales **à l'intérieur** d'une route déjà protégée.

Voir [Capacités](capabilities.md) pour le pattern complet.

## Field-level gating

Quand une route renvoie plusieurs champs dont certains sont sensibles, la bibliothèque permet de **gater chaque champ individuellement** : un champ est inclus dans la réponse seulement si l'utilisateur a la permission qui le couvre. Sinon, la clé n'apparaît pas du tout dans le JSON.

Voir [Restriction au niveau du champ](field-level-gating.md).

## Règles de validation

Pour les payloads de création/édition, la bibliothèque fournit un point d'entrée vers [Somnambulist Validation](https://github.com/somnambulist-tech/validation) et expose ses propres classes `Rule` (actuellement `RoleNameRule`).

Voir [Règles de validation](rules.md).

## Comment ça s'assemble dans un middleware HTTP

Voici la trame conceptuelle d'un middleware d'authentification + autorisation typique. La bibliothèque ne ship pas le middleware lui-même (il dépend de votre framework), mais elle ship toutes les briques nécessaires.

```php
namespace App\Middleware ;

use Psr\Http\Message\ServerRequestInterface as Request ;
use Psr\Http\Server\MiddlewareInterface ;
use Psr\Http\Server\RequestHandlerInterface ;

use oihana\auth\casbin\CapabilityEnforcer ;
use oihana\auth\jwt\IdTokenValidator ;
use oihana\auth\exceptions\IdTokenValidationException ;
use oihana\enums\http\RequestAttribute ;

use function oihana\auth\jwt\helpers\decodeJwtClaims ;
use function oihana\auth\jwt\helpers\extractFromClaims ;

final class AuthMiddleware implements MiddlewareInterface
{
    public function __construct
    (
        private IdTokenValidator    $validator ,
        private CapabilityEnforcer  $enforcer
    ) {}

    public function process( Request $request , RequestHandlerInterface $handler ) : ResponseInterface
    {
        // 1. Extraire le JWT du header Authorization
        $token = $this->extractBearerToken( $request ) ;

        // 2. Décoder rapidement pour récupérer le sub (sans vérif sig)
        $claims = decodeJwtClaims( $token ) ;
        $sub    = extractFromClaims( $claims , 'sub' ) ;

        // 3. Valider la signature + iss + sub
        try
        {
            $this->validator->validate( $token , expectedSub: $sub ) ;
        }
        catch ( IdTokenValidationException $e )
        {
            return $this->unauthorized( $e->getMessage() ) ;
        }

        // 4. Vérifier la permission Casbin sur (object, action) = (path, verb)
        $allowed = $this->enforcer->enforceObjectAction
        (
            userId : $sub ,
            object : $request->getUri()->getPath() ,
            action : $request->getMethod()
        ) ;

        if ( ! $allowed )
        {
            return $this->forbidden() ;
        }

        // 5. Stocker l'identifiant utilisateur sur la requête pour les contrôleurs
        $request = $request->withAttribute( RequestAttribute::USER_ID , $sub ) ;

        return $handler->handle( $request ) ;
    }

    // ... helpers extractBearerToken / unauthorized / forbidden
}
```

Le contrat avec les contrôleurs : ils consomment l'attribut `RequestAttribute::USER_ID` pour savoir qui appelle, et utilisent [`PermissionAuthorizerTrait`](../../src/oihana/auth/controllers/traits/PermissionAuthorizerTrait.php) ou les `Capability*Trait` pour les contrôles fins.

## Modèle de sécurité

| Pièce | Responsabilité | Fail-mode |
|---|---|---|
| JWKS fetch | Récupérer les clés publiques | **Fail-soft** — retourne `[]`, validation JWT échouera ensuite proprement |
| Validation JWT | Signature + iss + sub | **Fail-loud** — `IdTokenValidationException` |
| Enforce Casbin | Politique d'accès | **Fail-closed recommandé** — `CasbinException` → refus d'accès |
| Field-level gating | Projection sélective | **Fail-closed silencieux** — clé absente, jamais d'erreur 500 |

## Dépendances externes

| Lib | Rôle |
|---|---|
| `casbin/casbin` | Moteur RBAC + domaines |
| `firebase/php-jwt` (≥ 7.0) | Décodage et vérification de signature JWT |
| `guzzlehttp/guzzle` | Fetch HTTP des JWKS |
| `somnambulist/validation` | Moteur de règles de validation |
| `oihana/php-system` | Traits `prepare/*` (Filter, Search, Skin) consommés par les contrôleurs |
| Extension PHP `ext-memcached` | Cache des clés JWKS et du mapping sujets → `(object, action)` |

## Pour aller plus loin

- [Démarrage rapide](getting-started.md) — installer et valider un premier JWT.
- [Capacités](capabilities.md) — restreindre des paramètres / filtres / actions transversales.
- [Permissions](permissions.md) — nomenclature et enums typés.
- [Restriction au niveau du champ](field-level-gating.md) — couper des champs sensibles d'une réponse.
- [Règles de validation](rules.md) — payloads et `body.errors`.
- [Gestion des erreurs](error-handling.md) — catalogue des exceptions.
- [Bonnes pratiques](tips.md) — anti-patterns à éviter.
