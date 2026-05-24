# Démarrage rapide

Cette page montre comment installer **`oihana/php-auth`** et obtenir un premier appel qui valide un JWT, puis un premier contrôle Casbin, en moins de 2 minutes.

> 🇬🇧 [English version](../en/getting-started.md)

## 1. Prérequis

- [PHP 8.4+](https://www.php.net/releases/)
- [Composer](https://getcomposer.org/)
- L'extension `ext-memcached` (pour la mise en cache des clés JWKS)
- Un serveur [Memcached](https://memcached.org/) joignable
- L'URL d'un endpoint **JWKS** côté IdP (Zitadel, Auth0, Keycloak, etc.)

## 2. Installation

```bash
composer require oihana/php-auth
```

## 3. Valider un JWT

L'objet [`IdTokenValidator`](../../src/oihana/auth/jwt/IdTokenValidator.php) vérifie la signature, l'émetteur (`iss`) et le sujet (`sub`) d'un JWT. Il utilise [`JwksKeyFetcher`](../../src/oihana/auth/jwt/JwksKeyFetcher.php) pour récupérer et cacher les clés publiques.

```php
use Memcached ;

use oihana\auth\exceptions\IdTokenValidationException ;
use oihana\auth\jwt\IdTokenValidator ;
use oihana\auth\jwt\JwksKeyFetcher ;

$cache = new Memcached() ;
$cache->addServer( '127.0.0.1' , 11211 ) ;

$fetcher = new JwksKeyFetcher
(
    cache   : $cache ,
    jwksUri : 'https://your-idp.example.com/oauth/v2/keys'
) ;

$validator = new IdTokenValidator
(
    fetcher        : $fetcher ,
    expectedIssuer : 'https://your-idp.example.com'
) ;

try
{
    $claims = $validator->validate( $idToken , expectedSub: 'user-123' ) ;
    // $claims est un objet avec les claims décodés du JWT
}
catch ( IdTokenValidationException $e )
{
    // signature invalide, iss ou sub mismatch
    // → renvoyer 401 au client
}
```

Voir aussi [Gestion des erreurs](error-handling.md) pour la liste complète des cas d'échec.

## 4. Contrôler une capacité avec Casbin

L'objet [`CapabilityEnforcer`](../../src/oihana/auth/casbin/CapabilityEnforcer.php) permet de demander à Casbin si un utilisateur a le droit d'utiliser une capacité (par exemple, accéder à un skin enrichi, voir un champ sensible, déclencher une action transversale).

```php
use Casbin\Enforcer ;

use oihana\auth\casbin\CapabilityEnforcer ;
use oihana\auth\enums\CapabilityMode ;

$casbin = new Enforcer
(
    '/path/to/casbin/model.conf' ,
    '/path/to/casbin/policy.csv'
) ;

$enforcer = new CapabilityEnforcer
(
    enforcer : $casbin ,
    domain   : 'my-api'
) ;

$allowed = $enforcer->check
(
    userId     : 'user-123' ,
    object     : '/products' ,
    capability : 'offers.full' ,
    mode       : CapabilityMode::REQUIRE
) ;

if ( ! $allowed )
{
    // 403 — l'utilisateur n'a pas la capacité demandée
}
```

Voir [Capacités](capabilities.md) pour le pattern complet (mode REQUIRE vs DENY, allowlist/denylist, intégration via traits).

## 5. Aller plus loin

| Pour... | Voir |
|---|---|
| Comprendre l'architecture globale | [Architecture](auth.md) |
| Restreindre des paramètres `?skin=…`, `?filter=…` | [Capacités](capabilities.md) |
| Cacher des champs d'une réponse selon le caller | [Restriction au niveau du champ](field-level-gating.md) |
| Définir la nomenclature `resource:action` | [Permissions](permissions.md) |
| Valider des bodies de requête | [Règles de validation](rules.md) |
| Toutes les bonnes pratiques | [Bonnes pratiques](tips.md) |
