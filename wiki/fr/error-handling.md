# Gestion des erreurs

Cette page liste les exceptions levées par la bibliothèque et la façon recommandée de les rattraper.

> 🇬🇧 [English version](../en/error-handling.md)

## Vue d'ensemble

| Exception | Origine | Recovery |
|---|---|---|
| [`IdTokenValidationException`](../../src/oihana/auth/exceptions/IdTokenValidationException.php) | Lib `oihana/php-auth` | Renvoyer un **401 Unauthorized** |
| [`Casbin\Exceptions\CasbinException`](https://github.com/php-casbin/php-casbin) | Lib externe `casbin/casbin` | Renvoyer un **500 Internal Server Error** (fail-closed) |

## IdTokenValidationException

Levée par [`IdTokenValidator::validate()`](../../src/oihana/auth/jwt/IdTokenValidator.php) dans 4 cas :

| Cas | Message |
|---|---|
| Signature invalide ou JWT mal formé | `id_token signature or format invalid` |
| `iss` ne correspond pas à `expectedIssuer` | `id_token issuer mismatch: expected …, got …` |
| `sub` manquant ou différent de `expectedSub` | `id_token sub does not match the access token sub` |
| JWT expiré (claim `exp`) | délégué à `firebase/php-jwt` — laisse remonter une `ExpiredException` |

### Pattern de rattrapage

```php
use Firebase\JWT\ExpiredException ;

use oihana\auth\exceptions\IdTokenValidationException ;

try
{
    $claims = $validator->validate( $idToken , expectedSub: $userId ) ;
}
catch ( ExpiredException $e )
{
    // Token expiré — renvoyer 401 avec reason: token_expired
}
catch ( IdTokenValidationException $e )
{
    // Signature ou claims invalides — renvoyer 401 avec reason: invalid_token
}
```

## CasbinException

Levée par les méthodes [`CapabilityEnforcer`](../../src/oihana/auth/casbin/CapabilityEnforcer.php) quand l'enforcer Casbin sous-jacent rencontre un problème (politique mal formée, adaptateur indisponible, etc.).

**Doctrine recommandée : fail-closed** — toute `CasbinException` doit faire échouer la vérification (= refus d'accès), pas la laisser passer.

```php
use Casbin\Exceptions\CasbinException ;

try
{
    $allowed = $enforcer->check( $userId , $object , $capability , $mode ) ;
}
catch ( CasbinException $e )
{
    // Loguer pour investigation
    $logger->error( 'Casbin enforce failed' , [ 'exception' => $e ] ) ;

    // Fail-closed : on refuse
    $allowed = false ;
}
```

Le trait [`PermissionAuthorizerTrait`](../../src/oihana/auth/controllers/traits/PermissionAuthorizerTrait.php) applique déjà ce pattern : la closure retournée intercepte `CasbinException` et renvoie `false`.

## Échec silencieux du fetch JWKS

Par design, [`JwksKeyFetcher::getKeys()`](../../src/oihana/auth/jwt/JwksKeyFetcher.php) **ne lève pas d'exception** quand le cache est vide et que le fetch HTTP échoue : il retourne un tableau vide `[]`.

C'est volontaire : on ne veut pas casser la couche d'authentification à cause d'un hoquet réseau ponctuel. Mais sans clés, la validation JWT échouera ensuite avec `IdTokenValidationException` (signature invalide).

Le rate-limit interne (`REFRESH_COOLDOWN = 60 s`) empêche les refresh trop rapprochés.

## Helpers JWT — pas d'exception

Les helpers fonctionnels du namespace `oihana\auth\jwt\helpers` retournent `null` en cas de problème, ne lèvent jamais d'exception :

| Helper | Retour en cas d'échec |
|---|---|
| `decodeJwtClaims( string $token )` | `null` (JWT mal formé) |
| `extractFromClaims( ?array $claims , string $key )` | `null` (claim manquant) |
| `extractSidFromClaims( ?array $claims )` | `null` (sid absent) |

Donc on chaîne sans try/catch :

```php
use function oihana\auth\jwt\helpers\decodeJwtClaims ;
use function oihana\auth\jwt\helpers\extractFromClaims ;

$claims = decodeJwtClaims( $accessToken ) ;
$sub    = extractFromClaims( $claims , 'sub' ) ;

if ( $sub === null )
{
    // claim manquant — décision applicative
}
```
