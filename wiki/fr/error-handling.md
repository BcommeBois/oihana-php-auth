# Gestion des erreurs

Cette page liste les exceptions levées par la bibliothèque et la façon recommandée de les rattraper.

> 🇬🇧 [English version](../en/error-handling.md)

## Vue d'ensemble

| Exception | Origine | Recovery |
|---|---|---|
| [`IdTokenValidationException`](../../src/oihana/auth/exceptions/IdTokenValidationException.php) | Lib `oihana/php-auth` | Renvoyer un **401 Unauthorized** |
| [`IdTokenUnverifiableException`](../../src/oihana/auth/exceptions/IdTokenUnverifiableException.php) | Lib `oihana/php-auth` — étend la précédente | Renvoyer un **503 Service Unavailable** : le token n'a pas pu être vérifié |
| [`Casbin\Exceptions\CasbinException`](https://github.com/php-casbin/php-casbin) | Lib externe `casbin/casbin` | Renvoyer un **500 Internal Server Error** (fail-closed) |

## IdTokenValidationException

Levée par [`IdTokenValidator::validate()`](../../src/oihana/auth/jwt/IdTokenValidator.php) quand le token a été **vérifié et refusé** :

| Cas | Message |
|---|---|
| Signature invalide, JWT mal formé, ou JWT expiré (claim `exp`) | `id_token signature or format invalid` |
| `iss` ne correspond pas à `expectedIssuer` | `id_token issuer mismatch: expected …, got …` |
| `sub` manquant ou différent de `expectedSub` | `id_token sub does not match the access token sub` |

Un token expiré ne laisse pas remonter l'`ExpiredException` de `firebase/php-jwt` : le validateur l'attrape, et le token sort comme les autres refus.

## IdTokenUnverifiableException

Levée par [`IdTokenValidator::validate()`](../../src/oihana/auth/jwt/IdTokenValidator.php) quand le token **n'a pas pu être vérifié** : les clés de signature ne sont ni en cache ni joignables. On ne sait rien du token — il est peut-être parfaitement bon.

| Cas | Message |
|---|---|
| `JwksKeyFetcher` ne sert aucune clé (`[]`), ou la lecture des clés lève | `id_token could not be verified: the signing keys are out of reach` |
| Rotation des clés : les clés en cache ne vérifient pas le token, et les nouvelles ne peuvent pas être lues | idem |

🚨 **Ce n'est pas un token invalide.** Le répondre comme tel dit à l'appelant que son token est faux alors que le fournisseur d'identité est seulement hors de portée. Une application y répond par un `503`, et garde la session.

🔑 **Elle étend `IdTokenValidationException`, exprès.** Le code écrit avant elle attrape la parente et se comporte comme avant ; distinguer les deux est un choix, en attrapant celle-ci **en premier**.

### Pattern de rattrapage

```php
use oihana\auth\exceptions\IdTokenUnverifiableException ;
use oihana\auth\exceptions\IdTokenValidationException ;

try
{
    $claims = $validator->validate( $idToken , expectedSub: $userId ) ;
}
catch ( IdTokenUnverifiableException $e )
{
    // Les clés sont hors de portée — renvoyer 503, garder la session, réessayer plus tard
}
catch ( IdTokenValidationException $e )
{
    // Signature, expiration ou claims refusés — renvoyer 401
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

Par design, [`JwksKeyFetcher`](../../src/oihana/auth/jwt/JwksKeyFetcher.php) **ne lève pas d'exception** quand l'endpoint ne répond pas : `getKeys()` et `refreshKeys()` retournent un tableau vide `[]`.

C'est volontaire : on ne veut pas casser la couche d'authentification à cause d'un hoquet réseau ponctuel. Mais sans clés, la validation JWT échouera ensuite avec `IdTokenValidationException` (signature invalide).

🚨 **`[]` veut dire « aucune clé n'a pu être servie », jamais « ce token est refusé ».** Une application qui décode elle-même avec ces clés doit lire `[]` comme « la signature n'a pas pu être vérifiée » — un service indisponible, pas une session terminée.

Ce que retournent les deux méthodes :

| Situation | `getKeys()` | `refreshKeys()` |
|---|---|---|
| Clés en cache | les clés, sans appel | selon les lignes suivantes |
| Un refresh a réussi il y a moins de `REFRESH_COOLDOWN` (60 s) | — | les clés en cache, sans appel |
| L'endpoint répond | les clés, mises en cache | les nouvelles clés, qui **remplacent** celles du cache |
| L'endpoint ne répond pas | `[]` | `[]` — **les clés en cache restent en place** pour les autres requêtes |
| L'endpoint répond autre chose qu'un jeu de clés (page d'erreur d'un relais, document tronqué, jeu vide) | `[]`, **rien n'est mis en cache** | `[]` — les clés en cache restent en place |
| L'entrée du cache ne s'analyse plus | elle est supprimée, puis l'endpoint est appelé | selon les lignes ci-dessus |
| Un appel a échoué il y a moins de `FAILURE_TTL` (5 s) | `[]` si rien n'est en cache, sans appel | `[]`, sans appel |

Trois entrées vivent dans le cache : `jwks:keys` (les clés), `jwks:refreshed` (un refresh vient de réussir) et `jwks:unavailable` (le dernier appel a échoué). Les deux marqueurs sont **dans le cache, pas dans l'objet** : sous un runtime qui crée un processus par requête, une limite gardée dans une propriété repartirait de zéro à chaque requête.

- **Ce qui est mis en cache est ce qui a été lu.** La réponse de l'endpoint est analysée avant d'être gardée : mise en cache telle quelle, une réponse illisible ferait échouer toutes les vérifications pendant `CACHE_TTL`, bien après que l'endpoint s'est remis à répondre.
- **Un refresh ne supprime jamais les clés avant d'avoir les nouvelles.** Un token à la signature fausse ne peut donc pas vider le cache pendant que l'endpoint est injoignable.
- **Le cooldown n'est tenu que par un refresh réussi.** Un refresh raté ne bloque pas le suivant pendant une minute ; c'est `FAILURE_TTL` qui borne les échecs répétés.
- **Les durées se lisent par `static::`** : une sous-classe qui redéfinit `FAILURE_TTL`, `REFRESH_COOLDOWN` ou `CACHE_TTL` change le comportement sans réécrire de méthode.

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
