# Documentation Oihana PHP Auth — Français

Bienvenue dans la documentation de la bibliothèque **`oihana/php-auth`**.

Cette bibliothèque fournit une boîte à outils PHP composable pour protéger des API :

- vérification de jetons JWT via JWKS (clés publiques distantes mises en cache),
- contrôle d'accès basé sur les rôles (RBAC) avec [Casbin](https://casbin.org/),
- capacités fines (`PARAM:…`, `FIELDS:…`) pour restreindre des paramètres de requête ou des champs renvoyés,
- règles de validation prêtes à l'emploi (`oihana\auth\rules`),
- traits PSR-15 prêts à brancher sur n'importe quelle stack Slim/Symfony.

> 🇬🇧 English version available under [`../en/`](../en/README.md).

## 📘 Sommaire

| Page | Contenu |
|---|---|
| [Démarrage rapide](getting-started.md) | Installer la lib, valider un premier JWT, brancher un premier enforcer en moins de 2 minutes. |
| [Architecture](auth.md) | Vue d'ensemble : JWT + JWKS + Casbin + capacités + règles. |
| [Capacités](capabilities.md) | Pattern `Capability` : restreindre des paramètres, des champs, des actions transversales. |
| [Permissions](permissions.md) | Nomenclature `resource:action`, conventions de nommage, enums typés. |
| [Restriction au niveau du champ](field-level-gating.md) | Couper certains champs d'une réponse selon les capacités du caller. |
| [Règles de validation](rules.md) | Catalogue de règles, structure `RULES` / `CUSTOM_RULES`, format des erreurs `body.errors`. |
| [Gestion des erreurs](error-handling.md) | Catalogue des exceptions levées par la lib, comment les rattraper. |
| [Bonnes pratiques](tips.md) | Constantes typées, conventions, anti-patterns. |

## 🔗 Liens externes

- Dépôt GitHub : [BcommeBois/oihana-php-auth](https://github.com/BcommeBois/oihana-php-auth)
- Packagist : [oihana/php-auth](https://packagist.org/packages/oihana/php-auth)
- Documentation API (générée par phpDocumentor) : [bcommebois.github.io/oihana-php-auth](https://bcommebois.github.io/oihana-php-auth)
