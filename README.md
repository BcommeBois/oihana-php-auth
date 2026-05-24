# Oihana PHP Auth

![Oihana PHP Auth](https://raw.githubusercontent.com/BcommeBois/oihana-php-auth/main/assets/images/oihana-php-auth-logo-inline-512x160.png)

Composable PHP authorization toolkit. Part of the **Oihana PHP** ecosystem, this package combines Casbin RBAC, JWT/OIDC verification, fine-grained capabilities and HTTP middlewares to protect your APIs end‑to‑end.

[![Latest Version](https://img.shields.io/packagist/v/oihana/php-auth.svg?style=flat-square)](https://packagist.org/packages/oihana/php-auth)
[![Total Downloads](https://img.shields.io/packagist/dt/oihana/php-auth.svg?style=flat-square)](https://packagist.org/packages/oihana/php-auth)
[![License](https://img.shields.io/packagist/l/oihana/php-auth.svg?style=flat-square)](LICENSE)

## 📚 Documentation

Full API reference (generated with phpDocumentor): `https://bcommebois.github.io/oihana-php-auth`

User guides (FR + EN) live under [`wiki/`](wiki/).

## 📦 Installation

Requires [PHP 8.4+](https://php.net/releases/). Install via [Composer](https://getcomposer.org/):

```bash
composer require oihana/php-auth
```

## ✨ What you can do

- **Authenticate** any request against a Zitadel / Auth0 / Keycloak IdP using a JWKS‑backed JWT validator (cached via Memcached).
- **Authorize** with [Casbin](https://casbin.org/) RBAC + domains: route‑level guards, role/permission/policy CRUD, multi‑tenant.
- **Restrict** sensitive query parameters, filter keys or skin variants with **fine‑grained capabilities** (subject `PARAM:…`).
- **Validate** request bodies via [Somnambulist Validation](https://github.com/somnambulistphp/validation) rule catalogues.
- **Reuse ready‑made HTTP middlewares** (JWT check, authorization, rate‑limit hooks) compatible with any PSR‑15 stack.

### Under the hood

- A consistent set of interfaces (`CapabilityEnforcerInterface`, `PermissionSubjectResolverInterface`) you can implement against your own persistence layer.
- Pure‑PHP JWT validator built on top of [firebase/php-jwt](https://github.com/firebase/php-jwt) v7.
- Helpers for [PSR‑11 Container](https://www.php-fig.org/psr/psr-11/) wiring.
- Strongly‑typed enums and constants — no magic strings.

## ✅ Running tests

Run all tests:

```bash
composer test
```

Run a specific test file:

```bash
composer test ./tests/oihana/auth/SomeTest.php
```

## 🛠️ Generate the documentation

We use [phpDocumentor](https://phpdoc.org/) to generate documentation into the `./docs` folder.

```bash
composer doc
```

## 🧾 License

Licensed under the [Mozilla Public License 2.0 (MPL‑2.0)](https://www.mozilla.org/en-US/MPL/2.0/).

## 👤 About the author

- Author: Marc ALCARAZ (aka eKameleon)
- Email: `marc@ooop.fr`
- Website: `https://www.ooop.fr`

## 🔗 Related packages

- `oihana/php-core` – core helpers and utilities: `https://github.com/BcommeBois/oihana-php-core`
- `oihana/php-enums` – typed constants & enums: `https://github.com/BcommeBois/oihana-php-enums`
- `oihana/php-exceptions` – framework exceptions: `https://github.com/BcommeBois/oihana-php-exceptions`
- `oihana/php-reflect` – reflection and hydration utilities: `https://github.com/BcommeBois/oihana-php-reflect`
- `oihana/php-schema` – Schema.org constants and vocabulary: `https://github.com/BcommeBois/oihana-php-schema`
- `oihana/php-system` – framework helpers (controllers, models, request handling): `https://github.com/BcommeBois/oihana-php-system`
