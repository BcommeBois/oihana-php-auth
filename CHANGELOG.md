# Changelog

All notable changes to **oihana/php-auth** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-14

Maintenance release: full test coverage, coverage tooling and CI. No breaking
changes — the only public-surface addition is an optional constructor argument
on `JwksKeyFetcher`.

### Added

- Test coverage tooling: `tools/clover-to-markdown.php` (PHPUnit Clover → Markdown summary — global line/method/class percentages, per-directory table, least-covered files and a local `history.json` trend log) and the `coverage` / `coverage:md` Composer scripts.
- Continuous integration: `.github/workflows/ci.yml` runs `composer validate --strict` and the PHPUnit suite on PHP 8.4 (with the required PHP extensions and `libmemcached` installed for `ext-memcached`).
- `CONTRIBUTING.md`: setup, tests & coverage commands and testing philosophy.
- Test suite grown from 148 to **177 tests**, bringing the library to **100% line, method and class coverage**. New coverage for `EnforcerTrait`, `DocumentsControllerCapabilitiesTrait`, the `IdTokenValidator` end-to-end path (over a real forged RS256 signature, including key-rotation retry and expiry), the `JwksKeyFetcher` fetch-and-cache path, and the remaining capability-guard edge cases.
- `JwksKeyFetcher` accepts an optional Guzzle `Client` as a fourth constructor argument (defaulting to the previous TLS-verifying, 10s-timeout client), allowing the JWKS fetch path to be driven by a mocked transport in tests.

### Changed

- `JwksKeyFetcher` inlines its single-use `fetchJwks()` into `getKeys()` and reads its HTTP client from the injected dependency.
- Guzzle client options are expressed with `GuzzleOption` constants instead of raw string keys.
- `DocumentsControllerCapabilitiesTrait::prepareSearch()` drops an unreachable null-config guard (and its redundant second config lookup); behaviour is unchanged.

### Fixed

- Trait test classes now declare their target with `#[CoversTrait]` instead of the invalid `#[CoversClass]`, which under coverage raised "not a valid target" warnings and recorded no coverage for those tests.

### Dependencies

- Declare `ext-openssl` as a runtime requirement: RS256 id_token verification (`JWT::decode` / `JWK::parseKeySet`) relies on it and `firebase/php-jwt` does not declare it itself.

## [0.1.0] - 2026-05-31

### Added

- Dependency on `oihana/php-core` (`dev-main`) for shared encoding helpers.
- Initial scaffold: Composer manifest, PHPUnit 12 + phpDocumentor 3 configuration, MPL-2.0 license, README, CHANGELOG, sibling-aligned folder layout (`src/`, `tests/`, `wiki/`, `assets/`, `docs/`).
- Source code under `src/oihana/auth/` (34 PHP files):
  - Public interfaces `CapabilityEnforcerInterface` and `PermissionSubjectResolverInterface`.
  - Casbin layer: `CapabilityEnforcer` + `EnforcerTrait`.
  - JWT layer: `IdTokenValidator`, `JwksKeyFetcher` and three helper functions (`decodeJwtClaims`, `extractFromClaims`, `extractSidFromClaims`).
  - Controller traits: `PermissionAuthorizerTrait` plus eight `Capability*Trait` (Guard, Authorizer, Param, FilterKeys, Fields, Binary, Context, `DocumentsControllerCapabilitiesTrait`).
  - Typed enums: `Capability`, `CapabilityAction`, `CapabilityMode`, `CapabilityPolicy`, `AuthPermissions`, `RoleLevel`, `PermissionEffect`, `EdgeSyncType`, and per-resource permission subject traits (Me / Policies / Roles / Services / Users).
  - Exception `IdTokenValidationException`.
  - Helper `casbinSafeSubject` (autoload `files`).
  - Validation rule `RoleNameRule`.
- Test suite under `tests/oihana/auth/` (12 PHP files): 148 tests, 210 assertions, all green under PHPUnit 12 strict mode.
- Bilingual user guides under `wiki/{fr,en}/` (9 pages each, ~1250 lines per language): `README`, `getting-started`, `auth` (architecture), `capabilities`, `field-level-gating`, `permissions`, `rules`, `error-handling`, `tips`.

### Changed

- `decodeJwtClaims` now delegates base64url decoding to `oihana\core\encoding\base64UrlDecode` instead of an inline `base64_decode( strtr( … ) )`. The decoder enforces a strict URL-safe alphabet (rejecting `+`, `/` and whitespace), which is the expected behaviour for compact-serialized JWTs.
