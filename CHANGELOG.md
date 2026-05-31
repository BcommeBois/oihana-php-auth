# Changelog

All notable changes to **oihana/php-auth** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
