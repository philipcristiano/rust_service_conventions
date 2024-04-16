# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.15](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.14...v0.0.15) - 2024-04-16

### Fixed
- fix!(oidc): Set key via config

### Other
- *(deps)* lock file maintenance
- *(deps)* lock file maintenance
- *(deps)* lock file maintenance

## [0.0.14](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.13...v0.0.14) - 2024-04-03

### Other
- Revert "fix: tracing: Set tracing level to tracing"

## [0.0.13](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.12...v0.0.13) - 2024-04-03

### Fixed
- tracing: Set tracing level to tracing

### Other
- *(deps)* lock file maintenance

## [0.0.12](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.11...v0.0.12) - 2024-03-31

### Fixed
- tracing: Use defaults for resources

## [0.0.11](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.10...v0.0.11) - 2024-03-31

### Other
- Try again for TLS GRPC tracing
- workflow: Remove invalid docker release

## [0.0.10](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.9...v0.0.10) - 2024-03-31

### Other
- Use tls feature

## [0.0.9](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.8...v0.0.9) - 2024-03-31

### Fixed
- tracing: Include https things for reqwest
- *(deps)* update rust crate axum to 0.7.5
- *(deps)* update rust crate openidconnect to 3.5.0

### Other
- Switch to renovate

## [0.0.8](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.7...v0.0.8) - 2024-03-19

### Added
- [**breaking**] oidc: Return scopes/groups

## [0.0.7](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.6...v0.0.7) - 2024-03-19

### Fixed
- oidc: Accept format used by auth0

### Other
- Default for custom scopes/groups

## [0.0.6](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.5...v0.0.6) - 2024-03-16

### Added
- oidc: Remove state from router setup

### Other
- Include lint/fixers

## [0.0.5](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.4...v0.0.5) - 2024-03-12

### Other
- redirect after auth
- oidc-user
- Merge pull request [#16](https://github.com/philipcristiano/rust_service_conventions/pull/16) from philipcristiano/release-plz-2024-03-09T21-41-29Z

## [0.0.4](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.3...v0.0.4) - 2024-03-09

### Other
- Merge pull request [#15](https://github.com/philipcristiano/rust_service_conventions/pull/15) from philipcristiano/oidc-router
- Add axum router

## [0.0.3](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.2...v0.0.3) - 2024-03-09

### Other
- Add missing deps for oidc

## [0.0.2](https://github.com/philipcristiano/rust_service_conventions/compare/v0.0.1...v0.0.2) - 2024-03-09

### Added
- axum oidc login
- tracing

### Fixed
- correct the readme example ([#4](https://github.com/philipcristiano/rust_service_conventions/pull/4))

### Other
- *(deps)* Bump the opentelemetry group with 5 updates
- Use explicit Actions token
- Update to use repo token
- *(deps)* Bump agenthunt/conventional-commit-checker-action
