# Changelog

All notable changes to stateset-sequencer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.7] - 2026-04-02

### Security

- Enforce VES security profiles during agent key registration, signature validation, and encrypted payload checks
- Keep PostgreSQL SSL required by default while allowing explicit local-only development opt-in with `ALLOW_INSECURE_LOCAL_DB=true`

### Added

- ML-DSA helper backend wiring for PQC signing and verification paths
- Server tests covering the local database SSL override policy

### Changed

- Align README and Docker Compose local bootstrap instructions with server startup requirements
- Clear the remaining `clippy` warning backlog across core handlers, persistence, and projection code

### Fixed

- Remove duplicate `#[tokio::test]` and `#[sqlx::test]` registration in complex integration coverage
- Normalize touched Rust sources so the repo passes the release lint and test gates cleanly

### Validation

- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo test --locked --lib --bins`
- `cargo test --locked --tests`

## [0.2.5] - 2026-02-02

### Security

- Enforce store scoping on x402 payment listing
- Require admin auth for detailed health checks
- Use socket-derived client IPs for public registration unless proxy headers are trusted

### Added

- Global admin agent key lookup by agent id
- Docs for public registration and proxy trust configuration

## [0.2.4] - 2026-02-01

### Security

- Restrict public self-service to agent registration only and issue API keys on registration
- Require admin auth for metrics and x402 settlement operations
- Add audit logging and rate limiting for public agent registration

### Added

- Public registration router plus coverage for registration and x402 auth constraints

### Changed

- API key validation prefers the database store when available

## [0.2.0] - 2026-01-11

### Added

- **VES v1.0 Protocol v2 API** - Complete new gRPC service (`stateset.sequencer.v2`) with full VES v1.0 protocol support
- **Bidirectional Streaming** - `SyncStream` RPC for full-duplex agent synchronization
- **Server-Side Streaming** - `StreamEvents` RPC for continuous event delivery with filtering
- **Entity Subscription** - `SubscribeEntity` RPC for targeted entity update streams
- **Key Management Service** - New `KeyManagement` gRPC service for agent key lifecycle (register, get, revoke)
- **gRPC Auth Interceptor** - JWT and API key authentication via gRPC metadata (`authorization`, `x-api-key` headers)
- **Enhanced Push Response** - Includes batch commitment and rejection details
- **Inclusion Proofs** - `GetInclusionProof` RPC for Merkle proof generation and verification
- **Entity History** - `GetEntityHistory` RPC for retrieving entity event streams with version filtering
- **Sync State** - `GetSyncState` RPC for querying current sequencer head and latest commitment

### Changed

- Extended `PgEventStore` with `read_by_id` and `get_leaf_inputs` methods for proof generation
- Enhanced `PgCommitmentEngine` with `get_commitment_by_sequence` and `get_last_commitment` queries
- Improved JWT validation with additional claims support
- Server startup now registers both v1 and v2 gRPC services

## [0.1.1] - 2025-12-15

### Added

- Initial VES sequencer implementation
- PostgreSQL event store backend
- Merkle commitment engine with L2 anchoring
- Basic gRPC API (v1)
- JWT and API key authentication
- OpenTelemetry observability
