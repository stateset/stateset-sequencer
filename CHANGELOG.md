# Changelog

All notable changes to stateset-sequencer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **x402 sequencing is now atomic**: the payment-intent insert, nonce reservation, and sequence-number assignment run in a single transaction. Previously a crash between the intent commit and the separate sequencing transaction could strand an intent as `pending` with a permanently-burned nonce and no recovery path.
- **x402 sequence counter overflow** now returns an error instead of `saturating_add`, which would have handed every subsequent intent the same sequence number, breaking the per-(tenant,store) monotonic-unique invariant and Merkle leaf ordering.
- **x402 receipts no longer emit a wrong-but-valid-looking inclusion proof**: if an intent is not a member of its referenced batch, receipt generation errors instead of defaulting to leaf index 0 and substituting an empty proof.
- **VES events with a malformed stored encrypted payload now error loudly** instead of silently decoding to `payload_encrypted = None` while `payload_kind` stayed `Encrypted` (invariant violation).
- **VES receipt insert uses `ON CONFLICT DO NOTHING`** instead of a non-atomic `WHERE NOT EXISTS`, so a concurrent duplicate no longer aborts the entire ingest transaction with a duplicate-key error.
- **Inventory projection arithmetic is now overflow-safe**: adjust/reserve/release/fulfill use checked `i64` arithmetic and reject on overflow instead of wrapping silently (release builds) or panicking and killing the projection task (debug builds) on adversarial agent-supplied quantities. Reserve/release/fulfill now also reject negative quantities, which previously ran the arithmetic in reverse.
- **v1 gRPC `GetEntityHistory` now caps its response at `MAX_ENTITY_HISTORY` (100)**, matching the HTTP and v2 gRPC paths. Previously the v1 path applied no upper bound, so a reader could request the full version range of a hot entity and force its entire history to be serialized into one response.
- **Circuit breaker half-open state can no longer wedge**: `half_open_requests` now tracks in-flight probes and is freed when a probe records its result. Previously it counted total probes per half-open episode, so with the default config (`half_open_max_requests == success_threshold`) a single admitted-but-never-recorded probe (cancelled future / shutdown / timeout) left the circuit stuck half-open forever — never closing, never re-probing. (regression test added)
- **Pool monitor no longer underflows** computing active connections: `size - num_idle` (sampled non-atomically from sqlx, so `num_idle` can transiently exceed `size`) is now `saturating_sub`, preventing a spurious `Critical` reading that would trip the auth load-shedder into 503-ing all traffic (and a debug-build panic).
- **Retry backoff no longer panics on misconfigured delays**: the decorrelated-jitter lower bound is clamped to the upper bound, so a config with `initial_delay > max_delay` (or a sub-1.0 multiplier) can't produce an empty `gen_range` that kills the retrying task. (regression tests added)
- **HTTP handlers no longer leak raw backend error strings**: the legacy `create_commitment` handler and both event-ingest handlers returned `SequencerError::to_string()` directly with a `400`, exposing raw sqlx/internal detail (e.g. `database error: <constraint text>`) and mislabeling infrastructure failures as client errors. A new `map_sequencer_error` helper routes `Database`/`Encryption`/`MerkleTree`/`Configuration`/`Internal` variants through `internal_error` (generic 500, detail logged) while preserving `400` + message for genuine client-validation variants.
- **Merkle inclusion-proof verify endpoints now cap `proof_path` length** (`MAX_PROOF_PATH_LEN = 64`, ≈ tree depth) before hex-decoding, closing a CPU/memory amplification vector where a multi-megabyte path forced a large allocation and a long verification walk.

### Reliability

- **Background workers (anchor + x402 batch) are now supervised.** Previously each monitor task simply blocked on the shutdown signal, so if a worker panicked or returned early the death went completely unnoticed — anchoring/batching stopped silently while the server kept serving. The monitors now `select!` between the shutdown signal and the worker task completing; an unexpected early exit (panic or return) is logged at `ERROR` and triggers a coordinated shutdown so a process supervisor restarts the sequencer instead of running degraded.

### Observability

- The at-rest payload decrypt path logs a `WARN` when ciphertext fails to decrypt against *every* tenant key (the genuine tampering / corruption / AAD-mismatch signal), while still staying quiet on ordinary per-key rotation misses.

### Added

- Pure, runtime-free `merkle` module for VES Merkle tree operations with property tests covering arbitrary (including non-power-of-two) tree sizes: prove/verify round-trip, tampered-leaf rejection, cross-leaf rejection, and root determinism.
- `X402_MAX_AMOUNT` ingest bound (`i64::MAX`) so payment amounts cannot silently wrap negative when persisted to Postgres `BIGINT`.

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
