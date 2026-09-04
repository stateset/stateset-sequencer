# Changelog

All notable changes to stateset-sequencer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.3] - 2026-09-04

### Fixed

- Concurrent appends can no longer create a false sequence-gap invariant while
  projection workers read legacy or VES ranges, preventing unnecessary
  coordinated server shutdowns under sustained ingestion.

## [0.8.2] - 2026-09-04

### Fixed

- k6 workloads now generate valid UUIDs from `crypto.randomBytes`, honor the
  selected execution profile, target the host service explicitly in CI, and
  write summary evidence to a container-writable directory.

## [0.8.1] - 2026-09-04

### Added

- A typed Python SDK with synchronous and asynchronous clients, RFC 8785
  canonicalization, Ed25519 event signing, resilient reads and idempotent
  writes, projections, proofs, policies, durable cursors, and agent tool
  definitions. CI validates it on Python 3.10 through 3.13 and verifies both
  wheel and source distributions.

### Changed

- The unpublished Node package is now named `@stateset/sequencer-sdk`, with
  complete npm repository and provenance metadata. Its existing SDK, agent
  tools, MCP server, and x402 CLI exports remain intact.

### Fixed

- k6 workflows now load JSON profiles with the supported `--config` option;
  the invalid `--opts` flag no longer blocks release-binary CI.

## [0.8.0] - 2026-09-04

### Added

- Production projection workers for both VES and legacy ledgers, with dynamic
  keyset-paginated stream discovery, source-isolated durable read models, and a
  scoped projection read API exposed through the agent SDK and MCP toolkit.
- Opt-in, leader-elected STARK compliance-proof generation with durable job
  state, bounded retries and timeouts, self-verification, and encrypted proof
  persistence.
- Scheduled and manual k6 performance workflows, a release-binary CI smoke
  gate, and an exact-commit release workflow with checksums and build
  provenance attestations.
- Secret-file inputs and remotely refreshed asymmetric JWKS support, retaining
  the last known-good key set if refresh fails.

### Fixed

- gRPC receipt acknowledgements can no longer advance a durable agent cursor
  across missing sequence numbers or beyond the stream head.
- Load profiles now submit valid, projection-compatible events and enforce
  explicit latency and error-rate thresholds.

### Security

- JWT validation rejects symmetric JWKS keys, duplicate or missing key IDs,
  missing algorithms, and algorithm-confusion attempts; HMAC token issuance is
  disabled whenever an external JWKS is configured.

## [0.7.0] - 2026-09-04

### Added

- Server-enforced per-agent VES policies with exact and namespace-wildcard
  event/entity allowlists, optimistic-concurrency requirements, payload limits,
  enable/disable controls, administrative APIs, and audit logging.
- Durable, monotonic per-agent acknowledgement cursors over REST and gRPC,
  including stream-head lag reporting and protection against acknowledging
  events that do not exist.

### Changed

- gRPC sync state now reports the authenticated agent's persisted
  `acknowledged_sequence` and `lag`; `SyncStream` acknowledgements persist the
  same cursor used by REST clients and the Node.js SDK.

## [0.6.0] - 2026-09-04

### Added

- A production Node.js VES client that performs Rust-compatible canonical
  hashing, Ed25519 signing, authenticated idempotent ingestion, paged reads,
  cursor polling, and inclusion-proof operations.
- OpenAI-compatible function tools and a dependency-light MCP stdio server with
  fail-closed event-type allowlists and optimistic-concurrency enforcement.
- TypeScript declarations for the VES client, agent tools, MCP handler, and
  existing x402 client exports.
- Authenticated VES stream-head, range, and entity-history REST endpoints, plus
  end-to-end coverage proving reads and writes use the same canonical ledger.

### Changed

- CI now tests and audits the agent SDK on Node.js 20.

## [0.5.1] - 2026-09-04

### Security

- Forwarded client-IP headers now fail closed unless an exact, valid proxy
  allowlist is configured; missing and malformed production configuration is
  rejected at startup.
- Sensitive database, RPC, and private-key values are redacted from diagnostic
  output, and release builds retain integer overflow checks.
- Container and Kubernetes defaults now use a fixed non-root identity, a
  read-only filesystem, dropped capabilities, and the runtime-default seccomp
  profile.

### Added

- A canonical, schema-validated Helm chart with autoscaling, disruption budget,
  ingress, ServiceMonitor, external Secret, and optional worker support.
- CI validation for Helm and Kustomize manifests, MSRV enforcement, reliable
  coverage reporting, and release-image gating on every required check.

### Fixed

- Malformed database pool, session, cache, anchoring, and settlement settings
  now produce actionable startup errors instead of silently using defaults or
  partially enabling a subsystem.
- Deployment versions, documentation, STARK repository references, and
  monitoring configuration are synchronized with the release.

## [0.5.0] - 2026-08-31

### Security

- **Resolved five of the six open Dependabot alerts** (these sit outside RustSec, so `cargo audit` was already clean): `jsonwebtoken` 9.3 → 10.4 (CVE-2026-25537; v10 requires an explicit crypto backend — `rust_crypto` is enabled, and the panic a missing backend causes is covered by the JWT unit tests), `opentelemetry_sdk` 0.24 → 0.32.1 (CVE-2026-48504, a full 0.24→0.32 API migration of both tracer-init paths; shutdown now flushes through a kept provider handle since the global shutdown was removed), `cmov` 0.5.4 (CVE-2026-50185), `keccak` 0.1.6 (GHSA-3288-p39f-rqpv), `rsa` 0.9.10 (CVE-2026-21895).
- **Resolved the sixth and final Dependabot alert: `lru` (GHSA-rhfx-m35p-ff5j)** by upgrading alloy 0.8 → 1.6.3 (the newest line within the MSRV-1.90 pin; 1.7+ requires rustc 1.91 and 2.2+ requires 1.94), which pulls `lru` 0.16.4. The 1.x migration touched the settlement and anchoring send paths: recommended fillers are now the provider default, `on_http` became `connect_http`, and `sol!` call returns are unwrapped values rather than `_0`/named-field wrappers. Both send paths re-proven against a locally deployed `SetPaymentBatch` and `SetRegistry`, including the idempotency/no-retry-storm tests.

### Fixed

- **Concurrent batches sharing `command_id`s could deadlock and fail an entire ingest.** Command-id reservation inserted into `ves_command_dedupe` one id at a time in hash-set (arbitrary) order, so two transactions could take the row locks in opposite orders; PostgreSQL resolved the deadlock (40P01) by aborting one whole batch, surfacing as a 500 to a client that did nothing wrong. Reservation now acquires in sorted order, which is deadlock-free by construction. Found by the new randomised concurrency test below; reproduced 3/3 before the fix, 0/3 after (plus a targeted opposite-order stress test).
- **Built-in anchoring never worked against the deployed `SetRegistry`.** The sequencer's ABI binding declared `anchor`, `isAnchored`, `getLatestSequence` and `verifyEventsRoot`; the contract exposes `commitBatch`, `batchExists`, `getHeadSequence` and `getBatchCommitment`. Every anchor attempt in the shipped stack (`docker-compose.yml` points the worker at `SetRegistry`) reverted on selector lookup. This was invisible because the circuit-breaker wrapper discarded the inner error (`map_err(|_| "circuit breaker is open")`) and the retry policy then spent ~5 minutes per attempt on the guaranteed revert. The binding now matches the contract, `commitBatch` carries `prevStateRoot`, `verify_events_root_onchain` compares against the stored commitment, and breaker errors surface the real failure. Verified by a new on-chain test against a locally deployed `SetRegistry`.
- **Reverts were classified as transient by the retry policy.** A revert at gas estimation reaches the caller wrapped in the send error — `"Failed to send … execution reverted …"` — and both the anchor and settlement predicates keyed on `"failed to send"`, so a transaction guaranteed to revert identically was retried ten times over ~5 minutes, stalling the calling worker's whole tick. A shared `is_transient_chain_error` now checks terminal markers (revert, custom error, nonce too low/high, already known, insufficient funds, invalid signature, out of gas) *before* transport markers. Measured: an already-settled batch reconciled in 0.02 s where it previously took 290 s.
- **An anchored commitment whose local record was lost was re-sent every tick, forever.** `reconcile()` only checked commitments that already carried a tx hash. `anchor_ves_commitment` now pre-checks `batchExists` and returns `ALREADY_ANCHORED_TX_HASH` without sending; the worker, the two HTTP anchor handlers and the admin CLI confirm the anchor locally instead of recording a fake hash. Proven on-chain: second attempt is a read, the settler nonce does not move, and it completes in milliseconds.

### Added

- **Randomised concurrent-ingest invariant test.** Batch sizes, stream choice, exact-replay duplicates and command-id collisions are drawn from a seeded RNG (`SEQ_TEST_SEED` reproduces a failure) and fired concurrently; asserts per-stream contiguity from 1, one sequence number per event, identical receipts for replays, disjoint batch ranges tiling exactly 1..=head, and exactly one winner per command id. The fixed-shape concurrency test only ever checked one interleaving.

### Changed

- CI's `STARK_REF` advanced to `stateset-stark` v0.5.0 (`c2cd52c`), matching `Cargo.lock`; the sequencer's full library and integration suites pass against it.

### Documentation

- **Configuration reference moved to `docs/CONFIGURATION.md`.** The README had grown to ~770 lines, half of it per-variable tables; it now carries a six-variable boot-essentials table and a pointer, while the full reference (107 variables across 16 subsystems) lives in its own file. All internal links updated and verified.

## [0.4.1] - 2026-08-31

### Added

- **Settlement idempotency is now proven, not asserted.** A new on-chain test drives `SettlementService::settle_batch` twice for the same batch against a local EVM: the first call sends the transaction, the second finds `getBatch(id).settledAt != 0` and returns `already_settled` with a zero tx hash and no transaction. This is the crash-between-send-and-record / leader-failover case the code documented as safe; it is now exercised. A companion database test shows `settle_batch_with_results` called twice with different tx data is an idempotent no-op that never overwrites the first record.
- **Structural source checks** (`tests/source_invariants_test.rs`): every `fetch_all` in the PostgreSQL layer must have a `LIMIT` in its query, or a reviewed exemption with a stated reason. This encodes the entity-history defect class so a reviewer does not have to remember to look for it.
- **`#![deny(clippy::unwrap_used, clippy::expect_used)]` on the library** for non-test builds. The only remaining `expect` calls are the three RFC 8785 canonicalization sites, each carrying an `allow` with the reason they are unreachable; every other "checked above" `expect`/`unwrap` was converted to a proper error path.
- **Scrape-health alerts** in `monitoring/prometheus_rules.yaml`: `SequencerScrapeDown`, `SequencerScrapeSeriesMissing` and `SequencerMetricsCardinalityOverflow`. `/metrics` was unparseable for every real deployment until 0.3.1 and nothing noticed, because missing series looked like a quiet service; these make the absence of data itself an alert.
- **Minimum supported Rust version declared and enforced.** `rust-version = "1.90"` in `Cargo.toml`, with a CI job that builds `--all-targets --locked` on exactly that toolchain. The floor is set by the `ves-stark-*` crates, which require 1.90.
- **Admin CLI smoke tests** (`tests/admin_cli_test.rs`): `--help` lists every command, `version` prints the crate version, an unknown command exits non-zero with guidance, and per-command help works. These run without a database.

### Fixed

- **Cache miss/refresh locks could leak forever.** A request future dropped mid-fetch (client disconnected) never released its stampede lock, so every later miss on that key paid the stampede delay for the life of the process and the lock set grew by one entry per abandonment. Locks now carry an acquisition time and one older than `DEFAULT_MISS_LOCK_TTL` (10s) is treated as abandoned and taken over.
- **`read_by_type` is now span-capped** like the other range readers.
- **x402 integration tests no longer depend on another test binary having migrated the database first.** The harness runs migrations itself (idempotently); previously the suite failed with "relation does not exist" when run alone or first, an ordering dependency cargo does not guarantee.

### Changed

- **`admin.rs::main()` reduced from ~1,500 lines to ~50.** Each subcommand's body is now its own `cmd_*` function; behaviour is unchanged and covered by the new smoke tests.

## [0.4.0] - 2026-08-30

### Fixed

- **Entity history was loaded whole and paged in memory.** `EventStore::read_entity` and `VesSequencer::read_entity` fetched every event an entity ever had; the HTTP handler and both gRPC services then sliced the result with skip/take, so the documented 100-event cap bounded only the response, not the query. A hot entity cost a full-history fetch and decode per request to any authenticated reader, and gRPC v2 `subscribe_entity` with `include_history` buffered the entire history before streaming a byte. Both repositories now expose only `read_entity_page(offset, limit)`, which runs `COUNT(*)` plus `LIMIT/OFFSET` over the existing entity indexes and clamps the limit to `MAX_ENTITY_HISTORY_PAGE` inside the repository. The HTTP handler, gRPC v1/v2 `get_entity_history`, and the v2 subscribe replay (now page-at-a-time) all use it; response shapes and `current_version` semantics are unchanged.
- **`read_range` now rejects spans wider than `MAX_READ_RANGE_SPAN` (1000) at the repository.** Every caller already capped the span at 1000, so no live behaviour changes; this closes the case where one new call site reopens an unbounded read of the log.
- **x402: a failed batch stranded its claimed intents.** `mark_batch_failed_if_pending` flipped only the batch row. Intents already claimed (`sequenced` → `batched`) kept that status and their `batch_id`, pointing at a failed batch; the batcher selects only `sequenced` intents and settlement only committed batches, so those payments were never batched or settled again. The method now also returns the batch's `batched` intents to `sequenced` with `batch_id` cleared, in the same transaction.
- **x402: `X402_BATCH_AUTO_COMMIT=false` was a dead end.** The worker claimed intents into a pending batch and stopped, but no endpoint commits an existing pending batch (`POST /api/v1/x402/batches` creates and commits its own), so every batch made in that mode stranded its intents. The worker no longer has a claim-without-commit path: batch creation is atomic-or-nothing.

### Changed

- **BREAKING: `EventStore::read_entity` removed** in favour of `read_entity_page(offset, limit) -> EntityHistoryPage`. There is deliberately no unpaged variant; implementors of the trait must provide the paged method. `VesSequencer::read_entity` is likewise replaced.
- **BREAKING: `X402_BATCH_AUTO_COMMIT=false` now disables the batch worker's batching entirely** rather than claiming intents without committing. Intents stay `sequenced` and are batched via the API. The default (`true`) is unchanged.

### Testing

- Six new database-backed tests: entity paging order, totals past the end and limit clamping on both stores; span rejection on both stores; released intents after a failed batch; and a worker without auto-commit leaving intents unclaimed. 746 tests pass against a virgin PostgreSQL with zero ignored.

## [0.3.2] - 2026-08-30

### Documentation

- **README corrected.** Three claims were false: the Rust badge advertised
  `1.70+` although the code uses APIs stabilized well after it; the codecov
  badge pointed at branch `main` when the default branch is `master`; and the
  testing section instructed readers to run `-- --ignored`, which now runs
  nothing because no test is ignored. A `security: audited` badge that nothing
  in the repository substantiates was removed. No replacement MSRV was invented
  -- none is verified in CI, and the README now says so.
- **Documented 42 environment variables the code reads and the README never
  mentioned**, covering the x402 payment, on-chain settlement,
  anchoring-cadence, server-runtime and OpenTelemetry surfaces.
- **Documented `TRUST_PROXY_HEADERS` and `TRUST_PROXY_ALLOWLIST`**, which gate a
  security decision and were previously absent entirely: the resolved client IP
  drives the `ADMIN_IP_ALLOWLIST` check, the public-registration rate-limit key,
  and the IP recorded in audit logs. Explains why the forwarded chain is read
  from the right, and why a deployment behind an ingress generally must enable
  the flag.
- **Documented `VES_STARK_ALLOW_UNVERIFIED_AMOUNT_BINDING`** with an explicit
  warning that it weakens proof soundness to prover honesty.
- Documented the x402 endpoint surface, the HTTP 402 metered-route flow,
  autonomous settlement (including the three variables required before the
  worker starts at all), and distributed/HA leader election -- all shipped in
  0.3.0 but never described.
- Documented the ten admin CLI subcommands that were missing; two of twelve had
  been listed.
- Added `settlement.rs`, `x402.rs`, `payment_required.rs`, `settlement_worker.rs`
  and `net.rs` to the project structure, and the amount-binding, client-IP,
  admin-allowlist and replay-protection controls to the security table.
- Documented the database-test gating introduced in 0.3.0: tests skip when
  `DATABASE_URL` is unset, fail when it is set but unreachable, and fail either
  way under `SEQUENCER_REQUIRE_DB_TESTS`.

Every default, route and command in the new text was read back out of the code
rather than assumed.

## [0.3.1] - 2026-08-30

### Security

- **The client IP used for security decisions could be chosen by the caller.** `X-Forwarded-For` grows left-to-right -- each proxy *appends* the address it received from -- so only the rightmost entries are attested by trusted infrastructure, while the leftmost is whatever the original client wrote. The leftmost entry was being read, so with `TRUST_PROXY_HEADERS=true` (which any deployment behind the shipped `k8s/ingress.yaml` needs, since otherwise every client presents as the ingress) an external attacker sending `X-Forwarded-For: 10.0.0.1` was attributed that address. That value drives three things: the **`ADMIN_IP_ALLOWLIST` decision** on the admin and metrics routes, the **public agent-registration rate-limit key**, and the **client IP recorded in audit logs** -- so the allowlist could be bypassed, the rate limiter evaded by rotating fabricated addresses, and audit records poisoned with attacker-chosen IPs. The chain is now walked from the right, skipping hops that are themselves trusted proxies, so it resolves to the first address no trusted proxy vouched for; when every hop is trusted there is no external client and the socket peer is used. `x-real-ip` and `forwarded` now take the last header value rather than the first, for the same reason. Admin routes always required an admin API key as well, so this defeated a defence-in-depth layer rather than authentication itself. Not exploitable in the default configuration, where `TRUST_PROXY_HEADERS` is `false`.

### Fixed

- **`/metrics` emitted invalid exposition and Prometheus rejected the entire scrape.** `Histogram::to_prometheus_with_labels` emitted its own `# TYPE` line and is called once *per label set*, so a histogram with more than one label combination declared its type repeatedly. `http_request_latency` is labeled by method, path and status, so the second distinct request to any deployment was enough to break the endpoint -- observability was silently absent wherever this was scraped. The `# TYPE` header is now emitted once per metric name by the caller, with unlabeled and labeled histograms merged the way counters and gauges already were. This defect predates 0.3.0; the 0.3.0 hardening pass fixed two of the three exposition code paths and its changelog entry overstated the result, which has been corrected above.

### Testing

- Added a whole-payload exposition validator (`prometheus_exposition_is_well_formed`) that parses `/metrics` output and fails on any defect Prometheus would reject -- duplicate `# TYPE` declarations, unterminated label sets, unbalanced quotes -- exercised against a realistic mix of unlabeled and labeled counters, gauges and histograms plus a hostile label value. Asserting on whole-payload validity rather than on individual substrings is the check whose absence let the histogram defect survive the previous round of hardening on this same function.

## [0.3.0] - 2026-08-29

### Security

- **The `/metrics` endpoint could be taken down by any unauthenticated client, twice over.** The HTTP metrics middleware is layered *outside* the auth layers, so both paths were reachable pre-auth.
  - **Label values were emitted unescaped.** The Prometheus text exposition format requires `\`, `"` and newline to be escaped inside a quoted label value. A single raw `"` closes the quote early and makes the *entire* payload unparseable, so Prometheus rejects the whole scrape rather than the one malformed series. Unmatched request paths were fed verbatim into the `path` label, so `GET /x"y` from anyone blacked out the endpoint until the offending series aged out.
  - **Unmatched request paths were unbounded label cardinality.** A stream of junk 404s could exhaust the per-metric cardinality budget, after which every genuine route falls into the overflow bucket for the life of the process. All unmatched requests now share a single `<unmatched>` bucket; per-404 detail belongs in the request log and trace, which already carry the request id.
- **A metric name used both labeled and unlabeled emitted two `# TYPE` lines** for counters and gauges, because the two are kept in separate maps. Prometheus rejects a scrape that declares a type twice. Deduplicated for counters and gauges. **Correction:** this entry originally claimed the type was "now emitted once per exported name" and that the bug was "not reachable from current call sites." Both statements were wrong -- histograms were left on a separate code path that emitted a `# TYPE` line *per label set*, which every deployment hits. See 0.3.1.
- **Resolved 4 dependency advisories**, including RUSTSEC-2026-0258 (h2 unbounded empty DATA frames), directly reachable because this service serves HTTP/2 for gRPC. Also crossbeam-epoch (RUSTSEC-2026-0204), quinn-proto (RUSTSEC-2026-0185, 7.5 high) and ruint (RUSTSEC-2026-0220). `cargo audit` exits clean.

### Fixed

- **`event_schemas` was not under migration control.** The table was created by runtime DDL in `PgSchemaStore::initialize()` at boot, which kept the schema registry outside migration version control, required the application role to hold DDL grants in production, and raced between concurrently starting replicas. It also meant a freshly migrated database had no such table, so the three cross-tenant isolation tests for the registry could never run — the registry's tenant isolation was effectively unverified. Added migration `018_event_schemas.sql` and removed the runtime DDL.
- **Database-backed tests failed open.** Every one did `env::var("DATABASE_URL").ok()?` followed by `connect(..).await.ok()?`, so a `DATABASE_URL` pointing at a database that was down, misconfigured, or unreachable produced a green run that had asserted nothing — coverage could vanish without a single red test. A set-but-unreachable database is now always a panic, and CI sets `SEQUENCER_REQUIRE_DB_TESTS=1` so a missing one is red as well. (This caught a genuinely vanished test database on its first run.)
- **`cargo --locked` failed, so no CI job ran.** `Cargo.lock` lagged the committed `stateset-stark` HEAD, and every job in the workflow passes `--locked` — the pipeline failed before compiling anything, and none of its gates were gating. The `ves-stark-*` crates are path dependencies on a separate repository, so tracking its default branch meant any upstream commit silently invalidated the lockfile here, with no change in this repo. CI now pins `STARK_REF` to an exact commit.
- **The compliance-proof REST test exercised the weak path.** Its fixture used an encrypted payload, whose amount binding cannot be verified, so the test broke once verifier-side binding was enforced. It now drives the verified plaintext path end to end and additionally asserts that a witness commitment disagreeing with the stored payload amount is rejected — the mechanism that stops a large payment being proved as a small one to duck a reporting threshold.

- **x402 batch commit was completely non-functional; now fixed and atomic.** `commit_batch_with_merkle` read the batch's intents `WHERE batch_id = $1` *before* anything had set `batch_id` on them, so it always found an empty set and failed with "No intents in batch" — both the background batcher's auto-commit path and the manual `/x402/batches` commit endpoint were broken (every commit failed and the batch was marked failed). It now takes the batch's `intent_ids` and, in a single transaction, claims them into the batch (`sequenced` → `batched`), reads them back ordered by sequence number, computes the Merkle root, and marks the batch committed — so a crash can no longer strand intents as `batched` under an uncommitted batch. Verified end-to-end against PostgreSQL (full x402 integration suite passes).
- **x402 sequencing is now atomic**: the payment-intent insert, nonce reservation, and sequence-number assignment run in a single transaction. Previously a crash between the intent commit and the separate sequencing transaction could strand an intent as `pending` with a permanently-burned nonce and no recovery path.
- **x402 sequence counter overflow** now returns an error instead of `saturating_add`, which would have handed every subsequent intent the same sequence number, breaking the per-(tenant,store) monotonic-unique invariant and Merkle leaf ordering.
- **x402 receipts no longer emit a wrong-but-valid-looking inclusion proof**: if an intent is not a member of its referenced batch, receipt generation errors instead of defaulting to leaf index 0 and substituting an empty proof.
- **VES events with a malformed stored encrypted payload now error loudly** instead of silently decoding to `payload_encrypted = None` while `payload_kind` stayed `Encrypted` (invariant violation).
- **VES receipt insert uses `ON CONFLICT DO NOTHING`** instead of a non-atomic `WHERE NOT EXISTS`, so a concurrent duplicate no longer aborts the entire ingest transaction with a duplicate-key error.
- **SQLite outbox `store_pulled_event(s)` now rejects events with no sequence number** instead of defaulting to `0`. The sequence number is the `pulled_events` PRIMARY KEY under `INSERT OR REPLACE`, so two un-sequenced events would both land at key `0` and silently overwrite each other (offline-agent data loss).
- **SQLite outbox `mark_pushed` is scoped to unpushed rows** (`pushed_at IS NULL`), so a retried/duplicate call can no longer reset an already-pushed event's `pushed_at` timestamp.
- **Inventory projection arithmetic is now overflow-safe**: adjust/reserve/release/fulfill use checked `i64` arithmetic and reject on overflow instead of wrapping silently (release builds) or panicking and killing the projection task (debug builds) on adversarial agent-supplied quantities. Reserve/release/fulfill now also reject negative quantities, which previously ran the arithmetic in reverse.
- **gRPC `GetEntityHistory` (v1 + v2) now validates the version range before the empty-result shortcut.** A malformed `from_version > to_version` range was only rejected when `from_version` was within the entity's current version; if `from_version` also exceeded `current_version`, the early empty-result return masked the invalid range as `Ok(empty)`. Input validation now runs first, so an invalid range consistently returns `InvalidArgument`.
- **v1 gRPC `GetEntityHistory` now caps its response at `MAX_ENTITY_HISTORY` (100)**, matching the HTTP and v2 gRPC paths. Previously the v1 path applied no upper bound, so a reader could request the full version range of a hot entity and force its entire history to be serialized into one response.
- **Circuit breaker half-open state can no longer wedge**: `half_open_requests` now tracks in-flight probes and is freed when a probe records its result. Previously it counted total probes per half-open episode, so with the default config (`half_open_max_requests == success_threshold`) a single admitted-but-never-recorded probe (cancelled future / shutdown / timeout) left the circuit stuck half-open forever — never closing, never re-probing. (regression test added)
- **Pool monitor no longer underflows** computing active connections: `size - num_idle` (sampled non-atomically from sqlx, so `num_idle` can transiently exceed `size`) is now `saturating_sub`, preventing a spurious `Critical` reading that would trip the auth load-shedder into 503-ing all traffic (and a debug-build panic).
- **Retry backoff no longer panics on misconfigured delays**: the decorrelated-jitter lower bound is clamped to the upper bound, so a config with `initial_delay > max_delay` (or a sub-1.0 multiplier) can't produce an empty `gen_range` that kills the retrying task. (regression tests added)
- **HTTP handlers no longer leak raw backend error strings**: the legacy `create_commitment` handler and both event-ingest handlers returned `SequencerError::to_string()` directly with a `400`, exposing raw sqlx/internal detail (e.g. `database error: <constraint text>`) and mislabeling infrastructure failures as client errors. A new `map_sequencer_error` helper routes `Database`/`Encryption`/`MerkleTree`/`Configuration`/`Internal` variants through `internal_error` (generic 500, detail logged) while preserving `400` + message for genuine client-validation variants.
- **Merkle inclusion-proof verify endpoints now cap `proof_path` length** (`MAX_PROOF_PATH_LEN = 64`, ≈ tree depth) before hex-decoding, closing a CPU/memory amplification vector where a multi-megabyte path forced a large allocation and a long verification walk.

### Dependencies / Security advisories

- Resolved 7 RustSec advisories via semver-compatible updates: `bytes` 1.11.0→1.11.1 (RUSTSEC-2026-0007, integer overflow), `ruint` 1.17.0→1.18.0 (RUSTSEC-2025-0137, unsoundness), `rustls-webpki` 0.103.8→0.103.13 (RUSTSEC-2026-0049/0098/0099/0104, name-constraint + CRL-parsing bugs), `time` 0.3.44→0.3.49 (RUSTSEC-2026-0009, DoS), and `rand` 0.8.5→0.8.6 / 0.9.2→0.9.4 (RUSTSEC-2026-0097, unsoundness).
- `cargo audit` and `cargo deny check advisories/licenses/sources` now pass clean. The one remaining `rsa` advisory (RUSTSEC-2023-0071, no fix available) is documented and ignored in `.cargo/audit.toml` because `rsa` is not in the build graph — it is only pulled by the disabled sqlx `mysql` feature.
- Migrated `deny.toml` to the cargo-deny 0.16+ schema (the previous file no longer parsed): removed the deprecated per-class severity keys, switched the licenses section to the allowlist model, added the permissive licenses now present in the tree (`Unicode-3.0`, `Unlicense`, `MIT-0`, `0BSD`, `CDLA-Permissive-2.0`), and scoped `unmaintained` to workspace crates so transitive unmaintained build-time deps don't fail CI.
- **Eliminated the `openssl` dependency** (banned in favor of rustls): `alloy` now uses an explicit feature set with `reqwest-rustls-tls` instead of the `full` bundle's default `native-tls`, and `jsonschema` drops its unused `resolve-http`/`resolve-file` defaults. `openssl` is no longer in the dependency tree under any feature set, and all four `cargo deny check` checks (advisories/licenses/bans/sources) now pass. The L2-RPC HTTP transport uses rustls with bundled webpki roots — note that a private RPC endpoint behind a custom CA would need a native-roots variant.

### Reliability

- **Background workers (anchor + x402 batch) are now supervised.** Previously each monitor task simply blocked on the shutdown signal, so if a worker panicked or returned early the death went completely unnoticed — anchoring/batching stopped silently while the server kept serving. The monitors now `select!` between the shutdown signal and the worker task completing; an unexpected early exit (panic or return) is logged at `ERROR` and triggers a coordinated shutdown so a process supervisor restarts the sequencer instead of running degraded.

### API consistency

- **Event-ingestion error responses are now structured JSON** (`{ "error": { "code", "message", ... } }`), matching the x402 and other handlers, instead of bare plain-text bodies. The legacy and VES ingest handlers return `ApiError`, with a `From<(StatusCode, String)>` conversion so their validation helpers keep their existing return type. (api integration suite now 44/44.)

### Observability

- The at-rest payload decrypt path logs a `WARN` when ciphertext fails to decrypt against *every* tenant key (the genuine tampering / corruption / AAD-mismatch signal), while still staying quiet on ordinary per-key rotation misses.

### Added

- Pure, runtime-free `merkle` module for VES Merkle tree operations with property tests covering arbitrary (including non-power-of-two) tree sizes: prove/verify round-trip, tampered-leaf rejection, cross-leaf rejection, and root determinism.
- `X402_MAX_AMOUNT` ingest bound (`i64::MAX`) so payment amounts cannot silently wrap negative when persisted to Postgres `BIGINT`.

### Changed

- **BREAKING: removed six Cargo features that gated no code** — `grpc`, `telemetry`, `anchoring`, `schema-validation`, `sqlite`, `encryption`. tonic/prost, the OpenTelemetry stack, alloy, jsonschema and the sqlx sqlite driver are all unconditional dependencies and the corresponding modules compile unconditionally, so `--no-default-features --features grpc` produced a binary identical to a default build while implying the opposite. They were removed rather than kept as no-ops: a feature that silently does nothing is worse than an absent one, because it lets a build be described as "without gRPC" when gRPC is still compiled in and served. `full` is now `["pqc", "stark"]`. Build the core sequencer with `--no-default-features --features pqc`.
- **`PERFORMANCE_BENCHMARKS.md` no longer reports figures nothing measures.** The summary table carried numbers dated 2024-01-15 — including an availability figure that no benchmark here could produce — presented as measurements. Replaced with 14 real Criterion results (reproducible via `cargo bench`) and explicit "Not measured" rows for the end-to-end service metrics, plus instructions for populating them.

### Testing

- 735 tests pass against a virgin PostgreSQL with **zero ignored**; previously 4 failed and 76 were skipped by default. clippy `-D warnings` is clean on both the core and `stark` feature sets, and `cargo deny` passes licenses and advisories.

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
