# Production readiness gates

The hardening changes in Unreleased improve correctness; they do not establish
an A+ production reliability rating on their own. A release should attach the
following evidence to its exact commit and deployment configuration.

## Implemented safeguards

- V2 signatures bind command identity and optimistic concurrency controls, with
  shared Rust, Node, and Python test vectors and explicit V1 compatibility.
- `REQUIRE_SIGNED_EXECUTION_CONTROLS=true` rejects new unsigned-control events
  after clients migrate. Deploy the upgraded server before upgraded clients.
- Projection scheduling caps active streams, yields after a batch, and isolates
  stream failures. Tune concurrency and discovery interval against measured lag.
- Local SDK inclusion checks require independently trusted root and leaf hashes.
- Shutdown notification is sticky; leader workers have bounded teardown.
- Supervisor cancellation aborts owned workers; pool acquisition and lease
  probes are interruptible by shutdown and bounded by the health interval.
  PostgreSQL tests inject session termination and supervisor cancellation;
  these are lifecycle tests, not external-write fencing or crash-durability drills.
- Rate-limit capacity pressure cannot reset existing live budgets.
- HTTP and gRPC share tenant and credential budgets. The opt-in PostgreSQL
  backend uses atomic shared counters with bounded storage and fail-closed
  admission; memory mode remains per process.

## Remaining acceptance gates

1. **Fenced side effects:** introduce destination-enforced fencing or durable
   idempotency for external writes. Partition an old leader from PostgreSQL while
   leaving its destination reachable, elect a successor, and demonstrate that
   stale writes are rejected. Health polling and task cancellation are not fencing.
   The funded local-EVM drill now demonstrates destination duplicate protection
   for the supplied payment artifact, including a mined stale-batch revert.
   Production artifact matching, partition behavior, and anchoring remain to verify.
2. **Cluster-wide quota rollout:** enable PostgreSQL admission on all replicas
   with consistent settings. Validate database load and latency at deployment
   scale; the integration suite exercises independent pools, concurrent budgets,
   identity churn, expiry, and backend failure, not production capacity.
3. **Durability and recovery:** run kill/restart, database failover, and backup
   restore drills with production durability settings. Verify no acknowledged
   events are lost, ordering stays contiguous, replays preserve receipts, and
   proofs and projection checkpoints remain consistent. Record recovery time.
   The local process-crash/logical-restore drill is now automated in CI; standby
   failover, WAL/PITR, crashes within projection writes, and deployment-scale drills remain.
   In particular, projection document persistence, version compare-and-set, and
   checkpoint persistence are separate operations. Inject faults between those
   operations before claiming atomic or exactly-once projection recovery.
4. **Sustained capacity:** publish throughput, latency percentiles, projection
   lag, memory, connection use, and rejection rates under an agreed production
   workload, including hot tenants and corrupt streams. Define numeric SLOs
   before deciding pass/fail; do not infer capacity from unit tests.
5. **Full release matrix:** run locked-dependency CI including STARK/PQC and
   database integration paths. Audit V2 compatibility through proof production
   and verification, not just Merkle inclusion. Local no-default-feature checks
   do not substitute for this matrix.
6. **Independent security review:** review V2 encoding, downgrade controls,
   authorization boundaries, and key rotation; track findings to closure.

SDK registry publication and production rollout are separate release steps.
Passing local tests does not establish either one.

## Local evidence (2026-09-05 working tree)

- Full-feature unit suite: 592 passing tests with STARK and PQC enabled, using
  the locked CI dependency commit `c2cd52c6511279c9c73ab6eb16c5389176f95752`
  in an isolated source snapshot (the newer sibling checkout was not changed).
- Shared quota regression: independent PostgreSQL pools admitted exactly seven
  of 50 concurrent attempts against a seven-request budget. The same test covers
  restart persistence, capacity/churn, expiry, inconsistent window settings,
  HTTP/gRPC sharing, locked-row timeout, and unavailable-backend responses.
  Test connections used asynchronous commit to isolate concurrency behavior
  from host fsync stalls; this is not durability or production-capacity evidence.
- V2 STARK compliance regression: genuine signed ingestion, proof generation,
  REST submission/verification, and idempotent proof resubmission passed.
- Full-feature PostgreSQL integration suite: all 15 database cases passed,
  including concurrent migration/ingest, sequence invariants, exact replay,
  V2 controls, and validity/compliance proof REST flows.
- Core library and shared-quota test Clippy checks passed with warnings denied.
- Durable recovery drill: 128 signed V2 events survived SIGKILL and a logical
  restore into a fresh database with zero missing acknowledged events. An
  uncommitted sequence-head mutation rolled back. Stored envelopes, agent
  signatures/keys, signed receipts, exact replay, commitment persistence, and
  all 128 inclusion proofs were verified in two fresh runs. Local timings were
  9/12 seconds for crash recovery and 11/14 seconds for fresh-database restore,
  including checks.
  `fsync`, `full_page_writes`, and `synchronous_commit` were all `on`.
  Fixture SHA-256: `4b8e979958db0f3c5eca108e3602e6f8c031118264152b99cee9d7a71d1010f1`.
  This is a small local recovery fixture, not a production RTO/RPO guarantee.
- Projection recovery extension passed on 2026-09-05: both the crashed database
  and a fresh logical restore preserved 64 projected orders and checkpoint 64,
  independently caught up to 128 exact order IDs, and retained identical
  documents and version-1 entity records after worker restart. All existing
  event, receipt, and proof checks also passed. Local crash/restore checks took
  33/37 seconds excluding projection catch-up; these are not production targets.
  Fixture SHA-256: `3862b50074f02ca219373d5764f1d0017146351f1dc6f3919016df0ca6c02dd0`.
  Evidence was retained locally at `/tmp/sequencer-recovery.MiiaxB/result.json`.
- Funded settlement drill: real EIP-712 payment moved mock tokens exactly once.
  A fresh service recovered the lost-record outcome without a new transaction;
  a forced stale batch reverted on-chain; a duplicate intent in a new batch
  moved no further funds. See [settlement testing](SETTLEMENT_TESTING.md).
  Payment creation-bytecode text SHA-256:
  `dc4a6b9d7010d25d2e7c6f4783bca11db13d994b52cd23e327946e249e1878b9`.
  Fixture SHA-256:
  `cfc7ea7a6f3bc8bdecbe00cadc926ebc9e9f88d790d2f42a771477c800c6f9f2`.
  This used supplied local artifacts, not a verified production deployment.

These results do not replace staging failover, backup-restore, sustained-load,
or external-destination duplicate-write drills. Set deployment SLOs and identify
an authorized non-production target before running those drills.
