# Sequencer ordering verification

These models cover `PgSequencer::ingest`, `VesSequencer::ingest`, the legacy
`PgSequencer::sequence` range reservation API, and selected sync, commitment,
anchoring, and payment state transitions. The stream key is
`(tenant_id, store_id)`. A committed ingest batch appends fresh event IDs,
assigns consecutive sequence numbers, and raises
the counter by the number inserted. Rejections, exact replay, and transaction
rollback leave committed ordering state unchanged.

## What is checked

- [Ingest TLA+ model](tla/SequencerIngest.tla): TLC explores all reachable states for
  two streams, three event IDs, batches of one or two, and a maximum sequence
  of three. It checks `head = length(log)`, the bound, and uniqueness of event
  IDs within and across streams. Each `Commit` is the linearization point of
  one database transaction; concurrent transactions are represented by their
  possible commit orders.
- [Transaction TLA+ model](tla/SequencerTransactions.tla): two writers start
  requests, acquire per-stream locks, accept or reject, then commit or abort.
  TLC checks lock ownership, committed counter consistency, bounds, and global
  event ID uniqueness through these interleavings. An insert conflict across
  streams can abort a transaction in this model; the implementation may instead
  skip that insert and commit other accepted events.
- [Reservation TLA+ model](tla/SequencerReservations.tla): ingest and
  `sequence()` allocate from the same counter. TLC checks that ranges tile the
  allocated sequence space without overlap and that only ingest allocations
  create stored events. It permits gaps in stored events after reservations.
- [VES replay TLA+ model](tla/VesReplay.tla): a committed VES event, its command
  reservation, sequence number, and receipt appear atomically. Exact replay
  returns that receipt without advancing the counter. A changed event body or
  reused command receives no receipt. The abstract body includes the signature
  scheme and signature bundle as well as the event payload.
- [Entity version TLA+ model](tla/EntityVersions.tla): two writers compete on
  one stream with two entities and independently chosen base versions. TLC
  checks that only a matching base version advances the sequence and entity
  version together; conflicts and aborts leave both unchanged.
- [Command lock order TLA+ model](tla/CommandLockOrder.tla): two VES writers
  acquire two command ID locks in ascending order. TLC checks exclusive
  ownership, absence of a two-writer wait cycle, and that some writer can
  progress whenever a reservation is active. This is a deadlock safety check;
  it does not assume fair scheduling or prove eventual completion.
- [Command reservation race TLA+ model](tla/CommandReservationRace.tla): two
  streams reserve the same command ID while racing to insert one globally
  unique event ID. TLC checks that the losing stream releases its reservation,
  even when the winning event carries that same command ID. This applies to
  both legacy and VES ingest.
- [SQL-step refinement model](tla/IngestSqlRefinement.tla): two writers interleave
  lookup, command reservation, stream locking, conditional insert, conflict,
  abort, and commit. TLC checks the committed event log and counter satisfy
  `SequencerIngest` under an explicit refinement mapping. PostgreSQL's
  `ON CONFLICT DO NOTHING` and lock semantics are assumptions of this model.
- [Sync and projection model](tla/SyncAndProjection.tla): durable outbox state,
  remote event dedupe, acknowledgements, cursor advancement, pruning, and
  atomic projection checkpoints. TLC checks that pruned items were acknowledged,
  cursors do not exceed the remote head, and projected items form the checkpoint
  prefix. The SQLite outbox requires an event to be pushed before acknowledging
  it and keeps its first remote sequence on retries. The model still assumes
  the remote acknowledgement is truthful; REST and gRPC callers validate cursor
  bounds against the stream head.
- [Commitment chain model](tla/CommitmentChain.tla): idempotent commitment
  creation preserves contiguous, non-overlapping sequence ranges and chains
  every previous state root to the next entry.
- [Leadership and finality model](tla/LeaderFinality.tla): session-lock ownership,
  a delayed worker after lease loss, reorg before finality, and confirmation by
  block depth. It checks that local finalization follows sufficient observed
  chain depth. It assumes reorgs beyond the configured depth do not occur; it
  does not prove exactly one external submission.
- [x402 settlement model](tla/X402Settlement.tla): nonce reservation, batch
  construction, idempotent settlement, and partial failure. TLC checks that
  successful and failed intent amounts partition each committed asset total.
  Amounts are mathematical naturals; the Rust commit path uses checked `u64`
  addition and rejects an overflowing batch transaction.
- [Authorization isolation model](tla/AuthorizationIsolation.tla): two tenants,
  two stores, a bootstrap administrator, an agent, permission attenuation,
  administrator grants, and request outcomes. TLC checks that every effect was
  authorized at the time of the request. REST and gRPC both require admin
  permission for the nil-tenant bootstrap exception.
- [Crash recovery model](tla/CrashRecovery.tla): interrupted ingest and
  projection transactions, restart, outbox push, and acknowledgement. TLC
  checks that receipts and outbox rows commit with ledger events and projection
  documents commit with their checkpoint. The CI recovery drill exercises
  process crashes and a logical backup against PostgreSQL.
- [Key lifecycle model](tla/KeyLifecycle.tla): registration, rotation by a
  distinct key ID, validity windows, revocation, expiry, and stale caches. TLC
  checks accepted signatures used the authoritative status and bound scheme.
  PostgreSQL signature validation rereads lifecycle fields across nodes.
- [Migration preservation model](tla/MigrationPreservation.tla): an upgrade
  transaction may crash or commit while event IDs, receipt hashes, and roots
  remain stable. A PostgreSQL fixture upgrades a populated v13 database through
  the current migrations and compares stored bytes before and after. Migration
  024 makes the projection dead-letter table part of every fresh installation;
  `build.rs` ensures added migration files are embedded in new binaries.
- [Chain reconciliation model](tla/ChainReconciliation.tla): transaction
  replacement, receipt loss, reorg, a conflicting batch ID, and block-depth
  confirmation. TLC requires the observed transaction and inclusion block to
  match the current chain before finalization. The worker now checks both the
  receipt block and the local commitment fields against the on-chain batch.
  The registry getter exposes roots, range, count, and timestamp, but does not
  expose tenant or store ID for a stored batch; the batch ID remains the
  identity binding for those fields.
- [Shared rate limits model](tla/SharedRateLimits.tla): atomic admission across
  replicas, fixed-window rollover, and bounded active identities. Migration 025
  rejects a live-window limit mismatch between replicas.
- [Schema and policy model](tla/SchemaPolicy.tla): schema status and validation
  mode transitions, plus authoritative agent policy decisions. Latest-schema
  reads bypass the local cache so archiving on another replica takes effect.
- [Encrypted payload model](tla/EncryptedPayloadLifecycle.tla): recipient wraps,
  context binding, and key revocation. Revocation excludes a key from future
  wraps; it cannot erase access to ciphertext already obtained. Duplicate
  recipient IDs are rejected by the VES encoder and decoder.
- [Audit integrity model](tla/AuditIntegrity.tla): atomic effect and audit
  append, sequence continuity, and immutable links. Migration 026 adds a
  serialized SHA-256 chain and append-only database triggers. The model's
  atomic effect-to-audit transition is enforced for the privileged
  registries listed below by database triggers; other API call sites can still
  log after their writes. A database owner can also rewrite the chain unless its head is
  checkpointed outside PostgreSQL.
- [STARK admission model](tla/StarkAdmission.tla): only proofs with canonical
  inputs and a successful verifier result are admitted. Payload amount binding
  is either checked or explicitly recorded as prover-attested where the
  sequencer cannot inspect the payload.
  Compliance and batch validity STARK submission now always verify before
  storage. The model assumes the cryptographic verifier is sound.
- [Audit transaction model](tla/AuditTransactions.tla): crashes before commit
  leave neither effect nor audit entry; committed registry changes and audit
  entries advance together. Migration 027 installs same-transaction triggers
  on API keys, agent signing and encryption keys, encryption groups and members,
  event schemas, agent policies, rotation policies, and scheduled rotations.
  Actor-rich API entries remain supplemental. Other durable admin tables still
  need transactional coverage before claiming complete auditing.
- [Proof job model](tla/ProofJobLifecycle.tla): two workers may select the same
  event, fail, crash, or race to submit. Migration 029 records the `proved`
  job outcome in the same transaction as a `stark-compliance` proof insert;
  late failures cannot regress terminal outcomes.
- [Dead-letter claim model](tla/DeadLetterClaims.tla): retry claims have fresh
  fencing tokens, stale claims can be reclaimed, and only the current token
  can resolve or fail a retry. Migration 028 persists claim tokens. Projection
  application still relies on its own idempotent transaction boundary.
- [At-rest key rotation model](tla/AtRestKeyRotation.tla): new writes use the
  current key, old ciphertext remains readable while its key is retained, and
  retirement is safe only after all old rows are re-encrypted. The three
  `reencrypt-*` admin commands migrate rows, and `verify-key-retirement` checks
  current-key readability before old keys are removed. Writes must be quiesced
  for the final check because its snapshot excludes later rows.
- [External effect fencing model](tla/ExternalEffectFencing.tla): a stale
  worker may submit after lease loss, but a destination keyed by immutable
  batch ID admits one durable effect. This depends on the deployed contracts'
  duplicate-batch guard and does not rule out wasted duplicate transactions.
- [Cache/reorg model](tla/CacheReorgSafety.tla): mutable anchoring status is
  read from the primary, and cached inclusion proofs are accepted only when
  their root and leaf index match the requested commitment. The model does
  not prove a chain can never reorg after a response was sent.
- [Projection discovery model](tla/ProjectionDiscovery.tla): with one worker
  slot and three streams, round-robin discovery eventually starts every stream
  if each active runner eventually releases its slot. It assumes a finite
  stream set and fair scheduler; a permanently stuck runner defeats progress.
- [Projection replay model](tla/ProjectionReplay.tla): document bytes and
  checkpoint commit as the same event prefix. A crash drops the working copy,
  and replay from the committed checkpoint cannot duplicate an event. The
  PostgreSQL worker test restarts a runner and checks its document and version.
- [Nonce retention model](tla/NonceRetention.tla): replay remains blocked after
  cleanup when retention covers the maximum validity window plus two clock
  skew margins. The repository enforces at least 87,000 seconds (24 hours plus
  two five-minute margins); the server currently retains rows for 172,800
  seconds. The model assumes node clocks remain within five minutes of the
  database clock.
- [Rolling key upgrade model](tla/RollingKeyUpgrade.tla): all nodes first gain
  the new read key, then writers may switch to it while old readers remain.
  Retirement requires every writer upgraded and all old ciphertext re-encrypted.
  Operators must quiesce
  writes for the final retirement check.
- [Contract idempotency model](tla/ContractIdempotency.tla): two workers and a
  lost local record can retry a batch, while destination storage admits only
  the first effect. `scripts/run_anchor_drill.sh` and
  `scripts/run_settlement_drill.sh` exercise local contract artifacts;
  `scripts/verify_deployed_contract_bytecode.sh` can compare configured UUPS
  implementations to those artifacts without sending a transaction.
- [Receipt encoding proof](lean/ReceiptEncoding.lean): equal fixed-width
  receipt preimage bytes imply equal tenant, store, event, sequence, and
  signing-hash fields. A Rust test checks the actual receipt hash against an
  independently computed SHA-256 vector. SHA-256 collision resistance and
  the Rust-to-Lean refinement remain assumptions.
- [Lean proof](lean/Sequencer.lean): for any event type and any stream length,
  appending a fresh event or a batch of distinct, fresh events preserves
  `head = length(events)` and event ID uniqueness. Induction extends the result
  to any finite trace of accepted single events, accepted batches, and
  unchanged steps. A second induction covers batches committed across any
  number of streams and preserves global event ID uniqueness when every new
  ID is fresh across all streams. A capacity-guarded append stays within the
  limit, and consecutive positive-sized reservations have non-overlapping
  ranges. The
  entity version proof shows that each accepted append preserves the count of
  committed events for every entity at arbitrary stream lengths. A separate
  proof rules out a two-writer command lock cycle for arbitrary ordered keys.
  Lean also proves inclusion-path soundness for an abstract binary Merkle tree,
  injectivity of the optional-control presence encoding, and conservation of
  arbitrary natural-number amounts per asset when a payment batch is partitioned
  into settled and failed intents. It also proves that any finite sequence of
  serialized rate-limit takes stays within its quota, and that appending an
  audit record alongside an effect preserves equal counts and the next sequence
  number. It further proves that removing an unused at-rest key preserves
  readability and that any finite sequence of idempotent destination submits
  records at most one effect. These pure proofs assume the corresponding Rust
  encoders and hash functions implement the abstract operations.

These are proofs about an abstraction. They depend on the Rust ingest paths
continuing to use one transaction for event inserts and counter updates,
locking the per-stream counter before assignment, and handling insert conflicts
without advancing the head. The VES path also commits receipts in that
transaction. The PostgreSQL uniqueness constraints on event ID and
`(tenant_id, store_id, sequence_number)` support the abstraction.
The initial model state assumes an empty, consistent stream; when modeling an
existing database, its counter must match its committed event count.

The modeled counter locks, capacity checks, conditional inserts, and commits
correspond to `src/infra/postgres/sequencer.rs` and
`src/infra/postgres/ves_sequencer.rs`. Database integration checks in
`tests/postgres_integration_test.rs` exercise concurrent ingest, duplicate IDs,
partial batch rejection, exact replay, randomized multi-stream sequencing, concurrent range
reservations, version conflicts, overlapping command ID batches, and the
cross-stream event ID collision against PostgreSQL. The same suite checks
commitment range starts, retries, root chaining, pending-anchor recording, and
reorg clearing. SQLite outbox tests check acknowledgement bounds, and the
`x402_integration_test.rs` suite checks partial settlement and atomic rejection
  of overflowing totals. Shared RFC 8785 vectors in
  `tests/vectors/ves_enc_1_test_vectors.json` check Rust and Python
  canonicalization and payload hashes against the same expected bytes. The
  salted hash vector exercises Rust's encrypted-payload hash path; Python
  checks the specified preimage directly. The file's full-encryption and AEAD
  examples still contain descriptive placeholders. These tests check that
  the implementation continues to follow the model assumptions;
the formal models do not replace them.

The models do not cover cryptographic primitive security, receipt hash
contents, arbitrary process recovery schedules, PostgreSQL internals, or a
chain reorg after local finalization. Chain field checks assume the deployed
registry implements the ABI declared in `src/anchor.rs`. The
ingest gap-free property assumes `sequence()` is not used on the same stream;
the reservation model checks its distinct allocation contract. TLC checks
finite configurations. Lean proves the stated append rule for arbitrary lengths,
but does not prove a refinement from Rust or SQL to that rule.

## Run

Lean 4.15.0 is pinned in `lean-toolchain`. From the repository root:

```sh
cd formal
lake build
```

Download the official TLA+ 1.7.4 `tla2tools.jar` and run TLC from the model
directory:

```sh
cd formal/tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config SequencerIngest.cfg SequencerIngest.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config SequencerTransactions.cfg SequencerTransactions.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config SequencerReservations.cfg SequencerReservations.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config VesReplay.cfg VesReplay.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config EntityVersions.cfg EntityVersions.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config CommandLockOrder.cfg CommandLockOrder.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config CommandReservationRace.cfg CommandReservationRace.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config IngestSqlRefinement.cfg IngestSqlRefinement.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config SyncAndProjection.cfg SyncAndProjection.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config CommitmentChain.cfg CommitmentChain.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config LeaderFinality.cfg LeaderFinality.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config X402Settlement.cfg X402Settlement.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config AuthorizationIsolation.cfg AuthorizationIsolation.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config CrashRecovery.cfg CrashRecovery.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config KeyLifecycle.cfg KeyLifecycle.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config MigrationPreservation.cfg MigrationPreservation.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config ChainReconciliation.cfg ChainReconciliation.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config SharedRateLimits.cfg SharedRateLimits.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config SchemaPolicy.cfg SchemaPolicy.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config EncryptedPayloadLifecycle.cfg EncryptedPayloadLifecycle.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config AuditIntegrity.cfg AuditIntegrity.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config StarkAdmission.cfg StarkAdmission.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config AuditTransactions.cfg AuditTransactions.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config ProofJobLifecycle.cfg ProofJobLifecycle.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config DeadLetterClaims.cfg DeadLetterClaims.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config AtRestKeyRotation.cfg AtRestKeyRotation.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config ExternalEffectFencing.cfg ExternalEffectFencing.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config CacheReorgSafety.cfg CacheReorgSafety.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config ProjectionDiscovery.cfg ProjectionDiscovery.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config ProjectionReplay.cfg ProjectionReplay.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config NonceRetention.cfg NonceRetention.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config RollingKeyUpgrade.cfg RollingKeyUpgrade.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -config ContractIdempotency.cfg ContractIdempotency.tla
```

The `formal` CI job runs all thirty-five checks. TLC writes temporary state files
under `formal/tla/states/`, which Git ignores.

For destination idempotency, run the owned local EVM drills with the compiled
`set/contracts/out_ar` artifacts:

```sh
bash scripts/run_anchor_drill.sh
bash scripts/run_settlement_drill.sh
```

To bind those artifact assumptions to configured deployed UUPS proxies, set
`ANCHOR_RPC_URL`, `SET_REGISTRY_ADDRESS`, `SETTLEMENT_RPC_URL`, and
`SET_PAYMENT_BATCH_ADDRESS`, then run
`bash scripts/verify_deployed_contract_bytecode.sh`. This check reads chain
storage and runtime code, verifies proxy bytes and resolves compiler-reported
UUPS immutable address slots before comparing implementation bytes. It sends
no transaction. A later proxy upgrade
requires another check. The local drills use disposable Anvil chains and do
not establish behavior of an uninspected production deployment.
