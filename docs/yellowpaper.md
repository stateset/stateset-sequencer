# StateSet Sequencer: Technical Specification

**Yellow Paper v0.2.6 | March 2026**

---

## Abstract

This document is the formal technical specification of the StateSet Sequencer, a deterministic event ordering service implementing the Verifiable Event Sync (VES) v1.0 protocol. It defines the state machine, cryptographic constructions, ordering algorithms, commitment scheme, and zero-knowledge proof integration at a level of precision sufficient for independent reimplementation. Where the companion whitepaper describes *what* the sequencer does and *why*, this yellow paper specifies *how* — with formal notation, algorithm pseudocode, and exact byte-level encodings.

---

## Table of Contents

1. [Notation and Conventions](#1-notation-and-conventions)
2. [System Model](#2-system-model)
3. [State Machine Specification](#3-state-machine-specification)
4. [Binary Encoding](#4-binary-encoding)
5. [Cryptographic Constructions](#5-cryptographic-constructions)
6. [Sequencing Algorithm](#6-sequencing-algorithm)
7. [Ingestion Pipeline](#7-ingestion-pipeline)
8. [Merkle Commitment Scheme](#8-merkle-commitment-scheme)
9. [State Root Chaining](#9-state-root-chaining)
10. [Sequencer Receipts](#10-sequencer-receipts)
11. [End-to-End Encryption (VES-ENC-1)](#11-end-to-end-encryption-ves-enc-1)
12. [On-Chain Anchoring Protocol](#12-on-chain-anchoring-protocol)
13. [Zero-Knowledge Proof System](#13-zero-knowledge-proof-system)
14. [Agent Key Management Protocol](#14-agent-key-management-protocol)
15. [Optimistic Concurrency Control](#15-optimistic-concurrency-control)
16. [Deduplication Mechanics](#16-deduplication-mechanics)
17. [Resilience Subsystems](#17-resilience-subsystems)
18. [Database Schema Specification](#18-database-schema-specification)
19. [API Surface](#19-api-surface)
20. [Security Analysis](#20-security-analysis)
21. [Performance Model](#21-performance-model)
22. [Test Vectors](#22-test-vectors)

---

## 1. Notation and Conventions

### 1.1 Symbols

| Symbol | Meaning |
|--------|---------|
| $\mathbb{B}$ | The set of bytes $\{0, 1\}^8$ |
| $\mathbb{B}^n$ | Byte string of exactly $n$ bytes |
| $\mathbb{B}^*$ | Byte string of arbitrary length |
| $\texttt{H}(m)$ | SHA-256 hash function: $\mathbb{B}^* \to \mathbb{B}^{32}$ |
| $\texttt{Sign}(sk, m)$ | Ed25519 signature: $\mathbb{B}^{32} \times \mathbb{B}^* \to \mathbb{B}^{64}$ |
| $\texttt{Verify}(pk, m, \sigma)$ | Ed25519 verification: $\mathbb{B}^{32} \times \mathbb{B}^* \times \mathbb{B}^{64} \to \{0, 1\}$ |
| $\texttt{JCS}(v)$ | RFC 8785 JSON Canonicalization: $\text{JSON} \to \mathbb{B}^*$ |
| $\|$ | Byte concatenation |
| $\texttt{U32\_BE}(n)$ | Big-endian encoding of 32-bit unsigned integer |
| $\texttt{U64\_BE}(n)$ | Big-endian encoding of 64-bit unsigned integer |
| $\texttt{ENC\_STR}(s)$ | Length-prefixed UTF-8: $\texttt{U32\_BE}(\text{len}(s)) \| \text{UTF-8}(s)$ |
| $\texttt{UUID}(id)$ | 16-byte UUID in network byte order |
| $0^{32}$ | 32 zero bytes |
| $\bot$ | Undefined / absent value |
| $[a, b]$ | Closed integer interval |

### 1.2 Type Aliases

```
Hash256      = B^32          -- SHA-256 digest
Signature64  = B^64          -- Ed25519 signature
PublicKey32   = B^32          -- Ed25519 public key
TenantId     = UUID          -- Tenant identifier
StoreId      = UUID          -- Store identifier
AgentId      = UUID          -- Agent identifier
AgentKeyId   = u32           -- Key rotation index
StreamId     = Hash256       -- Derived from (TenantId, StoreId)
SeqNum       = u64           -- Sequence number in [0, 2^63 - 1]
```

### 1.3 Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `VES_VERSION` | `1` | Protocol version |
| `MAX_SEQUENCE` | `2^63 - 1` | Maximum sequence number (i64 range) |
| `MAX_BATCH_SIZE` | `1000` | Maximum events per ingestion batch |
| `MAX_PAYLOAD_SIZE` | `1 MB` | Maximum payload bytes per event |
| `MAX_BODY_SIZE` | `10 MB` | Maximum HTTP request body |
| `MAX_ENTITY_TYPE_LEN` | `128` | Maximum entity_type string length |
| `MAX_ENTITY_ID_LEN` | `512` | Maximum entity_id string length |
| `MAX_EVENT_TYPE_LEN` | `256` | Maximum event_type string length |

---

## 2. System Model

### 2.1 Participants

The system comprises three classes of participants:

**Agents** ($A_1, A_2, \ldots, A_n$): Autonomous processes (AI agents, sensors, human-operated applications) that produce commerce events. Each agent holds an Ed25519 signing key pair $(sk_i, pk_i)$ and is identified by $(agent\_id, key\_id)$.

**Sequencer** ($S$): A centralized service that assigns canonical ordering to events. The sequencer holds its own Ed25519 key pair $(sk_S, pk_S)$ for receipt signing. In the current deployment, $S$ is operated by StateSet; the protocol is designed so that $S$'s honesty is verifiable, not assumed.

**Verifiers** ($V_1, V_2, \ldots$): Third parties (auditors, regulators, counterparties) that verify the integrity of the event log using on-chain commitments and Merkle proofs without trusting $S$.

### 2.2 Communication Model

Agents communicate with the sequencer over authenticated channels (TLS + API key / JWT / agent signature). The communication is asynchronous — agents may be intermittently connected and batch events for submission.

### 2.3 Streams

A **stream** is the fundamental unit of isolation, identified by:

$$\text{stream\_id} = \texttt{H}(\texttt{DOMAIN\_STREAM} \| \texttt{UUID}(\text{tenant\_id}) \| \texttt{UUID}(\text{store\_id}))$$

where $\texttt{DOMAIN\_STREAM} = \texttt{b"VES\_STREAM\_V1"}$.

Each stream maintains an independent, gap-free sequence counter. Events from different streams have no ordering relationship.

### 2.4 Trust Assumptions

| Property | Assumption |
|----------|------------|
| **Ordering integrity** | Verified cryptographically via commitments + on-chain anchoring |
| **Non-repudiation** | Verified via agent signatures + sequencer receipts |
| **Liveness** | Trusted (single operator); mitigated by monitoring + receipts |
| **Confidentiality** | End-to-end encryption (VES-ENC-1) for sensitive payloads |
| **Agent authenticity** | Ed25519 key registry; key compromise is out of scope |

---

## 3. State Machine Specification

### 3.1 Global State

The sequencer maintains global state $\Sigma$:

```
Sigma = {
    -- Per-stream state
    streams: Map<StreamId, StreamState>,

    -- Event store (append-only)
    events: Map<EventId, SequencedEvent>,

    -- Agent key registry
    keys: Map<(TenantId, AgentId, AgentKeyId), KeyRecord>,

    -- Commitment history
    commitments: Map<BatchId, BatchCommitment>,

    -- Entity versions (for OCC)
    entity_versions: Map<(StreamId, EntityType, EntityId), u64>,
}

StreamState = {
    head: SeqNum,               -- Current highest assigned sequence
    prev_state_root: Hash256,   -- Last committed state root
    prev_events_root: Hash256,  -- Last committed events root
}
```

### 3.2 Event Envelope

A VES v1.0 event envelope $E$ is a tuple of three field categories:

```
VesEventEnvelope = {
    -- Agent-authored (included in COMPUTE_EVENT_SIGNING_HASH, Section 5.3)
    ves_version:        u32,
    event_id:           UUID,
    tenant_id:          TenantId,
    store_id:           StoreId,
    source_agent_id:    AgentId,
    agent_key_id:       AgentKeyId,
    entity_type:        String,
    entity_id:          String,
    event_type:         String,
    created_at:         String,         -- RFC 3339
    payload_kind:       u32,            -- 0 = plaintext, 1 = encrypted
    payload:            Option<JSON>,   -- Present when payload_kind = 0
    payload_encrypted:  Option<Blob>,   -- Present when payload_kind = 1
    payload_plain_hash: Hash256,
    payload_cipher_hash: Hash256,       -- 0^32 when payload_kind = 0
    agent_signature:    Signature64,

    -- Agent-supplied transport metadata (NOT signed, affects acceptance behavior)
    command_id:         Option<UUID>,   -- Idempotency key (Section 16)
    base_version:       Option<u64>,    -- OCC version check (Section 15)

    -- Sequencer-assigned (NOT signed, set during ingestion)
    sequence_number:    Option<SeqNum>,
    sequenced_at:       Option<DateTime>,
}
```

**Transport metadata trust boundary**: `command_id` and `base_version` are agent-supplied but deliberately excluded from the signing hash. They are operational hints that control idempotency and optimistic concurrency — they affect whether an event is *accepted*, not what the event *is*. Once accepted, the event's identity is fully determined by the signed fields.

This placement means the sequencer can, in principle, manipulate these fields. This is acceptable because the sequencer is already trusted for acceptance/rejection decisions (liveness assumption, Section 2.4). If the sequencer rejects an event by altering its `command_id`, the agent can detect this via the absence of a signed receipt for the original event. Including these fields in the signing hash would prevent agents from retrying OCC failures with a corrected `base_version` while preserving the same signed event content — a common operational pattern.

### 3.3 State Transitions

The sequencer supports three state transitions:

**INGEST**: Accept a batch of events, assign sequence numbers, persist.

$$\Sigma' = \texttt{INGEST}(\Sigma, [E_1, E_2, \ldots, E_k])$$

**COMMIT**: Compute a Merkle commitment over a sequence range.

$$C = \texttt{COMMIT}(\Sigma, \text{stream\_id}, [s_{\text{start}}, s_{\text{end}}])$$

**ANCHOR**: Submit a commitment to the on-chain registry.

$$\texttt{tx\_hash} = \texttt{ANCHOR}(\Sigma, C)$$

These transitions are detailed in Sections 6-9.

---

## 4. Binary Encoding

### 4.1 Integer Encoding

All integers are encoded in **big-endian** (network byte order):

```
U32_BE(n: u32) -> B^4:
    [n >> 24, n >> 16, n >> 8, n] & 0xFF each

U64_BE(n: u64) -> B^8:
    [n >> 56, n >> 48, n >> 40, n >> 32, n >> 24, n >> 16, n >> 8, n] & 0xFF each
```

### 4.2 String Encoding

Strings are length-prefixed UTF-8:

```
ENC_STR(s: String) -> B*:
    let bytes = UTF8(s)
    return U32_BE(len(bytes)) || bytes
```

### 4.3 UUID Encoding

UUIDs are encoded as their 16-byte binary representation in network byte order (RFC 4122):

```
UUID(id) -> B^16:
    id.as_bytes()  -- 16 bytes, big-endian fields
```

### 4.4 JSON Canonicalization

Payloads are canonicalized per **RFC 8785** (JSON Canonicalization Scheme):

- Object keys sorted by **UTF-16 code unit** values (RFC 8785 Section 3.2.3). For ASCII-only keys this is equivalent to byte-order sorting, but for keys containing non-ASCII Unicode characters (e.g., `"café"` vs `"caff"`), UTF-16 sorting may differ from UTF-8 byte sorting. Implementations MUST sort by UTF-16 code units, not UTF-8 bytes.
- Input MUST conform to I-JSON constraints (RFC 7493): no duplicate keys, integers within $[-(2^{53})+1, (2^{53})-1]$, and all strings valid Unicode.
- No insignificant whitespace
- Numbers normalized per ES6 `Number.toString()` semantics
- Negative zero ($-0$) serialized as `0`
- Strings escaped per JSON specification
- Unicode characters preserved (not escaped unless control characters)

The canonical form is the UTF-8 byte representation of the canonical JSON string.

**Financial amount guidance**: JSON numbers are subject to IEEE 754 floating-point rounding, which can cause divergent JCS output across programming languages. Commerce payloads SHOULD transport high-precision monetary values as `String` fields (e.g., `"amount": "199.99"`) or as integer cents (e.g., `"amount_cents": 19999`), never as floating-point `Number` values. This avoids rounding-induced hash mismatches during cross-platform signature verification.

---

## 5. Cryptographic Constructions

### 5.1 Domain Separation

Every hash computation in VES includes a **domain separation prefix** — an ASCII byte string prepended to the hash preimage. This prevents cross-protocol collision attacks where a valid preimage in one context could be reinterpreted in another.

Fourteen domains are defined:

| Constant | Byte Literal | Section |
|----------|-------------|---------|
| `DOMAIN_PAYLOAD_PLAIN` | `b"VES_PAYLOAD_PLAIN_V1"` | 5.2 |
| `DOMAIN_PAYLOAD_AAD` | `b"VES_PAYLOAD_AAD_V1"` | 11.3 |
| `DOMAIN_PAYLOAD_CIPHER` | `b"VES_PAYLOAD_CIPHER_V1"` | 11.4 |
| `DOMAIN_RECIPIENTS` | `b"VES_RECIPIENTS_V1"` | 11.5 |
| `DOMAIN_EVENTSIG` | `b"VES_EVENTSIG_V1"` | 5.3 |
| `DOMAIN_LEAF` | `b"VES_LEAF_V1"` | 8.2 |
| `DOMAIN_PAD_LEAF` | `b"VES_PAD_LEAF_V1"` | 8.3 |
| `DOMAIN_NODE` | `b"VES_NODE_V1"` | 8.4 |
| `DOMAIN_STREAM` | `b"VES_STREAM_V1"` | 2.3 |
| `DOMAIN_RECEIPT` | `b"VES_RECEIPT_V1"` | 10 |
| `DOMAIN_STATE_ROOT` | `b"VES_STATE_ROOT_V1"` | 9 |
| `DOMAIN_VALIDITY_PROOF` | `b"STATESET_VES_VALIDITY_PROOF_HASH_V1"` | 13.2 |
| `DOMAIN_COMPLIANCE_PROOF` | `b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1"` | 13.3 |
| `DOMAIN_COMPLIANCE_POLICY` | `b"STATESET_VES_COMPLIANCE_POLICY_HASH_V1"` | 13.4 |

### 5.2 Payload Plain Hash

For plaintext events ($\text{payload\_kind} = 0$):

$$\text{payload\_plain\_hash} = \texttt{H}(\texttt{DOMAIN\_PAYLOAD\_PLAIN} \| \texttt{JCS}(\text{payload}))$$

For encrypted events ($\text{payload\_kind} = 1$), a 16-byte salt is prepended:

$$\text{payload\_plain\_hash} = \texttt{H}(\texttt{DOMAIN\_PAYLOAD\_PLAIN} \| \text{salt}_{16} \| \texttt{JCS}(\text{payload}))$$

The salt prevents **precomputation** and **cross-record matching** of low-entropy plaintext payloads. It does not provide full confidentiality: if the sequencer sees both the salt and the salted plain hash (which it does for encrypted events), it can still brute-force low-entropy plaintexts record-by-record. The salt's purpose is to ensure that two events with identical plaintext produce different `payload_plain_hash` values, preventing a passive observer from detecting content repetition across events without performing per-record work.

### 5.3 Event Signing Hash

The event signing hash binds all agent-authored fields into a single 32-byte digest:

```
COMPUTE_EVENT_SIGNING_HASH(E) -> Hash256:
    preimage =
        DOMAIN_EVENTSIG              ||      -- 15 bytes
        U32_BE(E.ves_version)        ||      --  4 bytes
        UUID(E.tenant_id)            ||      -- 16 bytes
        UUID(E.store_id)             ||      -- 16 bytes
        UUID(E.event_id)             ||      -- 16 bytes
        UUID(E.source_agent_id)      ||      -- 16 bytes
        U32_BE(E.agent_key_id)       ||      --  4 bytes
        ENC_STR(E.entity_type)       ||      -- 4 + len bytes
        ENC_STR(E.entity_id)         ||      -- 4 + len bytes
        ENC_STR(E.event_type)        ||      -- 4 + len bytes
        ENC_STR(E.created_at)        ||      -- 4 + len bytes
        U32_BE(E.payload_kind)       ||      --  4 bytes
        E.payload_plain_hash         ||      -- 32 bytes
        E.payload_cipher_hash               -- 32 bytes

    return H(preimage)
```

**Minimum preimage size** (with empty strings): $15 + 4 + (16 \times 4) + 4 + (4 \times 4) + 4 + 32 + 32 = 171$ bytes.

### 5.4 Agent Signature

The agent computes:

$$\sigma_A = \texttt{Sign}(sk_A, \texttt{COMPUTE\_EVENT\_SIGNING\_HASH}(E))$$

The agent signs the 32-byte SHA-256 digest, not the raw preimage. This is a hash-then-sign construction. Note that Ed25519 internally hashes its input with SHA-512, so the message undergoes double hashing (SHA-256 externally, then SHA-512 within Ed25519). This is cryptographically safe — the two hash functions have different output sizes and serve different purposes — but implementers must be aware that the Ed25519 "message" parameter is always the 32-byte `event_signing_hash`, never the raw event fields. Passing the wrong input will produce valid-looking signatures that fail cross-implementation verification. The test vectors in Section 22 exist precisely to catch this class of error.

**Signature uniqueness**: The sequencer MUST enforce **strict Ed25519 verification** per RFC 8032 Section 5.1.7, rejecting non-canonical signature encodings (i.e., signatures where the `S` component is not reduced modulo the group order $\ell$). Standard Ed25519 is susceptible to signature malleability — an adversary can produce a different but mathematically valid signature for the same message by adding a multiple of $\ell$ to `S`. Because the raw signature bytes are included in the Merkle leaf hash (Section 8.2), a malleated signature would change the leaf hash and thus the events root, creating an inconsistency between the agent's original signature and the committed tree. The `ed25519-dalek` v2 crate used by this implementation enforces strict verification by default, rejecting non-canonical `S` values.

### 5.5 Signature Verification

The sequencer verifies:

1. Retrieve $pk_A$ from key registry by $(E.\text{tenant\_id}, E.\text{source\_agent\_id}, E.\text{agent\_key\_id})$.
2. Check key status: must be `active`, with $\text{valid\_from} \leq \text{now} \leq \text{valid\_until}$.
3. Recompute $h = \texttt{COMPUTE\_EVENT\_SIGNING\_HASH}(E)$.
4. Verify: $\texttt{Verify}(pk_A, h, E.\text{agent\_signature}) = 1$.
5. Payload hash verification (bifurcated by `payload_kind`):

**Plaintext events** ($\text{payload\_kind} = 0$):
- The sequencer recomputes $\text{payload\_plain\_hash} = \texttt{H}(\texttt{DOMAIN\_PAYLOAD\_PLAIN} \| \texttt{JCS}(E.\text{payload}))$ from the submitted JSON payload and compares it to the agent-supplied `payload_plain_hash`. This ensures the payload matches what the agent signed.
- `payload_cipher_hash` MUST equal $0^{32}$.

**Encrypted events** ($\text{payload\_kind} = 1$):
- The sequencer does NOT have access to the plaintext and therefore cannot recompute `payload_plain_hash`. Instead, the sequencer verifies only the **ciphertext bundle integrity**: it recomputes $\text{payload\_cipher\_hash} = \texttt{H}(\texttt{DOMAIN\_PAYLOAD\_CIPHER} \| \text{nonce} \| \text{salt} \| \text{ciphertext} \| \text{tag})$ from the submitted `payload_encrypted` bundle (Section 11.7) and compares it to the agent-supplied `payload_cipher_hash`.
- The `payload_plain_hash` is accepted as-is — its correctness is guaranteed by the agent's signature over the event signing hash (which includes both `payload_plain_hash` and `payload_cipher_hash`). Tampering with `payload_plain_hash` would invalidate the signature.
- This design preserves the end-to-end encryption model: the sequencer never sees plaintext for encrypted events.

---

## 6. Sequencing Algorithm

### 6.1 Invariants

The sequencing algorithm maintains three invariants for each stream:

**INV-1 (Gap-Free)**: For a stream with head $h$, every sequence number in $[1, h]$ has exactly one assigned event.

**INV-2 (Monotonic)**: If event $E_a$ is assigned sequence $s_a$ and $E_b$ is assigned $s_b$ where $s_a < s_b$, then $E_a$ was committed to the database before $E_b$.

**INV-3 (Bounded)**: $0 \leq h \leq 2^{63} - 1$ for all streams.

**INV-4 (Batch Atomicity)**: An ingestion batch is processed within a single PostgreSQL transaction. Either all accepted events in the batch are persisted and the sequence counter is advanced, or the entire transaction is rolled back and no state changes. There are no partial batches. If the PostgreSQL transaction is killed mid-ingestion (e.g., `statement_timeout` fires at 30s), the `ROLLBACK` restores the sequence counter and event store to their pre-batch state, preserving INV-1 (gap-free).

### 6.2 Atomic Sequence Assignment

Sequence assignment uses PostgreSQL row-level locking to achieve linearizability:

```
LOCK_SEQUENCE_COUNTER(tx, tenant_id, store_id) -> SeqNum:
    -- Ensure counter row exists (idempotent)
    INSERT INTO sequence_counters (tenant_id, store_id, current_sequence)
    VALUES (tenant_id, store_id, 0)
    ON CONFLICT (tenant_id, store_id) DO NOTHING

    -- Acquire exclusive row lock
    SELECT current_sequence
    FROM sequence_counters
    WHERE tenant_id = $1 AND store_id = $2
    FOR UPDATE                    -- blocks concurrent transactions

    return current_sequence

SET_SEQUENCE_COUNTER(tx, tenant_id, store_id, new_head):
    UPDATE sequence_counters
    SET current_sequence = new_head, updated_at = NOW()
    WHERE tenant_id = $1 AND store_id = $2
```

The `FOR UPDATE` clause acquires an exclusive row lock, serializing all concurrent ingestion for the same stream. Different streams can be sequenced concurrently without contention.

### 6.3 Overflow Protection

Before assigning sequences, the algorithm verifies capacity:

```
ENSURE_CAPACITY(head: SeqNum, count: usize) -> Result<()>:
    if head > MAX_SEQUENCE:
        return Err("sequence counter exceeded maximum")
    if head + count > MAX_SEQUENCE:
        return Err("sequence counter would overflow")
    return Ok(())
```

This prevents wraparound and ensures the sequence number always fits in a signed 64-bit integer (required for PostgreSQL `BIGINT` storage).

---

## 7. Ingestion Pipeline

### 7.1 Pipeline Stages

The ingestion of a batch $B = [E_1, E_2, \ldots, E_k]$ proceeds through seven stages, all within a single PostgreSQL transaction:

```
INGEST(Sigma, B) -> (Sigma', IngestReceipt):
    -- Stage 1: Batch Validation
    assert all E in B share same (tenant_id, store_id)
    assert k <= MAX_BATCH_SIZE

    -- Stage 2: Transaction Begin + Sequence Lock
    tx = BEGIN TRANSACTION
    head = LOCK_SEQUENCE_COUNTER(tx, tenant_id, store_id)
    existing_ids = SELECT event_id FROM events WHERE event_id IN (B.event_ids)

    -- Stage 3: Per-Event Validation
    rejected = []
    candidates = []
    seen_event_ids = {}
    seen_command_ids = {}

    for E in B:
        -- Intra-batch dedup
        if E.event_id in seen_event_ids:
            rejected.push(E, DuplicateEventId)
            continue
        seen_event_ids.add(E.event_id)

        -- Cross-batch dedup
        if E.event_id in existing_ids:
            rejected.push(E, DuplicateEventId)
            continue

        -- Payload hash verification (bifurcated by payload_kind)
        if E.payload_kind == 0:   -- plaintext
            computed = H(DOMAIN_PAYLOAD_PLAIN || JCS(E.payload))
            if computed != E.payload_plain_hash:
                rejected.push(E, InvalidPayloadHash)
                continue
            if E.payload_cipher_hash != 0^32:
                rejected.push(E, InvalidPayloadHash)
                continue
        else:                     -- encrypted (payload_kind == 1)
            computed = H(DOMAIN_PAYLOAD_CIPHER || E.payload_encrypted.nonce
                         || E.payload_encrypted.salt
                         || E.payload_encrypted.ciphertext
                         || E.payload_encrypted.tag)
            if computed != E.payload_cipher_hash:
                rejected.push(E, InvalidPayloadHash)
                continue
            -- payload_plain_hash trusted via agent signature (Section 5.5)

        -- Field length validation
        if len(E.entity_type) > MAX_ENTITY_TYPE_LEN:
            rejected.push(E, SchemaValidation)
            continue

        -- Command-level dedup
        if E.command_id != nil:
            if E.command_id in seen_command_ids:
                rejected.push(E, DuplicateCommandId)
                continue
            seen_command_ids.add(E.command_id)

        candidates.push(E)

    -- Stage 4: Command ID Reservation (atomic)
    command_ids = [E.command_id for E in candidates if E.command_id != nil]
    (reserved, duplicates) = BATCH_RESERVE_COMMAND_IDS(tx, tenant_id, store_id, command_ids)

    -- Filter out events with duplicate commands
    valid = []
    for E in candidates:
        if E.command_id in duplicates:
            rejected.push(E, DuplicateCommandId)
        else:
            valid.push(E)

    -- Stage 5: Optimistic Concurrency Check + Sequencing
    ENSURE_CAPACITY(head, len(valid))
    seq_start = nil
    seq_end = nil
    accepted = 0

    for E in valid:
        if E.base_version != nil:
            current = GET_ENTITY_VERSION(tx, stream, E.entity_type, E.entity_id)
            if E.base_version != current:
                rejected.push(E, VersionConflict)
                RELEASE_COMMAND_ID(tx, E.command_id)  -- if reserved
                continue

        -- Compute candidate sequence BEFORE advancing head
        candidate_seq = head + 1
        E.sequence_number = candidate_seq
        E.sequenced_at = NOW()

        -- Stage 6: Persistence (insert-then-advance pattern)
        inserted = INSERT_EVENT(tx, E)  -- ON CONFLICT DO NOTHING
        if not inserted:
            -- Insert failed (global event_id collision). Because head
            -- has NOT been advanced, INV-1 (gap-free) is preserved.
            rejected.push(E, DuplicateEventId)
            RELEASE_COMMAND_ID(tx, E.command_id)  -- if reserved
            continue

        -- Only advance head AFTER successful insert
        head = candidate_seq
        BUMP_ENTITY_VERSION(tx, E)
        accepted += 1
        seq_start = seq_start or head
        seq_end = head

    -- Stage 7: Commit
    SET_SEQUENCE_COUNTER(tx, tenant_id, store_id, head)
    COMMIT(tx)

    return IngestReceipt {
        batch_id:               new_uuid(),
        events_accepted:        accepted,
        events_rejected:        rejected,
        assigned_sequence_start: seq_start,
        assigned_sequence_end:   seq_end,
        head_sequence:          head,
    }
```

### 7.2 Rejection Reasons

| Code | Trigger | Recoverable |
|------|---------|-------------|
| `DuplicateEventId` | `event_id` already exists in store or batch | No (idempotent) |
| `DuplicateCommandId` | `command_id` already processed | No (idempotent) |
| `InvalidPayloadHash` | Recomputed hash differs from submitted | Yes (resubmit) |
| `SchemaValidation` | Field constraints violated | Yes (fix payload) |
| `VersionConflict` | `base_version` mismatch (OCC failure) | Yes (retry with latest) |
| `Unauthorized` | Signature or auth failure | Yes (fix auth) |
| `RateLimited` | Tenant exceeded rate limit | Yes (backoff) |

### 7.3 Batch Homogeneity Constraint

All events in a single ingestion batch must share the same `(tenant_id, store_id)`. This constraint enables the single `FOR UPDATE` lock pattern — the sequencer locks exactly one counter row per batch, minimizing contention. Cross-stream batching would require multi-row locking with deadlock potential.

---

## 8. Merkle Commitment Scheme

### 8.1 Overview

A **batch commitment** is a Merkle tree computed over a contiguous range of sequenced events $[s_{\text{start}}, s_{\text{end}}]$ within a stream. The root of this tree — the **events root** — is a 32-byte fingerprint that uniquely identifies the batch contents.

### 8.2 Leaf Hash

Each sequenced event maps to exactly one Merkle leaf:

```
COMPUTE_LEAF_HASH(stream, E) -> Hash256:
    preimage =
        DOMAIN_LEAF                     ||     -- 11 bytes
        UUID(stream.tenant_id)          ||     -- 16 bytes
        UUID(stream.store_id)           ||     -- 16 bytes
        U64_BE(E.sequence_number)       ||     --  8 bytes
        E.event_signing_hash            ||     -- 32 bytes
        E.agent_signature                      -- 64 bytes

    return H(preimage)
```

**Total preimage size**: $11 + 16 + 16 + 8 + 32 + 64 = 147$ bytes (fixed).

The leaf commits to:
- **Stream identity**: prevents cross-stream leaf reuse
- **Canonical position**: prevents reordering attacks
- **Signed content**: via the event signing hash
- **Agent attribution**: via the raw signature bytes

### 8.3 Padding

The Merkle tree requires a power-of-two number of leaves. If $n$ events produce $n$ leaves and $n$ is not a power of two, the tree is padded to $2^{\lceil \log_2 n \rceil}$ leaves using a deterministic padding leaf:

$$\text{PAD\_LEAF} = \texttt{H}(\texttt{DOMAIN\_PAD\_LEAF})$$

where $\texttt{DOMAIN\_PAD\_LEAF} = \texttt{b"VES\_PAD\_LEAF\_V1"}$.

The padding leaf is a constant — it is computed once and cached. Because it uses a distinct domain prefix, it cannot collide with any real event leaf.

```
PAD_LEAVES(leaves: [Hash256], n: usize) -> [Hash256]:
    target = next_power_of_two(n)
    pad = H(DOMAIN_PAD_LEAF)
    while len(leaves) < target:
        leaves.push(pad)
    return leaves
```

### 8.4 Internal Nodes

Internal nodes are computed pairwise with domain separation:

$$\text{node\_hash}(L, R) = \texttt{H}(\texttt{DOMAIN\_NODE} \| L \| R)$$

where $\texttt{DOMAIN\_NODE} = \texttt{b"VES\_NODE\_V1"}$.

The full tree construction:

```
BUILD_MERKLE_TREE(leaves: [Hash256]) -> (Hash256, [[Hash256]]):
    assert len(leaves) is a power of two
    assert len(leaves) >= 1

    layers = [leaves]
    current = leaves

    while len(current) > 1:
        next_layer = []
        for i in 0..len(current)/2:
            left = current[2*i]
            right = current[2*i + 1]
            next_layer.push(COMPUTE_NODE_HASH(left, right))
        layers.push(next_layer)
        current = next_layer

    root = current[0]
    return (root, layers)
```

### 8.5 Inclusion Proof

An inclusion proof for leaf at index $i$ in a tree of depth $d$ consists of $d$ sibling hashes:

```
GENERATE_PROOF(layers, leaf_index, tree_depth) -> MerkleProof:
    proof_path = []
    idx = leaf_index

    for depth in 0..tree_depth:
        sibling_idx = idx XOR 1    -- flip lowest bit
        proof_path.push(layers[depth][sibling_idx])
        idx = idx >> 1             -- move to parent

    return MerkleProof {
        leaf_hash: layers[0][leaf_index],
        proof_path: proof_path,
        leaf_index: leaf_index,
    }
```

### 8.6 Proof Verification

```
VERIFY_PROOF(proof: MerkleProof, expected_root: Hash256, expected_depth: u32) -> bool:
    -- Defense-in-depth: reject proofs with unexpected path length
    if len(proof.proof_path) != expected_depth:
        return false

    current = proof.leaf_hash
    idx = proof.leaf_index

    for sibling in proof.proof_path:
        if idx & 1 == 0:       -- current is left child
            current = COMPUTE_NODE_HASH(current, sibling)
        else:                  -- current is right child
            current = COMPUTE_NODE_HASH(sibling, current)
        idx = idx >> 1

    return current == expected_root
```

The verifier MUST extract `expected_depth` directly from the `tree_depth` field of the anchored `VesBatchCommitment`, rather than deriving it from the length of the provided proof path. The `tree_depth` is computed as $\lceil \log_2(\text{leaf\_count}) \rceil$ at commitment time and stored in the commitment record. Although the `IStateSetAnchor` contract interface does not anchor `tree_depth` directly, verifiers can derive it deterministically from the anchored `eventCount` (which equals `leaf_count`): $d = \lceil \log_2(\text{eventCount}) \rceil$. Both derivations MUST produce the same value. This prevents an attacker from supplying a proof with extra or missing siblings that happens to hash to the correct root by exploiting properties of the tree structure. While such an attack would be computationally infeasible against SHA-256, the explicit length check provides defense-in-depth and produces clearer error diagnostics than a root mismatch.

**Proof size**: $32d$ bytes where $d = \lceil \log_2 n \rceil$ for $n$ events. For a batch of 1000 events, $d = 10$, yielding a 320-byte proof.

### 8.7 VES Batch Commitment

The complete commitment record:

```
VesBatchCommitment = {
    batch_id:           UUID,
    tenant_id:          TenantId,
    store_id:           StoreId,
    ves_version:        u32,
    tree_depth:         u32,
    leaf_count:         u32,          -- actual events
    padded_leaf_count:  u32,          -- padded to 2^k
    merkle_root:        Hash256,      -- events root
    prev_state_root:    Hash256,      -- state before batch
    new_state_root:     Hash256,      -- state after batch
    sequence_range:     (SeqNum, SeqNum),
    committed_at:       DateTime,
    chain_id:           Option<u32>,
    chain_tx_hash:      Option<Hash256>,
    chain_block_number: Option<u64>,
    anchored_at:        Option<DateTime>,
}
```

---

## 9. State Root Chaining

### 9.1 Purpose

State root chaining prevents the sequencer from presenting different histories to different verifiers (the **equivocation attack**). Each commitment's state root depends on the previous commitment's state root, forming a hash chain.

### 9.2 State Root Computation

```
COMPUTE_STATE_ROOT(
    tenant_id:       UUID,
    store_id:        UUID,
    prev_state_root: Hash256,
    merkle_root:     Hash256,
    sequence_start:  u64,
    sequence_end:    u64,
    leaf_count:      u32,
) -> Hash256:

    stream_id = H(DOMAIN_STREAM || UUID(tenant_id) || UUID(store_id))

    preimage =
        DOMAIN_STATE_ROOT       ||     -- 18 bytes
        stream_id               ||     -- 32 bytes
        prev_state_root         ||     -- 32 bytes
        merkle_root             ||     -- 32 bytes
        U64_BE(sequence_start)  ||     --  8 bytes
        U64_BE(sequence_end)    ||     --  8 bytes
        U32_BE(leaf_count)             --  4 bytes

    return H(preimage)
```

### 9.3 Chain Rules

A new commitment $C_{i+1}$ is valid only if:

1. $C_{i+1}.\text{prev\_state\_root} = C_i.\text{new\_state\_root}$
2. $C_{i+1}.\text{sequence\_start} = C_i.\text{sequence\_end} + 1$
3. $C_{i+1}.\text{leaf\_count} > 0$

The genesis commitment ($C_0$) uses:
- $\text{prev\_state\_root} = 0^{32}$
- $\text{sequence\_start} = 1$ (first event)

**Enforcement**: These rules are enforced at two levels:

1. **Sequencer-side** (pre-submission): The `PgVesCommitmentEngine` reads the latest commitment for the stream from PostgreSQL, verifies that the new commitment's `prev_state_root` matches and `sequence_start` is contiguous, and rejects the commitment before anchoring if either check fails. This is a safety check, not a trust boundary — a compromised sequencer could bypass it.

2. **Contract-side** (on-chain): The `IStateSetAnchor` contract maintains per-stream state (`latest_events_root`, `latest_sequence_end`) and enforces chaining rules in the `anchor()` function. Invalid submissions revert. This is the trust boundary: the chain rules hold even if the sequencer is malicious, because the contract is the final arbiter. The full contract validation logic is specified in the SET Chain contract documentation (separate from this paper). For the purposes of this specification, the contract is treated as an oracle that enforces the three rules above and reverts on violation.

### 9.4 Fork Detection

If a verifier discovers two commitments $C_a, C_b$ for the same stream where $C_a.\text{sequence\_start} = C_b.\text{sequence\_start}$ but $C_a.\text{merkle\_root} \neq C_b.\text{merkle\_root}$, this constitutes a **fork proof** — irrefutable evidence that the sequencer presented conflicting histories.

---

## 10. Sequencer Receipts

### 10.1 Receipt Hash

Upon accepting an event, the sequencer computes a receipt hash binding the event to its assigned position:

```
COMPUTE_RECEIPT_HASH(
    tenant_id:          UUID,
    store_id:           UUID,
    event_id:           UUID,
    sequence_number:    u64,
    event_signing_hash: Hash256,
) -> Hash256:

    preimage =
        DOMAIN_RECEIPT               ||     -- 14 bytes
        UUID(tenant_id)              ||     -- 16 bytes
        UUID(store_id)               ||     -- 16 bytes
        UUID(event_id)               ||     -- 16 bytes
        U64_BE(sequence_number)      ||     --  8 bytes
        event_signing_hash                  -- 32 bytes

    return H(preimage)
```

### 10.2 Receipt Signature

The sequencer signs the receipt hash with its Ed25519 key:

$$\sigma_S = \texttt{Sign}(sk_S, \texttt{COMPUTE\_RECEIPT\_HASH}(\ldots))$$

### 10.3 Receipt Object

A complete receipt returned to the agent:

```
SequencerReceipt = {
    event_id:           UUID,
    sequence_number:    SeqNum,
    receipt_hash:       Hash256,         -- Section 10.1
    sequencer_signature: Signature64,    -- Section 10.2
    sequencer_id:       UUID,            -- Identifies the signing sequencer instance
    sequencer_key_version: u32,          -- Key rotation index (monotonic)
}
```

### 10.4 Receipt Verification

Third-party verifiers validate receipts as follows:

1. Obtain the sequencer's Ed25519 public key $pk_S$ for the claimed `sequencer_id` and `sequencer_key_version`. Public keys are distributed via:
   - The `/health/detailed` endpoint (returns the current sequencer public key)
   - On-chain registration (future: sequencer key registry contract)
   - Out-of-band distribution for audit scenarios

2. Recompute the receipt hash from the receipt's `event_id`, `sequence_number`, and the event's `event_signing_hash`:
   $$h_R = \texttt{COMPUTE\_RECEIPT\_HASH}(\text{tenant\_id}, \text{store\_id}, \text{event\_id}, \text{sequence\_number}, \text{event\_signing\_hash})$$

3. Verify: $\texttt{Verify}(pk_S, h_R, \text{sequencer\_signature}) = 1$.

### 10.5 Sequencer Key Rotation

The sequencer signing key (`VES_SEQUENCER_SIGNING_KEY`) follows the same monotonic rotation pattern as agent keys (Section 14.2). The `sequencer_key_version` in each receipt identifies which key signed it. Old keys are retained for historical receipt verification. Key rotation is performed by updating the environment variable and incrementing the version — no protocol change is required.

### 10.6 Non-Repudiation

A receipt $(\text{event\_id}, \text{sequence\_number}, \text{receipt\_hash}, \sigma_S)$ serves as a **non-repudiable commitment** by the sequencer that event $\text{event\_id}$ was assigned sequence number $\text{sequence\_number}$. If the sequencer later omits this event from a batch commitment, the agent can present the receipt as evidence of censorship.

---

## 11. End-to-End Encryption (VES-ENC-1)

### 11.1 Overview

VES-ENC-1 enables agents to submit encrypted payloads that the sequencer can sequence, commit, and anchor — without ever accessing the plaintext. The sequencer verifies structural integrity through the dual-hash binding.

### 11.2 Encryption Scheme

**HPKE Suite**: The key encapsulation uses a complete HPKE suite (RFC 9180 Section 7):

| Component | Algorithm | Suite ID |
|-----------|-----------|----------|
| KEM | DHKEM(X25519, HKDF-SHA256) | `0x0020` |
| KDF | HKDF-SHA256 | `0x0001` |
| AEAD | AES-256-GCM | `0x0002` |

**Primitives**:
- **Content encryption**: AES-256-GCM (NIST SP 800-38D) with a randomly generated DEK
- **Key encapsulation**: HPKE Base mode (`mode_base = 0x00`) — each recipient's X25519 public key independently encapsulates the DEK
- **Data encryption key (DEK)**: 32 random bytes per event (CSPRNG)
- **Nonce**: 12 random bytes per event (generated independently of HPKE's internal nonce sequence; this nonce is used for the outer AES-256-GCM content encryption, while HPKE manages its own internal nonces for each key encapsulation)
- **Salt**: 16 random bytes per event (used in `payload_plain_hash` computation, Section 5.2)

### 11.3 Additional Authenticated Data (AAD)

The AAD binds the ciphertext to its event context, preventing ciphertext transplant attacks:

```
COMPUTE_AAD(E) -> Hash256:
    preimage =
        DOMAIN_PAYLOAD_AAD      ||
        UUID(E.tenant_id)       ||
        UUID(E.store_id)        ||
        UUID(E.event_id)        ||
        UUID(E.source_agent_id) ||
        ENC_STR(E.entity_type)  ||
        ENC_STR(E.entity_id)    ||
        ENC_STR(E.event_type)

    return H(preimage)
```

### 11.4 Ciphertext Bundle Hash

```
payload_cipher_hash = H(
    DOMAIN_PAYLOAD_CIPHER ||
    nonce                 ||     -- 12 bytes
    salt                  ||     -- 16 bytes
    ciphertext            ||     -- variable
    tag                          -- 16 bytes (GCM auth tag)
)
```

Note: the `payload_cipher_hash` is computed over the **content ciphertext** only, not the per-recipient HPKE encapsulations. This allows the sequencer to verify ciphertext integrity without parsing the recipient envelopes.

### 11.5 Recipient Manifest and Binding

Each encrypted event includes a list of recipient envelopes specifying who can decrypt the DEK:

```
RecipientEnvelope = {
    recipient_key_id:  B*,        -- Opaque key identifier (e.g., X25519 public key fingerprint)
    enc:               B^32,      -- HPKE encapsulated key (X25519 ephemeral public key)
    encrypted_dek:     B*,        -- HPKE-sealed DEK (AEAD ciphertext + tag)
}
```

The recipient manifest is bound to the event via `DOMAIN_RECIPIENTS`:

```
COMPUTE_RECIPIENTS_HASH(recipients: [RecipientEnvelope]) -> Hash256:
    -- Deterministic ordering: sort by recipient_key_id (lexicographic)
    sorted = SORT_BY_KEY_ID(recipients)
    preimage = DOMAIN_RECIPIENTS
    for r in sorted:
        preimage = preimage || ENC_STR(r.recipient_key_id)
                            || r.enc
                            || ENC_STR(r.encrypted_dek)
    return H(preimage)
```

The recipients hash is included as additional context in the AAD computation (Section 11.3), preventing an adversary from adding or removing recipients from an encrypted event without detection. Note: `DOMAIN_RECIPIENTS` was previously listed in the domain table (Section 5.1) but not referenced in the spec. This section defines its usage.

### 11.6 Dual-Hash Binding

Both `payload_plain_hash` and `payload_cipher_hash` are included in the event signing hash (Section 5.3). This prevents an adversary from:

- Substituting ciphertext while keeping the same plaintext hash
- Substituting plaintext while keeping the same ciphertext hash
- Replaying ciphertext from a different event

### 11.7 Encrypted Payload Wire Format

The `payload_encrypted` field in a VES event envelope carries a canonical binary bundle:

```
EncryptedPayloadBundleV1 = {
    version:           u8,        -- 0x01
    nonce:             B^12,      -- AES-256-GCM nonce
    salt:              B^16,      -- payload_plain_hash salt (Section 5.2)
    ciphertext_len:    U32_BE,
    ciphertext:        B*,        -- AES-256-GCM ciphertext
    tag:               B^16,      -- AES-256-GCM authentication tag
    recipient_count:   U16_BE,
    recipients:        [RecipientEnvelope],  -- sorted by recipient_key_id
}
```

Each `RecipientEnvelope` is serialized as:
```
    key_id_len:    U16_BE,
    key_id:        B*,
    enc:           B^32,         -- HPKE encapsulated key
    encrypted_dek_len: U16_BE,
    encrypted_dek: B*,           -- HPKE-sealed DEK
```

Implementers MUST use this exact layout. The `payload_cipher_hash` (Section 11.4) is computed over `nonce || salt || ciphertext || tag` extracted from this bundle.

### 11.8 Server-Side Encryption at Rest

Independently of VES-ENC-1, the sequencer supports transparent server-side encryption of stored payloads:

- **Algorithm**: AES-256-GCM
- **Key management**: Per-tenant keyrings loaded from environment/secrets provider
- **AAD**: Derived from event metadata (tenant, store, sequence number)
- **Modes**: `disabled`, `optional` (encrypt if key available), `required` (reject without key)
- **Key rotation**: Comma-separated keyring; newest key encrypts, all keys decrypt

---

## 12. On-Chain Anchoring Protocol

### 12.1 Contract Interface

The `IStateSetAnchor` smart contract on SET Chain L2 exposes:

```solidity
interface IStateSetAnchor {
    function anchor(
        bytes32 batchId,
        bytes32 tenantId,
        bytes32 storeId,
        bytes32 eventsRoot,
        bytes32 stateRoot,
        uint64  sequenceStart,
        uint64  sequenceEnd,
        uint32  eventCount
    ) external;

    function commitBatchWithStarkProof(
        bytes32 batchId,
        bytes32 tenantId,
        bytes32 storeId,
        bytes32 eventsRoot,
        bytes32 prevStateRoot,
        bytes32 newStateRoot,
        uint64  sequenceStart,
        uint64  sequenceEnd,
        uint32  eventCount,
        bytes32 proofHash,
        bytes32 policyHash,
        uint64  policyLimit,
        bool    allCompliant,
        uint64  proofSize,
        uint64  provingTimeMs
    ) external;

    function isAnchored(bytes32 batchId) external view returns (bool);
    function getLatestSequence(bytes32 tenantId, bytes32 storeId) external view returns (uint64);
    function verifyEventsRoot(bytes32 batchId, bytes32 eventsRoot) external view returns (bool);
    function hasStarkProof(bytes32 batchId) external view returns (bool);
    function verifyStarkProofHash(bytes32 batchId, bytes32 proofHash) external view returns (bool);
}
```

**`anchor()` vs `commitBatchWithStarkProof()` parameter asymmetry**: The simpler `anchor()` function accepts only `stateRoot` (the new state root) and does not require `prevStateRoot` as a parameter. This is intentional — the contract maintains per-stream state internally (`mapping(bytes32 => bytes32) latestStateRoot`) and derives the `prev_state_root` check from its own stored value. When `anchor()` is called, the contract verifies that its stored `latestStateRoot[streamId]` is consistent with the expected chain (via sequence contiguity), then updates it to the submitted `stateRoot`. The `commitBatchWithStarkProof()` function accepts both `prevStateRoot` and `newStateRoot` explicitly because it additionally commits the STARK proof's public inputs, which reference the state transition. In both cases, the chain rule enforcement (Section 9.3) is equivalent.

### 12.2 UUID-to-bytes32 Encoding

UUIDs (16 bytes) are zero-padded to 32 bytes for Solidity compatibility:

```
UUID_TO_BYTES32(id: UUID) -> bytes32:
    let buf = [0u8; 32]
    buf[0..16] = id.as_bytes()
    return buf
```

### 12.3 Anchoring Flow

```
ANCHOR(commitment: VesBatchCommitment) -> (Hash256, Option<u64>):
    -- Circuit breaker check
    if circuit_breaker.is_open():
        return Err("RPC endpoint unavailable")

    -- Retry with exponential backoff (blockchain preset)
    result = RETRY_WITH_PREDICATE(
        config: RetryConfig::blockchain(),
        predicate: is_retryable_anchor_error,
        action: || {
            signer = parse_private_key(SEQUENCER_PRIVATE_KEY)
            provider = build_provider(L2_RPC_URL, signer)
            contract = IStateSetAnchor::new(SET_REGISTRY_ADDRESS, provider)

            tx = contract.anchor(
                UUID_TO_BYTES32(commitment.batch_id),
                UUID_TO_BYTES32(commitment.tenant_id),
                UUID_TO_BYTES32(commitment.store_id),
                commitment.merkle_root,
                commitment.new_state_root,
                commitment.sequence_range.0,
                commitment.sequence_range.1,
                commitment.leaf_count,
            )

            receipt = tx.send().await.get_receipt().await
            return (receipt.tx_hash, receipt.block_number)
        }
    )

    -- Update circuit breaker state
    circuit_breaker.record(result)

    return result.into_result()
```

### 12.4 Retry Classification

Only transport-level errors are retried; contract reverts and nonce errors are not:

| Error Pattern | Retryable | Rationale |
|---------------|-----------|-----------|
| `timeout` | Yes | Transient network issue |
| `connection` | Yes | Transient network issue |
| `reset by peer` | Yes | Transient TCP reset |
| `failed to get receipt` | Yes | Receipt polling timeout |
| Contract revert | No | Logic error; retrying is futile |
| Nonce mismatch | No | Requires nonce management |

### 12.5 Anchoring Cost

A single `anchor()` call costs 60-80k gas on SET Chain L2 (~$0.08 at current fee levels). A `commitBatchWithStarkProof()` call costs ~120-150k gas. Both cover up to 1000 events, yielding sub-cent per-event amortized cost.

### 12.6 L2 Reorganization Handling

Layer 2 networks occasionally experience chain reorganizations where previously included blocks are dropped and replaced. If a commitment $C_i$ is anchored in block $B$ but the L2 reorgs and $B$ is orphaned, the sequencer's database will record $C_i$ as anchored while the chain does not. Subsequent commitment $C_{i+1}$ may then fail to anchor because the contract's chain state has reverted.

The sequencer mitigates reorg risk through the following protocol:

1. **Finality polling**: The anchor service does not consider a commitment "hard-finalized" until the anchoring transaction has reached L2 finality depth (configured via `ANCHOR_FINALITY_CONFIRMATIONS`, default: 6 blocks). The `anchored_at` timestamp in the database is only set after finality confirmation.

2. **Anchor state reconciliation**: On startup and periodically during operation, the anchor service calls `isAnchored(batchId)` and `getLatestSequence(tenantId, storeId)` to reconcile its local view with the on-chain state. If a locally-anchored commitment is not found on-chain, the `chain_tx_hash`, `chain_block_number`, and `anchored_at` fields are cleared, returning the commitment to the "pending" pool for re-anchoring.

3. **Chain gap recovery**: If a reorg orphans $C_i$ but $C_{i+1}$ was submitted, $C_{i+1}$ will revert because $C_i$'s state root is absent from the contract. The anchor service detects this via the revert error and re-anchors the full chain starting from the earliest orphaned commitment.

4. **Soft finality preservation**: Reorgs do not affect soft finality. Signed sequencer receipts remain valid regardless of L2 state — they prove the sequencer accepted the event, independent of on-chain anchoring. Only the transition from soft to hard finality is affected.

---

## 13. Zero-Knowledge Proof System

### 13.1 Overview

> **Implementation status**: This section describes the architectural design for zero-knowledge proof integration. The proof hash computations (Sections 13.2–13.4), data models (13.5–13.6), and storage schema are implemented. The STARK AIR (Algebraic Intermediate Representation), field choices, exact public input encoding, proof serialization format, and standalone verifier logic are not yet specified at reimplementation grade. A future revision will add these details. Until then, this section should be treated as an architectural specification, not a normative wire-level protocol.

The sequencer integrates two classes of zero-knowledge proofs built on STARK (Scalable Transparent ARgument of Knowledge) technology:

- **Validity proofs**: Batch-level proofs that all events in a commitment satisfy structural constraints
- **Compliance proofs**: Per-event proofs that a specific event satisfies a regulatory predicate

Both use the Winterfell STARK library with 128-bit conjectured security and transparent setup.

### 13.2 Validity Proof Hash

```
COMPUTE_VALIDITY_PROOF_HASH(proof_bytes: B*) -> Hash256:
    return H(DOMAIN_VALIDITY_PROOF || proof_bytes)
```

### 13.3 Compliance Proof Hash

```
COMPUTE_COMPLIANCE_PROOF_HASH(proof_bytes: B*) -> Hash256:
    return H(DOMAIN_COMPLIANCE_PROOF || proof_bytes)
```

### 13.4 Compliance Policy Hash

Policies are identified by their canonical hash:

```
COMPUTE_POLICY_HASH(policy_id: String, policy_params: JSON) -> Hash256:
    canonical = JCS({
        "policyId": policy_id,
        "policyParams": policy_params,
    })
    return H(DOMAIN_COMPLIANCE_POLICY || canonical)
```

### 13.5 Validity Proof Record

```
VesValidityProof = {
    proof_id:      UUID,
    batch_id:      UUID,          -- links to VesBatchCommitment
    tenant_id:     TenantId,
    store_id:      StoreId,
    proof_type:    String,        -- "STARK"
    proof_version: u32,
    proof:         B*,            -- binary STARK proof
    proof_hash:    Hash256,       -- DOMAIN_VALIDITY_PROOF hash
    public_inputs: Option<JSON>,
    submitted_at:  DateTime,
}
```

### 13.6 Compliance Proof Record

```
VesComplianceProof = {
    proof_id:            UUID,
    event_id:            UUID,         -- links to specific event
    tenant_id:           TenantId,
    store_id:            StoreId,
    proof_type:          String,       -- "STARK"
    proof_version:       u32,
    policy_id:           String,       -- e.g., "aml.threshold"
    policy_params:       JSON,
    policy_hash:         Hash256,
    witness_commitment:  Option<Hash256>, -- Rescue hash of witness
    proof:               B*,
    proof_hash:          Hash256,
    public_inputs:       Option<JSON>,
    submitted_at:        DateTime,
}
```

### 13.7 STARK Properties

| Property | Value |
|----------|-------|
| Security level | 128-bit conjectured |
| Setup | Transparent (no trusted ceremony) |
| Post-quantum | Yes (hash-based) |
| Proof size (compliance) | ~36 KB per single-event compliance proof |
| Proof size (validity) | ~53 KB per batch validity proof |
| Verification time | $O(\log^2 N)$ |
| Prover time | $O(N \log N)$ |

**Proof size note**: Batch validity proofs are larger in absolute bytes than single-event compliance proofs because they commit to a more complex AIR (Algebraic Intermediate Representation) covering the full Merkle tree and all leaf constraints. However, the per-event amortized cost of a batch validity proof is much lower: a 53 KB proof covering 1000 events costs ~54 bytes per event, versus 36 KB for a single event's compliance proof.

---

## 14. Agent Key Management Protocol

### 14.1 Key Record

```
KeyRecord = {
    tenant_id:     TenantId,
    agent_id:      AgentId,
    key_id:        AgentKeyId,
    public_key:    PublicKey32,
    status:        KeyStatus,        -- active | revoked
    valid_from:    DateTime,
    valid_until:   Option<DateTime>,
    revoked_at:    Option<DateTime>,
    created_at:    DateTime,
}
```

### 14.2 Key Rotation

Key rotation follows a monotonic `key_id` scheme:

1. Agent generates new key pair $(sk_{i+1}, pk_{i+1})$.
2. Agent registers $pk_{i+1}$ with `key_id = i + 1`.
3. Agent begins signing new events with `agent_key_id = i + 1`.
4. Old key $pk_i$ remains valid for verification of historical events.
5. Optionally, old key is revoked after a transition period.

### 14.3 Revocation Semantics

When a key is revoked at time $t_r$:
- Events signed with this key and `sequenced_at < t_r` remain valid.
- Events signed with this key and `sequenced_at >= t_r` are rejected.

This prevents retroactive invalidation of already-sequenced events.

### 14.4 Key Lookup Cache

The key registry uses an LRU cache for performance:

```
KEY_LOOKUP(tenant_id, agent_id, key_id) -> Option<KeyRecord>:
    -- Check LRU cache first
    cache_key = (tenant_id, agent_id, key_id)
    if cache.contains(cache_key):
        record = cache.get(cache_key)
        -- Stale revocation check: cached active key may have been revoked
        if record.status == active AND cache_age(cache_key) > KEY_CACHE_TTL:
            -- Refresh from DB to pick up revocations
            record = DB_LOOKUP(tenant_id, agent_id, key_id)
            cache.insert(cache_key, record)  -- update with fresh data
        return record

    -- Database lookup
    record = SELECT * FROM agent_signing_keys
             WHERE tenant_id = $1 AND agent_id = $2 AND key_id = $3

    if record.is_some():
        cache.insert(cache_key, record)

    return record
```

**Revocation invalidation**: The LRU cache introduces a window during which a revoked key remains effectively active. Two mitigations are required:

1. **Write-through invalidation**: When a key is revoked via the admin API, the revocation handler MUST evict the key from the LRU cache in the same process. This eliminates the stale-cache window for same-process revocations.

2. **TTL-based refresh**: For multi-process deployments where the revoking process differs from the verifying process, cached `active` key records are refreshed from the database after `KEY_CACHE_TTL` (default: 60 seconds). This bounds the worst-case window to the TTL duration. The TTL applies only to active keys — revoked keys are cached indefinitely (they cannot become un-revoked).

---

## 15. Optimistic Concurrency Control

### 15.1 Entity Versioning

Each entity (identified by `(stream, entity_type, entity_id)`) maintains a monotonically increasing version counter. This enables agents to detect and resolve concurrent modifications.

### 15.2 OCC at Ingest Time

When an event includes a `base_version` field:

```
OCC_CHECK(tx, stream, E) -> Result<()>:
    if E.base_version is None:
        return Ok(())    -- no OCC requested

    -- Lock entity row to prevent TOCTOU race
    current = SELECT version FROM entity_versions
              WHERE (tenant_id, store_id, entity_type, entity_id) = ...
              FOR UPDATE

    actual = current.unwrap_or(0)

    if E.base_version != actual:
        return Err(VersionConflict {
            expected: E.base_version,
            actual: actual,
        })

    return Ok(())
```

### 15.3 Version Bump

After successful insertion:

```
BUMP_ENTITY_VERSION(tx, E):
    INSERT INTO entity_versions (tenant_id, store_id, entity_type, entity_id, version)
    VALUES ($1, $2, $3, $4, 1)
    ON CONFLICT (tenant_id, store_id, entity_type, entity_id)
    DO UPDATE SET version = entity_versions.version + 1, updated_at = NOW()
```

---

## 16. Deduplication Mechanics

### 16.1 Two-Level Deduplication

The sequencer provides two levels of idempotency:

**Level 1: Event ID** (`event_id: UUID`)
- Globally unique per event
- Enforced by `PRIMARY KEY (event_id)` on the events table
- Submitting the same `event_id` twice: the `INSERT ... ON CONFLICT DO NOTHING` silently skips the duplicate, and the event is reported as rejected with `DuplicateEventId` in the ingest receipt. The API does not distinguish between "same content" and "different content" duplicates — both are rejected identically. This is safe because the original event's signed content is immutable once persisted, and the agent can retrieve it by `event_id` if needed

**Level 2: Command ID** (`command_id: Option<UUID>`)
- A per-event idempotency key representing a higher-level intent (e.g., "place order ORD-001")
- Each `command_id` maps to exactly one event within a stream: the `event_command_dedupe` table enforces `PRIMARY KEY (tenant_id, store_id, command_id)`, meaning a given command ID can only be successfully reserved once per stream
- Submitting a batch containing two events with the same `command_id` will accept the first and reject the second as `DuplicateCommandId`
- Reservations are atomic: `BATCH_RESERVE_COMMAND_IDS` uses `INSERT ... ON CONFLICT DO NOTHING` with `RETURNING`
- If an agent needs to associate multiple events with a single business operation, each event should carry a distinct `command_id` (e.g., `ORD-001-item-1`, `ORD-001-item-2`), while sharing a common `entity_id` for correlation

### 16.2 Command ID Reservation

```
BATCH_RESERVE_COMMAND_IDS(tx, tenant_id, store_id, ids: [UUID]) -> (reserved, duplicates):
    reserved = []
    duplicates = []

    for id in ids:
        result = INSERT INTO event_command_dedupe (tenant_id, store_id, command_id)
                 VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING

        if result.rows_affected == 1:
            reserved.push(id)
        else:
            duplicates.push(id)

    return (reserved, duplicates)
```

### 16.3 Command ID Release

If an event with a reserved command ID is later rejected (e.g., OCC conflict), the reservation is released within the same transaction to prevent false-positive deduplication:

```
RELEASE_COMMAND_ID(tx, tenant_id, store_id, command_id):
    DELETE FROM event_command_dedupe
    WHERE tenant_id = $1 AND store_id = $2 AND command_id = $3
```

---

## 17. Resilience Subsystems

### 17.1 Circuit Breaker

The anchor service uses a circuit breaker to prevent cascading failures when the L2 RPC endpoint is unavailable:

```
CircuitBreaker = {
    state: Closed | Open | HalfOpen,
    failure_count:    u32,
    success_count:    u32,    -- in HalfOpen
    last_failure_at:  Instant,
    open_timeout:     Duration,
}

State Transitions:
    Closed -> Open:     failure_count >= failure_threshold (5)
    Open -> HalfOpen:   elapsed > open_timeout (60s)
    HalfOpen -> Closed: success_count >= success_threshold (2)
    HalfOpen -> Open:   any failure (see note below)

Configuration:
    failure_threshold:       5
    success_threshold:       2
    open_timeout:            60s
    failure_window:          120s
    half_open_max_requests:  1
    backoff_multiplier:      2.0
    max_backoff:             300s
    jitter_factor:           0.1
    slow_call_threshold:     30s
```

**HalfOpen aggressiveness tradeoff**: With `half_open_max_requests = 1`, a single transient failure during recovery resets the full 60s open timeout. This is intentionally conservative for L2 RPC endpoints where a failed probe likely indicates genuine unavailability. For flakier endpoints, operators can increase `half_open_max_requests` to allow a small failure budget (e.g., 1 failure out of 3 probes) before re-opening. The exponential `backoff_multiplier` (2.0x, capped at 300s) ensures that even with aggressive re-opening, the system does not hammer a recovering endpoint.

### 17.2 Retry with Exponential Backoff

Four preset configurations are defined:

| Preset | Max Retries | Initial Delay | Max Delay | Multiplier | Jitter |
|--------|-------------|---------------|-----------|------------|--------|
| `fast()` | 3 | 10ms | 100ms | 2.0 | 0.1 |
| `database()` | 5 | 50ms | 5s | 2.0 | 0.2 |
| `external_service()` | 5 | 200ms | 30s | 2.0 | 0.3 |
| `blockchain()` | 7 | 1s | 60s | 2.0 | 0.2 |

Delay formula with decorrelated jitter:

$$d_i = \min(\text{max\_delay}, \text{rand}(\text{initial\_delay}, d_{i-1} \times \text{multiplier}))$$

### 17.3 Pool Monitoring

The database pool monitor runs every 15 seconds (configurable via `MONITORING_INTERVAL_SECS`):

```
POOL_HEALTH_CHECK():
    stats = pool.stats()

    if stats.idle_connections == 0 AND stats.pending_acquires > stats.max_connections / 2:
        return PoolStatus::Critical    -- triggers 503 load-shedding

    if stats.pending_acquires > 0:
        return PoolStatus::Degraded    -- warn-level logging

    return PoolStatus::Healthy
```

### 17.4 Graceful Shutdown

The `ShutdownCoordinator` uses a `tokio::sync::broadcast` channel:

```
ShutdownCoordinator = {
    tx: broadcast::Sender<()>,
}

Components that listen:
    - HTTP server:   axum::serve().with_graceful_shutdown(signal)
    - gRPC server:   tonic::transport::Server::serve_with_shutdown(signal)
    - Pool monitor:  select! { _ = signal => break }
    - Metrics:       select! { _ = signal => break }
    - DLQ cleanup:   select! { _ = signal => break }
```

### 17.5 Dead Letter Queue

**Projections** are downstream read-model materializers that consume the sequenced event log and build derived state (e.g., current inventory levels, order status aggregates, entity version counters). Projections are an application-layer concern; their specification is outside the scope of this document. The DLQ interacts with projections at a single interface point: when a projection handler returns an error for a specific event, that event is routed to the DLQ rather than blocking the projection pipeline.

Events that fail during projection are captured in a dead letter queue (DLQ):

```
DeadLetterEntry = {
    event_id:       UUID,
    tenant_id:      TenantId,
    store_id:       StoreId,
    reason:         DeadLetterReason,
    attempt_count:  u32,
    last_attempt:   DateTime,
    next_retry_at:  DateTime,
    created_at:     DateTime,
}

DeadLetterReason = InvariantViolation
                 | InvalidStateTransition
                 | ProjectionTimeout
                 | TransientError
```

Retry behavior:
- **Initial delay**: 1 second
- **Backoff multiplier**: 2.0x per attempt
- **Max retries**: 10
- **Non-retryable reasons**: `InvariantViolation`, `InvalidStateTransition` (these indicate logic bugs, not transient failures)

The `spawn_dlq_cleanup()` background task runs on a configurable interval, retries eligible entries, and removes entries that have exceeded `max_retries`.

---

## 18. Database Schema Specification

### 18.1 Core Tables

**`sequence_counters`** — Per-stream sequence state

| Column | Type | Constraints |
|--------|------|-------------|
| `tenant_id` | `UUID` | `NOT NULL` |
| `store_id` | `UUID` | `NOT NULL` |
| `current_sequence` | `BIGINT` | `NOT NULL DEFAULT 0` |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` |

Primary key: `(tenant_id, store_id)`

**`events`** — Append-only event log (legacy, pre-VES)

| Column | Type | Constraints |
|--------|------|-------------|
| `event_id` | `UUID` | `PRIMARY KEY` |
| `command_id` | `UUID` | nullable |
| `sequence_number` | `BIGINT` | `NOT NULL` |
| `tenant_id` | `UUID` | `NOT NULL` |
| `store_id` | `UUID` | `NOT NULL` |
| `entity_type` | `VARCHAR(64)` | `NOT NULL` |
| `entity_id` | `VARCHAR(256)` | `NOT NULL` |
| `event_type` | `VARCHAR(64)` | `NOT NULL` |
| `payload_encrypted` | `BYTEA` | `NOT NULL` |
| `payload_hash` | `BYTEA` | `NOT NULL` |
| `base_version` | `BIGINT` | nullable |
| `source_agent` | `UUID` | `NOT NULL` |
| `signature` | `BYTEA` | nullable |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `sequenced_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` |

Unique constraint: `(tenant_id, store_id, sequence_number)`

Indexes:
- `(tenant_id, store_id, sequence_number)` — range queries
- `(tenant_id, store_id, entity_type, entity_id, sequence_number)` — entity history
- `(command_id) WHERE command_id IS NOT NULL` — command dedup lookup

**`payload_encrypted` column semantics**: Despite its name, this column stores the output of the server-side `PayloadEncryption` layer for *all* events, including plaintext ones. When `PAYLOAD_ENCRYPTION_MODE = disabled`, the column contains the raw JSON bytes. When encryption is enabled, it contains the AES-256-GCM ciphertext. The column is always `NOT NULL` because all payloads pass through the encryption layer (which acts as a passthrough when disabled). The naming is a legacy artifact from when the column was added specifically for encryption support.

**Legacy schema field limits**: The `events` table predates the VES v1.0 specification and uses tighter field length limits (`entity_type` `VARCHAR(64)`, `entity_id` `VARCHAR(256)`) than the `ves_events` table (`VARCHAR(128)`, `VARCHAR(512)` respectively). The VES-spec constants in Section 1.3 (`MAX_ENTITY_TYPE_LEN = 128`, `MAX_ENTITY_ID_LEN = 512`) apply to the VES API surface. Events ingested via the legacy `/api/v1/events/ingest` endpoint are subject to the narrower `events` table limits. This discrepancy is intentional — widening the legacy columns would require a schema migration on existing production tables, and the legacy API is deprecated in favor of VES ingestion.

**UUID indexing note**: The `event_id` primary key uses UUIDv4 (random). Random UUID primary keys cause B-Tree index fragmentation as the table grows, because insertions scatter across the index rather than appending sequentially. For deployments expecting > 10M events, operators SHOULD generate `event_id` values using **UUIDv7** (time-ordered, RFC 9562) or **ULID**, which preserve 128-bit uniqueness while enabling sequential insertion. The VES protocol does not mandate a UUID version — any valid UUID is accepted.

**`ves_events`** — VES v1.0 event envelopes

| Column | Type | Constraints |
|--------|------|-------------|
| `event_id` | `UUID` | `PRIMARY KEY` |
| `ves_version` | `INTEGER` | `NOT NULL` |
| `tenant_id` | `UUID` | `NOT NULL` |
| `store_id` | `UUID` | `NOT NULL` |
| `source_agent_id` | `UUID` | `NOT NULL` |
| `agent_key_id` | `INTEGER` | `NOT NULL` |
| `entity_type` | `VARCHAR(128)` | `NOT NULL` |
| `entity_id` | `VARCHAR(512)` | `NOT NULL` |
| `event_type` | `VARCHAR(256)` | `NOT NULL` |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL` |
| `created_at_str` | `TEXT` | `NOT NULL` |
| `payload_kind` | `INTEGER` | `NOT NULL` |
| `payload` | `JSONB` | nullable |
| `payload_encrypted` | `BYTEA` | nullable |
| `payload_plain_hash` | `BYTEA` | `NOT NULL` |
| `payload_cipher_hash` | `BYTEA` | `NOT NULL` |
| `agent_signature` | `BYTEA` | `NOT NULL` |
| `event_signing_hash` | `BYTEA` | nullable (cached) |
| `sequence_number` | `BIGINT` | nullable (assigned by sequencer) |
| `sequenced_at` | `TIMESTAMPTZ` | nullable |
| `command_id` | `UUID` | nullable |
| `base_version` | `BIGINT` | nullable |

**`created_at_str` timestamp preservation**: The `created_at` field is signed by the agent as an RFC 3339 string (e.g., `"2025-12-20T17:51:10.243Z"`). PostgreSQL's `TIMESTAMPTZ` type normalizes this value, potentially altering fractional-second padding or timezone representation (e.g., `+00:00` vs `Z`). Since `COMPUTE_EVENT_SIGNING_HASH` uses the exact original string bytes (via `ENC_STR(E.created_at)`), the sequencer stores the original string literal in `created_at_str` (`NOT NULL` for VES events) to ensure hash recomputation produces identical results. When verifying signatures or computing leaf hashes, implementations MUST use `created_at_str`, not the `TIMESTAMPTZ`-normalized `created_at`.

**`entity_versions`** — OCC version tracking

| Column | Type | Constraints |
|--------|------|-------------|
| `tenant_id` | `UUID` | `NOT NULL` |
| `store_id` | `UUID` | `NOT NULL` |
| `entity_type` | `VARCHAR(128)` | `NOT NULL` |
| `entity_id` | `VARCHAR(512)` | `NOT NULL` |
| `version` | `BIGINT` | `NOT NULL DEFAULT 0` |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` |

Primary key: `(tenant_id, store_id, entity_type, entity_id)`

> **Migration note**: The production migration (`001_production_postgres.sql`) created this table with `entity_type VARCHAR(64)` and `entity_id VARCHAR(256)`. These limits predate the VES specification and are narrower than `MAX_ENTITY_TYPE_LEN` (128) and `MAX_ENTITY_ID_LEN` (512). VES events with valid field lengths can fail the OCC version bump if they exceed the legacy column widths. Operators MUST apply an `ALTER TABLE entity_versions ALTER COLUMN entity_type TYPE VARCHAR(128), ALTER COLUMN entity_id TYPE VARCHAR(512)` migration before enabling VES ingestion with OCC. A future migration will ship this change.

### 18.2 Commitment Tables

**`ves_commitments`** — Batch commitment records

| Column | Type |
|--------|------|
| `batch_id` | `UUID PRIMARY KEY` |
| `tenant_id` | `UUID NOT NULL` |
| `store_id` | `UUID NOT NULL` |
| `ves_version` | `INTEGER NOT NULL` |
| `tree_depth` | `INTEGER NOT NULL` |
| `leaf_count` | `INTEGER NOT NULL` |
| `padded_leaf_count` | `INTEGER NOT NULL` |
| `merkle_root` | `BYTEA NOT NULL` |
| `prev_state_root` | `BYTEA NOT NULL` |
| `new_state_root` | `BYTEA NOT NULL` |
| `sequence_start` | `BIGINT NOT NULL` |
| `sequence_end` | `BIGINT NOT NULL` |
| `committed_at` | `TIMESTAMPTZ NOT NULL` |
| `chain_id` | `INTEGER` |
| `chain_tx_hash` | `BYTEA` |
| `chain_block_number` | `BIGINT` |
| `anchored_at` | `TIMESTAMPTZ` |

### 18.3 Proof Tables

**`ves_validity_proofs`**

| Column | Type |
|--------|------|
| `proof_id` | `UUID PRIMARY KEY` |
| `batch_id` | `UUID NOT NULL` |
| `tenant_id` | `UUID NOT NULL` |
| `store_id` | `UUID NOT NULL` |
| `proof_type` | `TEXT NOT NULL` |
| `proof_version` | `INTEGER NOT NULL` |
| `proof` | `BYTEA NOT NULL` |
| `proof_hash` | `BYTEA NOT NULL` |
| `public_inputs` | `JSONB` |
| `submitted_at` | `TIMESTAMPTZ NOT NULL` |

**`ves_compliance_proofs`**

| Column | Type |
|--------|------|
| `proof_id` | `UUID PRIMARY KEY` |
| `event_id` | `UUID NOT NULL` |
| `tenant_id` | `UUID NOT NULL` |
| `store_id` | `UUID NOT NULL` |
| `proof_type` | `TEXT NOT NULL` |
| `proof_version` | `INTEGER NOT NULL` |
| `policy_id` | `TEXT NOT NULL` |
| `policy_params` | `JSONB NOT NULL` |
| `policy_hash` | `BYTEA NOT NULL` |
| `witness_commitment` | `BYTEA` |
| `proof` | `BYTEA NOT NULL` |
| `proof_hash` | `BYTEA NOT NULL` |
| `public_inputs` | `JSONB` |
| `submitted_at` | `TIMESTAMPTZ NOT NULL` |

### 18.4 Auth Tables

**`agent_signing_keys`**

| Column | Type |
|--------|------|
| `tenant_id` | `UUID NOT NULL` |
| `agent_id` | `UUID NOT NULL` |
| `key_id` | `INTEGER NOT NULL` |
| `public_key` | `BYTEA NOT NULL` |
| `status` | `TEXT NOT NULL` |
| `valid_from` | `TIMESTAMPTZ NOT NULL` |
| `valid_until` | `TIMESTAMPTZ` |
| `revoked_at` | `TIMESTAMPTZ` |
| `created_at` | `TIMESTAMPTZ NOT NULL` |

Primary key: `(tenant_id, agent_id, key_id)`

**`api_keys`**

| Column | Type |
|--------|------|
| `key_hash` | `BYTEA PRIMARY KEY` |
| `tenant_id` | `UUID NOT NULL` |
| `store_ids` | `UUID[]` |
| `permissions` | `JSONB NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL` |
| `expires_at` | `TIMESTAMPTZ` |
| `revoked` | `BOOLEAN NOT NULL DEFAULT FALSE` |

### 18.5 Session Configuration

Database sessions are configured with safety timeouts:

| Setting | Value | Purpose |
|---------|-------|---------|
| `statement_timeout` | `30s` | Prevent runaway queries |
| `idle_in_transaction_session_timeout` | `60s` | Prevent abandoned transactions |
| `lock_timeout` | `10s` | Prevent lock convoy buildup |

---

## 19. API Surface

### 19.1 REST Endpoints (Axum)

**Event Ingestion**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/events/ingest` | Legacy event ingestion |
| `POST` | `/api/v1/ves/events/ingest` | VES v1.0 event ingestion |

**Event Query**

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/events/:event_id` | Get event by ID |
| `GET` | `/api/v1/events` | Query events by range |
| `GET` | `/api/v1/entities/:entity_type/:entity_id/history` | Entity event stream |

**Commitments**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/ves/commitments` | Create batch commitment |
| `GET` | `/api/v1/ves/commitments/:batch_id` | Get commitment |
| `GET` | `/api/v1/ves/commitments` | List commitments |

**Proofs**

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/ves/inclusion-proofs/:event_id` | Generate inclusion proof |
| `POST` | `/api/v1/ves/validity-proofs` | Submit validity proof |
| `GET` | `/api/v1/ves/validity-proofs/:proof_id` | Get validity proof |
| `POST` | `/api/v1/ves/compliance-proofs` | Submit compliance proof |
| `GET` | `/api/v1/ves/compliance-proofs/:proof_id` | Get compliance proof |

**Schemas**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/schemas` | Register schema |
| `GET` | `/api/v1/schemas/:entity_type/:event_type` | Get schema |
| `PUT` | `/api/v1/schemas/:id` | Update schema |
| `DELETE` | `/api/v1/schemas/:id` | Delete schema |

**Agent Keys**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/agent-keys` | Register agent key |
| `GET` | `/api/v1/agent-keys/:agent_id` | List agent keys |
| `DELETE` | `/api/v1/agent-keys/:agent_id/:key_id` | Revoke key |

**Health**

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe (DB connectivity) |
| `GET` | `/health/detailed` | Component-level status |

### 19.2 gRPC Services (Tonic)

**v1 Service**

| RPC | Request | Response |
|-----|---------|----------|
| `Push` | `PushRequest` | `PushResponse` |
| `Pull` | `PullRequest` | `PullResponse` |
| `GetHead` | `GetHeadRequest` | `GetHeadResponse` |
| `GetCommitment` | `GetCommitmentRequest` | `GetCommitmentResponse` |
| `GetEntityHistory` | `GetEntityHistoryRequest` | `GetEntityHistoryResponse` |
| `GetInclusionProof` | `GetInclusionProofRequest` | `GetInclusionProofResponse` |

**v2 Sequencer Service**

| RPC | Request | Response | Notes |
|-----|---------|----------|-------|
| `Push` | `PushRequest` | `PushResponse` | Event ingestion |
| `PullEvents` | `PullEventsRequest` | `PullEventsResponse` | Filtered event retrieval |
| `GetSyncState` | `GetSyncStateRequest` | `GetSyncStateResponse` | Agent sync state |
| `GetInclusionProof` | `GetInclusionProofRequest` | `GetInclusionProofResponse` | Merkle proof |
| `GetCommitment` | `GetCommitmentRequest` | `GetCommitmentResponse` | Batch commitment |
| `GetEntityHistory` | `GetEntityHistoryRequest` | `GetEntityHistoryResponse` | Entity event stream |
| `GetHealth` | `GetHealthRequest` | `GetHealthResponse` | Health check |
| `StreamEvents` | `StreamEventsRequest` | `stream StreamEventsResponse` | Server-side streaming |
| `SyncStream` | `stream SyncRequest` | `stream SyncResponse` | Bidirectional sync |
| `SubscribeEntity` | `SubscribeEntityRequest` | `stream EntityEvent` | Entity change subscription |

**v2 KeyManagement Service**

| RPC | Request | Response |
|-----|---------|----------|
| `RegisterAgentKey` | `RegisterAgentKeyRequest` | `RegisterAgentKeyResponse` |
| `GetAgentKeys` | `GetAgentKeysRequest` | `GetAgentKeysResponse` |
| `RevokeAgentKey` | `RevokeAgentKeyRequest` | `RevokeAgentKeyResponse` |

All gRPC methods include `#[instrument(skip(self, request))]` tracing spans. String field lengths are validated on ingest: `entity_type` (128), `entity_id` (512), `event_type` (256). Filter fields validate entry counts (max 100 entries).

### 19.3 Middleware Stack

Requests pass through the following middleware in order:

```
Request
    -> RequestId (extract x-request-id or generate UUID)
    -> SecurityHeaders (X-Content-Type-Options, X-Frame-Options, Cache-Control)
    -> CORS (configurable origins, expose x-request-id/x-error-code/Retry-After)
    -> Compression (gzip)
    -> Timeout (30s default, configurable via REQUEST_TIMEOUT_SECS)
    -> RequestBodyLimit (10 MB)
    -> Tracing
    -> Auth (API key / JWT / agent signature)
    -> RateLimiting (per-tenant fixed window)
    -> Handler
```

### 19.4 Rate Limiting

The rate limiter uses a **fixed window** algorithm keyed by `tenant_id`:

```
RateLimiter = {
    entries: LRU<TenantId, WindowState>,    -- bounded, max 10,000 entries
    limit:   u32,                            -- requests per window (default: 100)
    window:  Duration,                       -- window duration (default: 60s)
}

WindowState = {
    count:        u32,
    window_start: Instant,
}

CHECK_RATE_LIMIT(tenant_id) -> Result<(), RateLimited>:
    entry = entries.get_or_insert(tenant_id)

    if elapsed(entry.window_start) >= window:
        entry.count = 0
        entry.window_start = now()

    entry.count += 1

    if entry.count > limit:
        return Err(RateLimited)    -- 429 with Retry-After: 60

    return Ok(())
```

The fixed window approach was chosen over token bucket or sliding log for its simplicity and O(1) memory per tenant. The tradeoff is that burst traffic at window boundaries can briefly exceed 2x the configured rate. For the commerce workloads this system targets, this is acceptable — the rate limit exists to prevent abuse and runaway agents, not to enforce precise QoS. The LRU eviction (max 10,000 entries) bounds memory usage for multi-tenant deployments.

### 19.5 Error Response Format

All errors include structured headers:

| Header | Condition | Value |
|--------|-----------|-------|
| `x-request-id` | Always | UUID (from request or generated) |
| `x-error-code` | 4xx errors | Machine-readable error code |
| `Retry-After` | 429 responses | `60` (seconds) |

500 errors never leak internal details to clients. The real error is logged at `ERROR` level; the client receives a generic `"Internal error"` message.

---

## 20. Security Analysis

### 20.1 Ordering Integrity

**Claim**: A verifier can detect any reordering of events after commitment.

**Proof sketch**: Each Merkle leaf includes $\texttt{U64\_BE}(\text{sequence\_number})$ in its preimage (Section 8.2). Changing an event's position changes the leaf hash, which propagates to the events root. The events root is anchored on-chain, where it is immutable. Therefore, any post-commitment reordering produces a different events root that does not match the on-chain record.

### 20.2 Event Integrity

**Claim**: A verifier can detect any modification of event content after commitment.

**Proof sketch**: The leaf hash includes `event_signing_hash`, which is a SHA-256 hash of all event fields (Section 5.3). Modifying any field changes the signing hash, which changes the leaf hash, which changes the events root. The agent signature over the signing hash provides additional binding: even if the sequencer could find a SHA-256 collision (computationally infeasible), it would need to forge the agent's Ed25519 signature.

### 20.3 Non-Repudiation

**Claim**: An agent cannot deny having produced an event after submitting it.

**Proof sketch**: The event includes the agent's Ed25519 signature over the event signing hash. The signing hash commits to the agent's identity (`source_agent_id`, `agent_key_id`) and the public key is registered in the key registry. Forging a signature requires the agent's private key.

**Claim**: The sequencer cannot deny having accepted an event after issuing a receipt.

**Proof sketch**: The receipt includes the sequencer's Ed25519 signature over a hash that binds the event ID to its assigned sequence number (Section 10). Forging this receipt requires the sequencer's private key.

### 20.4 Anti-Equivocation

**Claim**: The sequencer cannot present two different histories for the same stream.

**Proof sketch**: State root chaining (Section 9) requires each commitment to include the previous commitment's state root. The `IStateSetAnchor` contract maintains per-stream state and enforces the three chain rules defined in Section 9.3: (1) `prev_state_root` must match the last anchored `new_state_root`, (2) `sequence_start` must equal the last anchored `sequence_end + 1`, and (3) the batch must be non-empty. A fork would require two commitments with the same `sequence_start` but different events roots. The contract rejects the second submission because the first has already advanced the stream's on-chain state. The invariant holds even if the sequencer is compromised, because the contract is the enforcement boundary (see Section 9.3). Note that this guarantee applies only to anchored (hard-finalized) commitments. Between anchor points, the sequencer could theoretically present different soft-finalized views; the receipt mechanism (Section 10) provides the detection mechanism for this window. The **equivocation exposure window** is bounded by the anchoring interval — the time between successive `anchor()` transactions. This interval is operationally configurable: operators can anchor on a fixed cadence (e.g., every 60 seconds via `ANCHOR_INTERVAL_SECS`) or on a batch-size trigger (e.g., every 1000 events via `ANCHOR_BATCH_THRESHOLD`). Reducing the anchor interval shrinks the equivocation window at the cost of higher L2 gas spend. For most commerce deployments, a 60-second anchor cadence provides a practical balance between verification latency and cost.

### 20.5 Replay Protection

**Claim**: An adversary cannot replay previously accepted events.

**Proof sketch**: `event_id` uniqueness is enforced by the `PRIMARY KEY` constraint on the events table. Submitting the same `event_id` with identical content returns the existing sequence number (idempotent). Submitting the same `event_id` with different content is rejected by `ON CONFLICT DO NOTHING` (the insert fails silently, and the event is marked as a duplicate).

### 20.6 Payload Confidentiality (VES-ENC-1)

**Claim**: The sequencer cannot read encrypted payloads.

**Proof sketch**: VES-ENC-1 uses HPKE (RFC 9180) to encrypt the DEK to each recipient's X25519 public key. The sequencer does not possess any recipient's private key. The sequencer verifies structural integrity through `payload_cipher_hash` (which hashes the ciphertext, not the plaintext) and sequences the event based on metadata alone.

---

## 21. Performance Model

### 21.1 Sequencing Throughput

The critical path for sequencing is the `SELECT ... FOR UPDATE` on the sequence counter. This serializes writes per stream but allows parallel writes across different streams.

**Per-stream throughput**: Limited by PostgreSQL transaction round-trip latency. A single event incurs ~1-5ms latency; batches of up to 1000 events amortize the lock acquisition overhead. Practical per-stream throughput is 200-1000 events/second depending on batch size, network latency, and payload encryption overhead.

**Per-stream ceiling**: The `FOR UPDATE` lock is the fundamental bottleneck. A single stream cannot exceed the throughput of one serialized PostgreSQL connection. For workloads requiring > 1000 TPS on a single stream (e.g., flash sale event bursts), the recommended approach is to shard by sub-store (e.g., `store_id` per product category or warehouse zone) rather than funneling all events through a single `(tenant_id, store_id)` stream. A future optimization path would be an in-memory sequence allocator (e.g., Redis-backed or process-local) that reserves sequence number ranges and flushes to PostgreSQL asynchronously, trading strict linearizability for higher throughput.

**Cross-stream throughput**: Linear scaling with the number of concurrent streams, limited by connection pool size and database IOPS. With the default PostgreSQL pool configuration, the system supports hundreds of concurrent streams.

### 21.2 Commitment Generation

Merkle tree construction is $O(n)$ where $n$ is the number of events:
- $n$ leaf hash computations (each ~1 $\mu$s for SHA-256)
- $n - 1$ internal node computations
- Total: $\approx 2n$ hash operations

For a batch of 1000 events: ~2ms for tree construction.

### 21.3 Proof Generation

Inclusion proof generation is $O(\log n)$:
- $\log_2 n$ sibling lookups from pre-computed tree layers
- For 1000 events: 10 lookups, < 1ms

### 21.4 Anchoring Latency

On-chain anchoring latency depends on:
- L2 block time: ~2s on SET Chain
- Transaction confirmation: 1-2 blocks
- Total: 2-6s per anchor

### 21.5 Storage Costs

| Component | Size per Event | Notes |
|-----------|---------------|-------|
| Event record | ~1 KB | Compressed, encrypted payload |
| Leaf hash | 32 B | Cached in commitment |
| Commitment | ~500 B | Per batch, not per event |
| Validity proof | ~53 KB | Per batch (amortized ~54 B/event at 1000 events) |
| Compliance proof | ~36 KB | Per event (opt-in) |

---

## 22. Test Vectors

### 22.1 Event Signing Hash

**Input**:

```
ves_version:      1
tenant_id:        64527dd3-a654-4410-9327-e58a1492ce77
store_id:         91def158-819a-4461-b5c9-7759750ad157
event_id:         861910c9-7a1d-4b6f-83d6-51bbf4ae2849
source_agent_id:  80441726-74e2-430a-95ae-97ce21c6351b
agent_key_id:     1
entity_type:      "order"
entity_id:        "ORD-001"
event_type:       "order.created"
created_at:       "2025-12-20T17:51:10.243Z"
payload_kind:     0
payload_plain_hash: 0x7777c3fef466a0e9df7e07ea4ff13dc8ffbb9e487098f1b65530cdce7b6bbbe7
payload_cipher_hash: 0x0000000000000000000000000000000000000000000000000000000000000000
```

**Intermediate preimage** (220 bytes, hex):

```
5645535f4556454e545349475f5631    -- DOMAIN_EVENTSIG "VES_EVENTSIG_V1"
00000001                          -- U32_BE(ves_version = 1)
64527dd3a65444109327e58a1492ce77  -- UUID(tenant_id)
91def158819a4461b5c97759750ad157  -- UUID(store_id)
861910c97a1d4b6f83d651bbf4ae2849  -- UUID(event_id)
8044172674e2430a95ae97ce21c6351b  -- UUID(source_agent_id)
00000001                          -- U32_BE(agent_key_id = 1)
000000056f72646572                -- ENC_STR("order")
000000074f52442d303031            -- ENC_STR("ORD-001")
0000000d6f726465722e63726561746564  -- ENC_STR("order.created")
00000018323032352d31322d32305431  -- ENC_STR("2025-12-20T17:51:10.243Z")
  373a35313a31302e3234335a        --   (continued)
00000000                          -- U32_BE(payload_kind = 0)
7777c3fef466a0e9df7e07ea4ff13dc8  -- payload_plain_hash
  ffbb9e487098f1b65530cdce7b6bbbe7  --   (continued)
0000000000000000000000000000000000000000000000000000000000000000  -- payload_cipher_hash (zeros)
```

Full preimage (single line):
```
0x5645535f4556454e545349475f56310000000164527dd3a65444109327e58a1492ce7791def158819a4461b5c97759750ad157861910c97a1d4b6f83d651bbf4ae28498044172674e2430a95ae97ce21c6351b00000001000000056f72646572000000074f52442d3030310000000d6f726465722e6372656174656400000018323032352d31322d32305431373a35313a31302e3234335a000000007777c3fef466a0e9df7e07ea4ff13dc8ffbb9e487098f1b65530cdce7b6bbbe70000000000000000000000000000000000000000000000000000000000000000
```

**Expected output**:

```
event_signing_hash: 0xe970dfc9ffc285c2c0ba59be5d9c653eee2d1ae4db9b7a02ea3cd62b8e7cf92b
```

### 22.2 Canonical JSON (RFC 8785)

| Input | Canonical Output |
|-------|-----------------|
| `{"zebra": 1, "apple": 2}` | `{"apple":2,"zebra":1}` |
| `{"b": {"d": 1, "c": 2}, "a": 3}` | `{"a":3,"b":{"c":2,"d":1}}` |
| `[3, 1, 2]` | `[3,1,2]` (arrays preserve order) |
| `-0.0` | `0` |
| `1.0` | `1` |

### 22.3 Domain Prefix Bytes

| Constant | Hex Encoding |
|----------|-------------|
| `VES_EVENTSIG_V1` | `5645535f4556454e545349475f5631` |
| `VES_LEAF_V1` | `5645535f4c4541465f5631` |
| `VES_NODE_V1` | `5645535f4e4f44455f5631` |
| `VES_PAD_LEAF_V1` | `5645535f5041445f4c4541465f5631` |
| `VES_STREAM_V1` | `5645535f53545245414d5f5631` |
| `VES_RECEIPT_V1` | `5645535f524543454950545f5631` |
| `VES_STATE_ROOT_V1` | `5645535f53544154455f524f4f545f5631` |
| `VES_PAYLOAD_PLAIN_V1` | `5645535f5041594c4f41445f504c41494e5f5631` |

### 22.4 Padding Leaf

The padding leaf is a constant:

```
PAD_LEAF = SHA-256(b"VES_PAD_LEAF_V1")
         = 0xd9dd0e003ba5370a698013c48ed69c6c41d9ebc1236d44b280c52ceacfdad524
```

All implementations MUST produce this exact value. If your PAD_LEAF differs, check that the domain prefix is encoded as raw ASCII bytes (not UTF-16 or null-terminated).

### 22.5 String Encoding

```
ENC_STR("order"):
    U32_BE(5) = [0x00, 0x00, 0x00, 0x05]
    UTF-8("order") = [0x6F, 0x72, 0x64, 0x65, 0x72]
    Result: [0x00, 0x00, 0x00, 0x05, 0x6F, 0x72, 0x64, 0x65, 0x72]

ENC_STR(""):
    U32_BE(0) = [0x00, 0x00, 0x00, 0x00]
    Result: [0x00, 0x00, 0x00, 0x00]
```

### 22.6 UUID Byte Encoding

```
UUID: 64527dd3-a654-4410-9327-e58a1492ce77

UUID(id) -> B^16:
    [0x64, 0x52, 0x7D, 0xD3, 0xA6, 0x54, 0x44, 0x10,
     0x93, 0x27, 0xE5, 0x8A, 0x14, 0x92, 0xCE, 0x77]

UUID_TO_BYTES32(id) -> B^32:
    [0x64, 0x52, 0x7D, 0xD3, 0xA6, 0x54, 0x44, 0x10,
     0x93, 0x27, 0xE5, 0x8A, 0x14, 0x92, 0xCE, 0x77,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

Hex: 64527dd3a65444109327e58a1492ce7700000000000000000000000000000000
```

### 22.7 Non-ASCII JCS Test Vector

RFC 8785 sorts object keys by UTF-16 code units, which can differ from UTF-8 byte ordering for non-ASCII keys:

```
Input:  {"ö": 1, "o": 2, "A": 3}

UTF-16 code unit order:
    "A"  -> U+0041
    "o"  -> U+006F
    "ö"  -> U+00F6

Canonical output: {"A":3,"o":2,"ö":1}

Note: Under UTF-8 byte sorting, "ö" (0xC3 0xB6) would sort AFTER "o" (0x6F),
which matches UTF-16 in this case. A divergent case:

Input:  {"€": 1, "⁰": 2}

UTF-16 code unit order:
    "€"  -> U+20AC
    "⁰"  -> U+2070

Canonical output: {"⁰":2,"€":1}

Under UTF-8 bytes: "€" = [0xE2, 0x82, 0xAC], "⁰" = [0xE2, 0x81, 0xB0]
UTF-8 byte sort would put "⁰" first (0x81 < 0x82), matching UTF-16 here.
The distinction matters for characters where surrogate pairs reorder vs BMP.
```

### 22.8 Receipt Hash

Using the event from Section 22.1 with assigned sequence number 42:

```
Input:
    tenant_id:          64527dd3-a654-4410-9327-e58a1492ce77
    store_id:           91def158-819a-4461-b5c9-7759750ad157
    event_id:           861910c9-7a1d-4b6f-83d6-51bbf4ae2849
    sequence_number:    42
    event_signing_hash: 0xe970dfc9ffc285c2c0ba59be5d9c653eee2d1ae4db9b7a02ea3cd62b8e7cf92b

Preimage (102 bytes):
    5645535f524543454950545f5631      -- DOMAIN_RECEIPT "VES_RECEIPT_V1" (14 bytes)
    64527dd3a65444109327e58a1492ce77  -- UUID(tenant_id)
    91def158819a4461b5c97759750ad157  -- UUID(store_id)
    861910c97a1d4b6f83d651bbf4ae2849  -- UUID(event_id)
    000000000000002a                  -- U64_BE(42)
    e970dfc9ffc285c2c0ba59be5d9c653eee2d1ae4db9b7a02ea3cd62b8e7cf92b  -- event_signing_hash

Expected receipt_hash:
    SHA-256 of the above preimage (implementers: verify this against your implementation)
```

### 22.9 State Root

Genesis commitment state root computation:

```
Input:
    tenant_id:       64527dd3-a654-4410-9327-e58a1492ce77
    store_id:        91def158-819a-4461-b5c9-7759750ad157
    prev_state_root: 0x0000000000000000000000000000000000000000000000000000000000000000
    merkle_root:     0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    sequence_start:  1
    sequence_end:    10
    leaf_count:      10

Step 1: Compute stream_id
    stream_id = H(DOMAIN_STREAM || UUID(tenant_id) || UUID(store_id))
              = H("VES_STREAM_V1" || 64527dd3... || 91def158...)

Step 2: Compute state root
    preimage =
        DOMAIN_STATE_ROOT     ||     -- "VES_STATE_ROOT_V1" (18 bytes)
        stream_id             ||     -- 32 bytes
        prev_state_root       ||     -- 32 bytes (zeros for genesis)
        merkle_root           ||     -- 32 bytes
        U64_BE(1)             ||     --  8 bytes
        U64_BE(10)            ||     --  8 bytes
        U32_BE(10)                   --  4 bytes

    state_root = H(preimage)         -- 134-byte preimage
```

---

## Appendix A: Finality Model

VES defines two levels of finality:

| Level | Trigger | Latency | Guarantee |
|-------|---------|---------|-----------|
| **Soft finality** | Sequencer receipt | Milliseconds | Cryptographic non-repudiation via signed receipt. Sequencer has committed to this ordering. Sufficient for most commerce operations. |
| **Hard finality** | On-chain anchor | 2-6 seconds | Publicly verifiable. Third parties can independently verify without trusting the sequencer. Required for regulatory audits and cross-organizational proofs. |

## Appendix B: Configuration Parameters

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `BOOTSTRAP_ADMIN_API_KEY` | (required) | Initial admin API key |
| `JWT_SECRET` | none | HMAC secret for JWT validation |
| `AUTH_MODE` | `required` | `required` or `disabled` |
| `SCHEMA_VALIDATION_MODE` | `disabled` | `disabled`, `warn`, `strict` |
| `PAYLOAD_ENCRYPTION_MODE` | `disabled` | `disabled`, `optional`, `required` |
| `REQUEST_TIMEOUT_SECS` | `30` | HTTP request timeout |
| `RATE_LIMIT_PER_MINUTE` | `100` | Per-tenant rate limit (requests per window) |
| `MONITORING_INTERVAL_SECS` | `15` | Pool/metrics polling interval |
| `L2_RPC_URL` | none | SET Chain L2 RPC endpoint |
| `SET_REGISTRY_ADDRESS` | none | Anchor contract address |
| `SEQUENCER_PRIVATE_KEY` | none | EVM secp256k1 private key for L2 anchoring transactions |
| `L2_CHAIN_ID` | `84532001` | SET Chain chain ID |
| `VES_SEQUENCER_ID` | none | Sequencer UUID for receipts |
| `VES_SEQUENCER_SIGNING_KEY` | none | Ed25519 key for receipt signing |
| `ANCHOR_INTERVAL_SECS` | `60` | Time-based anchoring cadence |
| `ANCHOR_BATCH_THRESHOLD` | `1000` | Event-count anchoring trigger |
| `ANCHOR_FINALITY_CONFIRMATIONS` | `6` | L2 blocks before hard finality |
| `RATE_LIMIT_MAX_ENTRIES` | `10000` | LRU capacity for rate limiter |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window duration |
| `KEY_CACHE_TTL_SECS` | `60` | Agent key cache TTL for revocation refresh (Section 14.4) |

**Key type clarification**: The sequencer uses two distinct signing key types:

| Key | Algorithm | Purpose | Variable |
|-----|-----------|---------|----------|
| Anchoring key | secp256k1 (EVM) | Sign L2 `anchor()` transactions | `SEQUENCER_PRIVATE_KEY` |
| Receipt signing key | Ed25519 | Sign sequencer receipts (Section 10) | `VES_SEQUENCER_SIGNING_KEY` |

These are separate keys with different cryptographic algorithms. The anchoring key is an Ethereum-compatible secp256k1 key required by the EVM transaction signing model. The receipt signing key is an Ed25519 key consistent with the VES signature scheme used by agents.

## Appendix C: Feature Flags

| Feature | Effect |
|---------|--------|
| `grpc` | Enables tonic gRPC service alongside REST |
| `telemetry` | Enables OpenTelemetry + OTLP trace export |
| `anchoring` | Enables SET Chain L2 commitment anchoring (alloy) |
| `schema-validation` | Enables JSON Schema payload validation (jsonschema) |
| `sqlite` | Enables SQLite backend for local agent outbox |
| `encryption` | Enables AES-256-GCM + HPKE payload encryption |

## Appendix D: Migration Index

| # | File | Purpose |
|---|------|---------|
| 001 | `production_postgres.sql` | Core tables: events, sequence counters, entity versions |
| 002 | `ves_v1_tables.sql` | VES event envelopes, VES commitments |
| 003 | `constraints.sql` | Foreign keys, indexes, uniqueness constraints |
| 004 | `ves_validity_proofs.sql` | STARK validity proof storage |
| 005 | `ves_compliance_proofs.sql` | Per-event compliance proof storage |
| 006 | `key_rotation_policies.sql` | Agent key rotation schedule tracking |
| 007 | `encryption_groups.sql` | Multi-tenant encryption keyring groups |
| 008 | `command_dedupe.sql` | Command-level deduplication table |
| 009 | `api_keys.sql` | API key management (SHA-256 hashed) |
| 010 | `ves_sequence_counters.sql` | VES-specific sequence counters |
| 011 | `x402_payments.sql` | x402 payment protocol tables (see Appendix E) |
| 012 | `ves_compliance_proofs_witness_commitment.sql` | Witness commitment column |

## Appendix E: x402 Payment Protocol

The x402 payment protocol is integrated into the sequencer for on-chain payment settlement alongside event sequencing. The x402 subsystem is defined by migration `011_x402_payments.sql` and handles:

- **Multi-network support**: SET Chain (chain ID 84532001), SET Chain Testnet (84532002), Arc, Base, Ethereum, Arbitrum, Optimism
- **Payment batching**: The `x402_batch_worker` aggregates payment intents and submits them in batches for gas efficiency (max batch size: 1000, matching `MAX_BATCH_SIZE`)
- **Nonce replay protection**: Each payment intent includes a monotonic nonce per `(tenant_id, store_id)` to prevent double-settlement
- **Signature validation**: ECDSA signatures on payment intents are verified before sequencing

**Sequence counter isolation**: Payment intents use a **separate** sequence counter namespace from VES events. The VES per-stream counter (`sequence_counters` table, keyed by `(tenant_id, store_id)`) is used exclusively for VES event sequencing. Payment intents maintain their own ordering via the x402 batch worker's internal sequencing. This separation ensures that:

1. VES Merkle commitments cover a contiguous, gap-free range of VES events only — no "holes" from non-event sequenced objects
2. The gap-free invariant (INV-1, Section 6.1) applies strictly to VES event sequences
3. Payment intents can be batched and settled on independent cadences without affecting VES commitment generation

Payment intents are **not** included in VES Merkle commitments. If a payment event needs to be part of the verifiable event log (e.g., for audit purposes), the agent MUST also submit a corresponding VES event that references the payment intent. This keeps the VES commitment scheme self-contained and the x402 protocol cleanly separated.

Full x402 protocol specification is maintained separately from the VES core spec.

## Appendix F: Censorship Resistance Roadmap

The current single-sequencer deployment model trades decentralized liveness for operational simplicity. The protocol's cryptographic properties (signatures, receipts, on-chain commitments) provide *verification* guarantees even under a centralized operator, but *liveness* depends on the operator accepting and sequencing events.

The censorship resistance roadmap progresses through three phases:

**Phase 1: Backup Sequencer** (Q2 2026) — A standby sequencer monitors the primary via health probes. If the primary is unresponsive for a configurable timeout, the standby activates using the same signing key (rotated post-failover). Receipt-bearing agents can resubmit events that were accepted but not yet committed.

**Phase 2: Shared Sequencer Set** (Q3-Q4 2026) — Multiple sequencers form a committee. A lightweight consensus protocol (based on HotStuff or similar BFT protocol) determines event ordering. Any sequencer in the set can accept events, eliminating single points of liveness failure. The committee threshold (e.g., 2-of-3) determines fault tolerance.

**Phase 3: L1 Forced Inclusion** (2027+) — Agents can bypass the sequencer entirely by posting encrypted events to an L1 deposit contract on Ethereum. The sequencer is required to include these events within a bounded window (e.g., 24 hours) or forfeit a staked bond. This is the same mechanism that OP Stack rollups use to guarantee censorship resistance. Combined with the receipt mechanism, this provides the strongest liveness guarantee: if the sequencer censors, the agent can force-include on L1 and present the original receipt as evidence of prior acceptance.

---

*This specification is derived from the StateSet Sequencer v0.2.6 implementation. Cross-language test vectors are published and verified in CI to ensure byte-level compatibility between the Rust sequencer and JavaScript client agents.*
