# StateSet Sequencer: A Verifiable Event Ordering Service for Autonomous Commerce

**Version 0.2.5 | March 2026**

---

## Abstract

The StateSet Sequencer is a deterministic event ordering service that provides the cryptographic backbone for distributed commerce systems. It implements the Verifiable Event Sync (VES) v1.0 protocol — a specification for producing gap-free, Ed25519-signed, Merkle-committed event streams that can be independently audited without trusting the sequencer itself.

Where traditional message queues offer "at-least-once" delivery and hope for the best, the StateSet Sequencer offers a stronger guarantee: every commerce event — every order, shipment, inventory adjustment, and payment — receives a canonical sequence number, a cryptographic receipt, and an inclusion proof anchored to an L2 blockchain. The result is an append-only ledger of truth that AI agents, human operators, and regulatory auditors can independently verify.

This paper describes the protocol design, cryptographic primitives, ordering semantics, commitment scheme, and zero-knowledge compliance proof architecture.

---

## 1. The Problem: Trust in Distributed Commerce

Modern commerce is a multi-agent system. Orders originate from AI assistants, inventory adjustments arrive from warehouse sensors, payments settle across blockchains, and returns are processed by autonomous agents operating on behalf of merchants and customers.

These agents operate concurrently, often offline, and across organizational boundaries. Three problems emerge:

**Ordering ambiguity.** When two agents modify the same inventory item concurrently, which modification wins? Wall-clock timestamps are unreliable — agent clocks drift, and adversaries can backdate events.

**Auditability gaps.** Traditional event stores are opaque. An operator can silently reorder, drop, or duplicate events. Auditors must trust the database administrator, which is insufficient for regulated commerce (tax compliance, trade finance, cross-border customs).

**Forgery risk.** In a multi-agent system, any participant can claim to have seen or produced an event. Without cryptographic attribution, a compromised agent can forge events on behalf of another.

The StateSet Sequencer solves all three problems with a single primitive: a **verifiable, append-only event log** where every entry is signed by its author, sequenced by the service, committed into a Merkle tree, and periodically anchored on-chain.

---

## 2. Where the Sequencer Fits: Deployment Model

The StateSet Sequencer is the **shared cloud primitive** that synchronizes a fleet of local agents. To understand its role, consider the full deployment topology:

- **StateSet iCommerce** (the *brain*) is an embedded, zero-dependency commerce engine that runs locally — inside an AI agent, a warehouse sensor, or a merchant's laptop. It processes orders, manages inventory, and enforces business rules with no network dependency. It is the subject of the companion whitepaper.
- **The StateSet Sequencer** (the *central nervous system*) is a hosted service that connects those local engines. When an agent creates an event locally, that event is signed with the agent's Ed25519 key, placed in a local SQLite outbox, and pushed to the Sequencer when connectivity is available. The Sequencer assigns a canonical sequence number, issues a signed receipt, and periodically anchors batches of events to the SET Chain L2.

In the initial deployment, StateSet operates the Sequencer as a managed service. Tenants authenticate via API key or JWT and are isolated by `(tenant_id, store_id)` streams. The roadmap includes a multi-sequencer set (Section 20) and ultimately permissionless participation, but the protocol is designed to be verifiable even under a single-operator model — receipts, Merkle proofs, and on-chain commitments ensure that the operator cannot lie about the past.

### 2.1 Sequencer Economics

Agents submit events to the Sequencer at no per-event charge — sequencing and receipt issuance are included in the tenant's platform subscription. The gas cost of on-chain anchoring (Section 10) is borne by the platform and amortized across all tenants: a single `commitBatch` transaction on SET Chain costs 60-80k gas (~$0.08 at current L2 fee levels) and covers 100+ events, reducing the per-event anchoring cost to fractions of a cent. For tenants requiring dedicated anchoring cadence or custom compliance proof generation, premium tiers are available.

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          API Layer (Axum)                                │
│  POST /ves/events/ingest  │  GET /ves/commitments  │  POST /ves/proofs │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────┐
│                           Service Layer                                  │
│  VesSequencer │ CommitmentEngine │ AgentKeyRegistry │ SchemaValidator   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────┐
│                    PostgreSQL (Source of Truth)                           │
│  ves_events │ sequence_counters │ batch_commitments │ agent_keys        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
           ┌───────────────┐               ┌───────────────┐
           │ STARK Prover  │               │  SET Chain L2  │
           │ (Compliance)  │               │  (Anchoring)   │
           └───────────────┘               └───────────────┘
```

The sequencer is a Rust service built on Axum and PostgreSQL. It accepts signed event envelopes from agents, assigns monotonic sequence numbers via `SELECT FOR UPDATE`, computes Merkle commitments over event batches, and optionally anchors those commitments to the SET Chain L2 via the SetRegistry contract.

---

## 4. The VES v1.0 Protocol

VES (Verifiable Event Sync) is the wire protocol that governs how agents submit events and how the sequencer processes them. It is designed to be independently verifiable: given the on-chain commitment and the event data, any third party can recompute every hash and confirm the integrity of the log.

### 4.1 Streams

Every event belongs to a **stream** identified by `(tenant_id, store_id)` — both UUIDs. Streams are the unit of isolation: sequence numbers are monotonic per stream, commitments are chained per stream, and rate limits are enforced per stream.

### 4.2 The Event Envelope

A VES event envelope contains agent-authored fields (signed) and sequencer-assigned fields (unsigned):

| Field | Source | Purpose |
|-------|--------|---------|
| `ves_version` | Agent | Protocol version (must be `1`) |
| `event_id` | Agent | Globally unique event identifier (UUID) |
| `tenant_id`, `store_id` | Agent | Stream identity |
| `source_agent_id` | Agent | Signing agent identity |
| `agent_key_id` | Agent | Key rotation index |
| `entity_type`, `entity_id` | Agent | Commerce domain (e.g., `order`, `ORD-001`) |
| `event_type` | Agent | Domain event (e.g., `order.created`) |
| `created_at` | Agent | Agent-claimed timestamp (RFC 3339) |
| `payload_kind` | Agent | `0` = plaintext, `1` = encrypted |
| `payload` / `payload_encrypted` | Agent | Event data |
| `payload_plain_hash` | Agent | SHA-256 over domain prefix + JCS(payload) |
| `payload_cipher_hash` | Agent | SHA-256 over ciphertext bundle; **32 zero bytes for plaintext events** |
| `agent_signature` | Agent | Ed25519 signature over signing hash |
| `sequence_number` | Sequencer | Canonical ordering position |
| `sequenced_at` | Sequencer | Sequencer acceptance timestamp |

### 4.3 Supported Event Types

| Domain | Events |
|--------|--------|
| Orders | `order.created`, `order.confirmed`, `order.shipped`, `order.delivered`, `order.cancelled` |
| Inventory | `inventory.initialized`, `inventory.adjusted`, `inventory.reserved`, `inventory.released` |
| Products | `product.created`, `product.updated`, `product.deactivated` |
| Customers | `customer.created`, `customer.updated`, `customer.address_added` |
| Returns | `return.requested`, `return.approved`, `return.received`, `return.refunded` |

---

## 5. Cryptographic Design

Every hash in VES includes a domain separation prefix — an ASCII byte string prepended to the hash preimage — preventing cross-protocol collision attacks. Ten domains are defined in v1.0:

| Domain Prefix | Purpose |
|---------------|---------|
| `VES_PAYLOAD_PLAIN_V1` | Plaintext payload hash |
| `VES_PAYLOAD_AAD_V1` | Encryption AAD computation |
| `VES_PAYLOAD_CIPHER_V1` | Ciphertext bundle hash |
| `VES_RECIPIENTS_V1` | Recipient list hash |
| `VES_EVENTSIG_V1` | Event signing preimage |
| `VES_LEAF_V1` | Merkle leaf hash |
| `VES_NODE_V1` | Merkle internal node hash |
| `VES_PAD_LEAF_V1` | Merkle padding leaf |
| `VES_STREAM_V1` | Stream identifier |
| `VES_RECEIPT_V1` | Sequencer receipt hash |

### 5.1 Payload Hashing

The payload is canonicalized using RFC 8785 JSON Canonicalization Scheme (JCS), then hashed:

```
payload_plain_hash = SHA-256( "VES_PAYLOAD_PLAIN_V1" || JCS(payload) )
```

JCS eliminates the "same JSON, different bytes" problem that plagues naive hash-then-sign schemes. Monetary values are represented as strings or integer cents to avoid IEEE 754 floating-point normalization issues.

For plaintext events, `payload_cipher_hash` is 32 zero bytes. For encrypted events, both hashes are non-zero and bound into the signature (Section 6).

### 5.2 Event Signing

The agent computes a deterministic binary preimage over all signed fields:

```
signing_preimage =
    "VES_EVENTSIG_V1"         ||
    U32_BE(ves_version)       ||
    UUID(tenant_id)           ||    // 16 bytes
    UUID(store_id)            ||    // 16 bytes
    UUID(event_id)            ||    // 16 bytes
    UUID(source_agent_id)     ||    // 16 bytes
    U32_BE(agent_key_id)      ||
    ENC_STR(entity_type)      ||    // length-prefixed UTF-8
    ENC_STR(entity_id)        ||
    ENC_STR(event_type)       ||
    ENC_STR(created_at)       ||
    U32_BE(payload_kind)      ||
    payload_plain_hash        ||    // 32 bytes
    payload_cipher_hash             // 32 bytes

event_signing_hash = SHA-256(signing_preimage)
agent_signature    = Ed25519.Sign(private_key, event_signing_hash)
```

This construction ensures that every field in the envelope — including the payload hashes, creation timestamp, and entity identifiers — is cryptographically bound to the agent's identity.

### 5.3 Sequencer Verification

On receipt, the sequencer:

1. Looks up the agent's Ed25519 public key by `(tenant_id, source_agent_id, agent_key_id)`.
2. Recomputes `payload_plain_hash` from the submitted payload via JCS.
3. Recomputes `event_signing_hash` from the envelope fields.
4. Verifies: `Ed25519.Verify(public_key, event_signing_hash, agent_signature)`.

If any check fails, the event is rejected with a typed error code (`invalid_signature`, `invalid_payload_hash`, `agent_key_invalid`, etc.).

### 5.4 Sequencer Receipts

Upon accepting an event, the sequencer issues a signed receipt:

```
receipt_preimage =
    "VES_RECEIPT_V1"       ||
    UUID(tenant_id)        ||
    UUID(store_id)         ||
    UUID(event_id)         ||
    U64_BE(sequence_number)||
    event_signing_hash          // 32 bytes

receipt_hash = SHA-256(receipt_preimage)
sequencer_signature = Ed25519.Sign(sequencer_key, receipt_hash)
```

Receipts make acceptance provable: if the sequencer later censors or denies an event, the agent can present the receipt as evidence of prior acceptance. This is the foundation of non-repudiation in VES.

---

## 6. End-to-End Encryption (VES-ENC-1)

For privacy-sensitive commerce events — payment details, customer PII, pricing agreements — VES supports encrypted payloads where the sequencer can verify structural integrity and assign sequence numbers without ever seeing plaintext.

### 6.1 Encryption Scheme

VES-ENC-1 uses a hybrid encryption scheme:

- **Content encryption:** AES-256-GCM (random DEK per event)
- **Key encapsulation:** HPKE (RFC 9180) with DHKEM(X25519, HKDF-SHA256)

The encryption process:

1. Generate random `dek` (32 bytes), `nonce` (12 bytes), `salt` (16 bytes).
2. Compute `payload_aad` — a SHA-256 hash binding the event context to the ciphertext.
3. Encrypt: `(ciphertext, tag) = AES-256-GCM(dek, nonce, salt || JCS(payload), aad)`.
4. Wrap the DEK for each recipient using HPKE with their X25519 public key.
5. Compute `payload_cipher_hash` over the complete ciphertext bundle.

### 6.2 Security Properties

- **Sequencer-blind:** The sequencer sequences and commits encrypted events without accessing plaintext.
- **Context binding:** The AAD prevents ciphertext substitution between events.
- **Salt protection:** The 16-byte salt prevents dictionary attacks on low-entropy payloads.
- **Forward secrecy:** Per-event random DEKs limit exposure from key compromise.
- **Dual-hash binding:** Both `payload_plain_hash` and `payload_cipher_hash` are included in the agent signature, preventing an adversary from substituting ciphertext while keeping the same plaintext hash.

---

## 7. Ordering Semantics

### 7.1 The Canonical Clock

**The only canonical ordering primitive is `sequence_number`.** This is the core invariant of VES.

`created_at` is an agent claim — it is signed but never trusted for ordering. Agent clocks drift, and adversaries can backdate events. `sequenced_at` is a sequencer observation — useful for monitoring but not authoritative.

All state reconstruction, event replay, and consistency checks must use ascending `sequence_number`.

### 7.2 Gap-Free Guarantee

For each stream `(tenant_id, store_id)`, the sequencer assigns sequence numbers that are strictly increasing by 1 with no gaps. This is enforced atomically via PostgreSQL `SELECT FOR UPDATE` on a per-stream counter, ensuring linearizable ordering even under concurrent ingestion.

### 7.3 Finality Model

VES defines two levels of finality that agents must understand when deciding how to act on an event:

| Level | Trigger | Latency | What It Means |
|-------|---------|---------|---------------|
| **Soft finality** | Sequencer receipt returned | Milliseconds | The sequencer has committed to ordering this event. The agent holds a signed receipt (Section 5.4) that is cryptographically non-repudiable. The agent can safely proceed with its workflow — display a confirmation, trigger a downstream process, or notify a counterparty. |
| **Hard finality** | Batch anchored on SET Chain | Minutes | The event's Merkle commitment is recorded on-chain. The event is now independently verifiable by any third party without trusting the sequencer. The commitment chain (Section 9) prevents retroactive reordering. |

**Practical guidance:** For most commerce operations — displaying an order confirmation, reserving inventory, sending a shipping notification — soft finality is sufficient. The signed receipt provides strong guarantees against sequencer misbehavior. Hard finality is required for high-stakes external verification: trade finance disbursement, regulatory audit trails, cross-organizational proof of existence.

### 7.4 Exactly-Once Delivery

Events are idempotent by `event_id`. If the same `event_id` is re-submitted with identical signed content, the sequencer returns the previously assigned `sequence_number`. If the same `event_id` is submitted with different content, the sequencer rejects it. An optional `command_id` field provides intent-level deduplication for higher-level operations.

---

## 8. Merkle Commitments

Sequence numbers provide ordering. Merkle trees provide verifiability.

### 8.1 Batch Construction

A batch commitment covers a contiguous sequence range `[sequence_start, sequence_end]`. The batch defines an ordered list of events by their sequence numbers.

### 8.2 Leaf Encoding

Each event maps to a Merkle leaf:

```
leaf_preimage =
    "VES_LEAF_V1"         ||
    UUID(tenant_id)       ||
    UUID(store_id)        ||
    U64_BE(sequence_number) ||
    event_signing_hash    ||    // 32 bytes
    agent_signature             // 64 bytes

leaf_hash = SHA-256(leaf_preimage)
```

This encoding commits the leaf to: (a) stream identity, (b) canonical position, (c) the signed event content, and (d) the agent's signature bytes. Changing any field — even a single bit of the signature — produces a different leaf hash.

### 8.3 Padding and Tree Construction

The tree is padded to the next power of two using a deterministic padding leaf:

```
PAD_LEAF = SHA-256( "VES_PAD_LEAF_V1" )
```

Internal nodes are computed pairwise:

```
node_hash = SHA-256( "VES_NODE_V1" || left_child || right_child )
```

The root of this tree — the **events root** — is a 32-byte fingerprint of the entire batch.

### 8.4 Inclusion Proofs

Given an events root, any third party can verify that a specific event was included in a batch using a standard Merkle proof:

1. Recompute the leaf hash from the event data.
2. Walk the proof path, combining siblings with domain-separated hashing.
3. Confirm the result matches the committed events root.

Direction at each level is derived from the leaf index: `(leaf_index >> depth) & 1`.

---

## 9. Commitment Chaining and Anti-Equivocation

### 9.1 The Fork Problem

A dishonest sequencer could anchor two conflicting Merkle roots for the same stream — showing one history to auditors and another to merchants. VES prevents this through commitment chaining.

### 9.2 Chain Rules

Each on-chain commitment for a stream stores:

| Field | Description |
|-------|-------------|
| `stream_id` | `SHA-256("VES_STREAM_V1" \|\| tenant_id \|\| store_id)` |
| `sequence_start` | First sequence number in batch |
| `sequence_end` | Last sequence number in batch |
| `events_root` | Merkle root of the batch |
| `prev_events_root` | Previous batch's Merkle root |

A new commitment is valid only if:

1. `prev_events_root` matches the current head's `events_root`.
2. `sequence_start` equals the previous `sequence_end + 1`.
3. The batch is non-empty.

The genesis commitment uses `prev_events_root = 0x00...00` and `sequence_start = 0`.

This forces a single append-only chain per stream. Any attempt to anchor a conflicting history is rejected by the smart contract, and the fork is publicly detectable.

---

## 10. On-Chain Anchoring

The sequencer integrates with the SET Chain L2 through the SetRegistry smart contract. The flow:

```
Sequencer                      Anchor Service                  SetRegistry (L2)
    │                               │                               │
    │  Create BatchCommitment       │                               │
    │  with Merkle roots            │                               │
    │                               │                               │
    │  GET /commitments/pending ◄───│                               │
    │  Return unanchored batches    │                               │
    │                               │  commitBatch(streamId,        │
    │                               │    seqStart, seqEnd,          │
    │                               │    eventsRoot, prevRoot)  ───►│
    │                               │                               │
    │                               │  ◄── tx hash ────────────────│
    │                               │                               │
    │  POST /commitments/{id}/anchored                              │
    │  with chain_tx_hash       ◄───│                               │
```

The anchor service is a Rust daemon that polls the sequencer for pending commitments and submits them to the SetRegistry contract using an authorized sequencer key. The SetRegistry enforces the chaining rules on-chain, providing a public, immutable record of every committed batch.

---

## 11. Zero-Knowledge Compliance Proofs

### 11.1 The Compliance Paradox

Regulated commerce requires proving compliance — that tax was collected, that export controls were observed, that KYC was performed — without revealing the underlying transaction data. This is the classic tension between transparency and privacy.

### 11.2 A Concrete Example: Cross-Border VAT Compliance

A B2B purchasing agent executes a cross-border sale: a German manufacturer ships components to a French buyer. EU regulations require that the correct 20% French VAT was applied and that both parties passed AML screening. Traditionally, proving this to a regulatory auditor means handing over the full transaction — prices, identities, volumes — which the merchant considers commercially sensitive.

With VES STARKs, the agent generates a zero-knowledge proof that the transaction satisfies two predicates: (1) the applied VAT rate matches the destination jurisdiction, and (2) the counterparty's AML risk score is below the regulatory threshold. This proof is submitted to the sequencer, anchored on-chain alongside the batch commitment, and verifiable by any auditor — without revealing the supplier's identity, the buyer's identity, or the trade volume on the public ledger.

### 11.3 STARK Integration

The StateSet Sequencer integrates with a STARK proving system (built on Winterfell) to generate zero-knowledge compliance proofs:

- **Validity proofs:** Batch-level ZK proofs that all events in a commitment satisfy certain constraints (e.g., all orders have valid tax computations) without revealing the orders themselves.
- **Compliance proofs:** Per-event encrypted proofs that a specific event satisfies a compliance predicate.

Both proof types are submitted via the API and stored alongside the commitments they attest to.

STARK properties make this particularly suitable for commerce: transparent setup (no trusted ceremony), 128-bit conjectured security, post-quantum resistance (hash-based), and proof sizes of 100-200 KB with O(log^2 N) verification time.

### 11.4 API

```
POST /api/v1/ves/validity-proofs
{
    "batch_id": "uuid",
    "proof_type": "stark",
    "proof_data": "base64-encoded-proof",
    "public_inputs": { ... }
}

POST /api/v1/ves/compliance-proofs
{
    "event_id": "uuid",
    "proof_type": "stark",
    "encrypted_payload": "base64-encoded",
    "public_inputs": { ... }
}
```

---

## 12. Agent Key Management

### 12.1 Key Registry

Every agent registers Ed25519 public keys with the sequencer. Keys are indexed by `(tenant_id, agent_id, key_id)`, enabling key rotation without losing historical verification capability.

### 12.2 Key Lifecycle

- **Registration:** Agents register keys with validity windows (`valid_from`, `valid_until`).
- **Rotation:** Agents increment `agent_key_id` and register a new key. The old key remains valid for historical verification.
- **Revocation:** Keys can be revoked. The sequencer evaluates revocation against `sequenced_at` to prevent backdating attacks.

### 12.3 Public Self-Registration

Agents can self-register keys via a rate-limited public endpoint, enabling open participation while preventing Sybil attacks through per-IP rate limiting and tenant-level controls.

---

## 13. Payload Encryption at Rest

Beyond VES-ENC-1 (end-to-end encryption), the sequencer supports server-side payload encryption for data-at-rest protection:

- **AES-256-GCM** with per-tenant keyrings.
- **Key rotation** via comma-separated keyring configuration (newest key first).
- **Three modes:** `disabled`, `optional`, `required`.
- Encryption keys are never stored in the database — they are provided via environment variables or a secret manager.

---

## 14. Schema Validation

The sequencer supports JSON Schema validation of event payloads in three modes:

| Mode | Behavior |
|------|----------|
| `disabled` | No validation |
| `warn` | Log schema violations but accept events |
| `strict` | Reject events that fail schema validation |

Schemas are registered per `(entity_type, event_type)` and cached for performance. This provides defense-in-depth: even if an agent constructs a syntactically valid event, the sequencer can enforce domain-level constraints.

---

## 15. Observability

The sequencer exposes three observability surfaces:

- **Prometheus metrics** at `GET /metrics` — ingestion rates, latency histograms, error counts, queue depths.
- **Structured logging** via `tracing` with JSON format support and configurable log levels.
- **OpenTelemetry** distributed tracing with OTLP export for end-to-end request tracing across the sequencer, anchor service, and client agents.

Health and readiness probes (`GET /health`, `GET /ready`) support Kubernetes deployment.

---

## 16. Performance and Deployment

### 16.1 Database Architecture

The sequencer uses PostgreSQL as its source of truth with configurable read replicas:

- **Write pool:** Handles event ingestion and sequence assignment (atomic `SELECT FOR UPDATE`).
- **Read pool:** Routes queries, commitment reads, and proof lookups to a separate replica.
- **Connection tuning:** Configurable pool sizes, acquisition timeouts, idle timeouts, and lifetime limits.
- **Session-level controls:** Statement timeouts, idle-in-transaction timeouts, and lock timeouts prevent resource exhaustion.

### 16.2 Rate Limiting

Per-tenant rate limiting with bounded memory (LRU eviction) prevents abuse without requiring external infrastructure. Limits are configurable per-minute with separate controls for public agent registration.

### 16.3 Request Limits

| Limit | Default |
|-------|---------|
| Max body size | 10 MB |
| Max events per batch | 1,000 |
| Max payload per event | 1 MB |

### 16.4 Binary

The sequencer compiles to a single binary with `lto = true` and `codegen-units = 1` for maximum optimization. Feature flags (`grpc`, `telemetry`, `anchoring`, `schema-validation`, `sqlite`, `encryption`) allow slimming the binary for constrained deployments.

---

## 17. Cross-Platform Compatibility

VES v1.0 specifies exact byte-level encoding for every hash computation, ensuring identical outputs across implementations:

| Primitive | JavaScript (Node.js) | Rust |
|-----------|---------------------|------|
| SHA-256 | `crypto.createHash('sha256')` | `sha2::Sha256` |
| Ed25519 | `crypto.sign(null, ...)` | `ed25519_dalek` |
| UUID bytes | hex decode of stripped UUID | `Uuid::as_bytes()` |
| String encoding | `U32_BE(len) + UTF-8` | `u32_be(len) + utf8` |
| JSON canonicalization | RFC 8785 JCS | `serde_json_canonicalizer` |

Cross-language test vectors are published and verified in CI to ensure that the Rust sequencer and JavaScript CLI agents produce identical hashes for identical inputs.

---

## 18. Threat Model

### 18.1 Threats Addressed

| Threat | Mitigation |
|--------|------------|
| Event forgery | Ed25519 agent signatures + key registry |
| Event mutation | Payload hash, signature, leaf hash, and Merkle root all break |
| History forking | Commitment chaining rules enforced on-chain |
| Replay/duplication | `event_id` uniqueness + idempotent semantics |
| Payload snooping | VES-ENC-1 end-to-end encryption |
| Key compromise | Rotation via `agent_key_id`, time-bounded validity |

### 18.2 Threats Acknowledged

| Threat | Mitigation Path |
|--------|----------------|
| Sequencer censorship | Signed receipts, monitoring, multi-sequencer (roadmap) |
| Pre-anchoring manipulation | Frequent anchoring cadence, receipts |
| Agent key theft | HSM/secure enclave integration, anomaly detection |
| Sequencer key compromise | On-chain revocation via SetRegistry, key rotation |

### 18.3 Liveness and Forced Inclusion

Signed receipts prevent the sequencer from *lying about the past*, but they do not prevent the sequencer from *ignoring new events* (a liveness failure). In the current single-sequencer deployment, liveness depends on the operator. This is an explicit trust assumption — a "Web 2.5" model where the cryptographic protocol provides verification guarantees while operational liveness remains centralized.

The mitigation path is layered:

1. **Monitoring and SLOs.** Sequencer uptime is monitored via health probes and Prometheus metrics. Tenants can detect liveness failures within seconds.
2. **Signed receipts as evidence.** If a sequencer accepts an event (issues a receipt) but later fails to include it in a batch, the agent holds irrefutable proof of censorship.
3. **Multi-sequencer set (Phase 1-2).** The decentralization roadmap (Section 20) introduces backup and then shared sequencer sets, eliminating single points of liveness failure.
4. **L1 forced inclusion (Phase 3).** In the permissionless phase, agents can force-include events via L1 deposit transactions on Ethereum, bypassing the sequencer entirely — the same mechanism that OP Stack rollups use to guarantee censorship resistance.

---

## 19. What an Auditor Can Verify Without Trust

Given an on-chain commitment from SetRegistry:

1. **Read** `(stream_id, sequence_start, sequence_end, events_root, prev_events_root)` from the blockchain.
2. **Fetch** the event list for the sequence range from the sequencer or any mirror.
3. **For each event:** Canonicalize the payload with JCS, recompute `payload_plain_hash`, recompute `event_signing_hash`, and verify the agent signature against the registered public key.
4. **For each event:** Recompute the leaf hash per Section 8.2.
5. **Recompute** the Merkle tree and events root per Section 8.3.
6. **Compare** to the on-chain events root.
7. **Verify** chain continuity by checking `prev_events_root` matches the previous batch.

If all checks pass, the auditor has independently verified the integrity of the commerce event log — without trusting the sequencer, the database, or any single party.

---

## 20. Roadmap

### Near-Term (Q1-Q2 2026)

- **Multi-sequencer consensus** — eliminate single points of failure with a shared sequencer set.
- **HSM integration** — hardware-backed key storage for sequencer signing keys.
- **Real-time streaming** — WebSocket/SSE push for event subscriptions.

### Medium-Term (Q3-Q4 2026)

- **Decentralized key registry** — on-chain agent key registry for strongest auditability.
- **Cross-stream commitments** — aggregate Merkle roots across tenant streams for platform-level proofs.
- **STARK proof automation** — automated compliance proof generation for common regulatory patterns.

### Long-Term (2027+)

- **Permissionless sequencing** — economic incentives (staking, slashing) for open sequencer participation.
- **Cross-chain anchoring** — anchor commitments to multiple chains for maximum availability.
- **Formal verification** — machine-checked proofs of the VES protocol properties.

---

## 21. Conclusion

The StateSet Sequencer transforms commerce events from opaque database rows into cryptographically verifiable facts. By combining Ed25519 agent signatures, RFC 8785 canonicalization, domain-separated Merkle trees, on-chain commitment chaining, and STARK compliance proofs, it provides the infrastructure for a world where AI agents transact autonomously — and every transaction can be independently audited.

> **The question is no longer "do you trust the database?" It is "can you verify the proof?"**

---

## Appendix A: VES v1.0 Test Vector

Given:
```
tenant_id:      64527dd3-a654-4410-9327-e58a1492ce77
store_id:       91def158-819a-4461-b5c9-7759750ad157
event_id:       861910c9-7a1d-4b6f-83d6-51bbf4ae2849
source_agent:   80441726-74e2-430a-95ae-97ce21c6351b
agent_key_id:   1
entity_type:    "order"
entity_id:      "ORD-001"
event_type:     "order.created"
created_at:     "2025-12-20T17:51:10.243Z"
payload_kind:   0
plain_hash:     7777c3fef466a0e9df7e07ea4ff13dc8ffbb9e487098f1b65530cdce7b6bbbe7
cipher_hash:    0000000000000000000000000000000000000000000000000000000000000000
```

Expected `event_signing_hash`:
```
e970dfc9ffc285c2c0ba59be5d9c653eee2d1ae4db9b7a02ea3cd62b8e7cf92b
```

## Appendix B: Database Schema (PostgreSQL)

Nine migrations define the schema:

| Migration | Purpose |
|-----------|---------|
| `001_production_postgres` | Core tables: events, sequence counters |
| `002_ves_v1_tables` | VES event envelopes, commitments |
| `003_constraints` | Foreign keys, indexes, uniqueness |
| `004_ves_validity_proofs` | STARK validity proof storage |
| `005_ves_compliance_proofs` | Per-event compliance proofs |
| `006_key_rotation_policies` | Agent key rotation schedules |
| `007_encryption_groups` | Multi-tenant encryption keyrings |
| `008_command_dedupe` | Command-level deduplication |
| `009_api_keys` | API key management (SHA-256 hashed) |

## Appendix C: Feature Flags

| Feature | Dependencies Added | Purpose |
|---------|-------------------|---------|
| `grpc` | tonic, prost | gRPC service alongside REST |
| `telemetry` | opentelemetry, OTLP | Distributed tracing export |
| `anchoring` | alloy | SET Chain L2 commitment anchoring |
| `schema-validation` | jsonschema | JSON Schema payload validation |
| `sqlite` | sqlx/sqlite | Local agent outbox support |
| `encryption` | aes-gcm, hpke | Payload encryption at rest |
