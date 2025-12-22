# StateSet Sequencer Architecture

This document describes the high-level architecture of the StateSet Sequencer, a Verifiable Event Sync (VES) v1.0 implementation for deterministic event ordering and cryptographic verification.

## System Overview

```
                                    ┌─────────────────────────────────────────────────────────────┐
                                    │                    StateSet Sequencer                        │
                                    │                                                              │
┌──────────────────┐               │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│                  │   HTTP POST   │  │             │    │             │    │                 │  │
│   AI Agent 1     │──────────────▶│  │   Ingest    │───▶│  Sequencer  │───▶│   Event Store   │  │
│  (Local SQLite)  │               │  │   Service   │    │             │    │   (PostgreSQL)  │  │
│                  │               │  │             │    │             │    │                 │  │
└──────────────────┘               │  └──────┬──────┘    └──────┬──────┘    └────────┬────────┘  │
                                    │         │                  │                    │           │
┌──────────────────┐               │         ▼                  │                    │           │
│                  │   HTTP POST   │  ┌─────────────┐           │                    │           │
│   AI Agent 2     │──────────────▶│  │  Agent Key  │           │                    │           │
│  (Local SQLite)  │               │  │  Registry   │           │                    │           │
│                  │               │  │             │           │                    │           │
└──────────────────┘               │  └─────────────┘           │                    │           │
                                    │                            ▼                    ▼           │
┌──────────────────┐               │                     ┌─────────────┐    ┌─────────────────┐  │
│                  │   HTTP POST   │                     │  Projector  │    │   Commitment    │  │
│   AI Agent N     │──────────────▶│                     │             │───▶│     Engine      │  │
│  (Local SQLite)  │               │                     │ (Domain     │    │   (Merkle)      │  │
│                  │               │                     │  Handlers)  │    │                 │  │
└──────────────────┘               │                     └─────────────┘    └────────┬────────┘  │
        │                          │                                                  │           │
        │                          │  ┌─────────────────────────────────────────┐    │           │
        │                          │  │         Compliance Proof Engine         │    │           │
        │                          │  │  (Verification + Storage)               │    │           │
        │                          │  └──────────────────┬──────────────────────┘    │           │
        │                          │                     │                           ▼           │
        │                          │                     │                 ┌─────────────────┐  │
        │                          │                     │                 │  Anchor Service │  │
        │                          │                     │                 │  (Ethereum L2)  │  │
        │                          │                     │                 └─────────────────┘  │
        │                          └─────────────────────┼───────────────────────────────────────┘
        │                                                │                           │
        │  ┌────────────────────┐                       │                           ▼
        │  │                    │                       │                  ┌─────────────────┐
        └─▶│   stateset-stark   │───────────────────────┘                  │   Set Chain     │
           │   (STARK Prover)   │    Submit Proof                          │ (StateSetAnchor)│
           │                    │                                          └─────────────────┘
           └────────────────────┘
```

### Component Relationships

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              Full Stack Architecture                                     │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│   ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌────────────┐ │
│   │  AI Agent   │────▶│ stateset-sequencer│────▶│  stateset-stark  │────▶│ Set Chain  │ │
│   │   (CLI)     │     │   (Event Sync)   │     │  (ZK Proofs)     │     │   (L2)     │ │
│   └─────────────┘     └──────────────────┘     └──────────────────┘     └────────────┘ │
│         │                      │                        │                      │        │
│         │                      │                        │                      │        │
│         ▼                      ▼                        ▼                      ▼        │
│   ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌────────────┐ │
│   │   SQLite    │     │   PostgreSQL     │     │  STARK Proofs    │     │ On-Chain   │ │
│   │   Outbox    │     │  Event Store     │     │  (~100-200KB)    │     │  Anchors   │ │
│   └─────────────┘     └──────────────────┘     └──────────────────┘     └────────────┘ │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Ingest Service

**Location:** `src/api/rest.rs`, `src/server.rs`

The entry point for all events. Responsible for:

- **Authentication**: Validates API keys or JWT tokens
- **Schema Validation**: Ensures events conform to VES v1.0 format
- **Signature Verification**: Verifies Ed25519 agent signatures
- **Deduplication**: Rejects duplicate `event_id` values
- **Batching**: Groups events for efficient processing

```
Request → Auth → Validate → Verify Sig → Dedupe → Sequencer
```

### 2. Agent Key Registry

**Location:** `src/auth/agent_keys.rs`

Manages agent public keys for signature verification:

- **Key Registration**: `POST /api/v1/agents/keys`
- **Key Lookup**: `(tenant_id, agent_id, key_id) → public_key`
- **Validity Windows**: Keys have `valid_from` and `valid_to` timestamps
- **Revocation**: Keys can be revoked to invalidate future signatures

```rust
pub struct AgentKeyEntry {
    pub public_key: [u8; 32],    // Ed25519 public key
    pub status: KeyStatus,       // Active, Revoked, Expired
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
}
```

### 3. Sequencer

**Location:** `src/infra/postgres/sequencer.rs`, `src/infra/postgres/ves_sequencer.rs`

Assigns monotonic sequence numbers to events:

- **Monotonic Ordering**: Each `(tenant_id, store_id)` has independent sequence counter
- **Gap-Free**: Sequence numbers are contiguous with no gaps
- **Atomic Assignment**: Uses a single PostgreSQL transaction with `SELECT ... FOR UPDATE` on the per-stream counter
- **Receipt Generation**: Produces signed receipts for each sequenced event

```sql
-- Sequence counter table
CREATE TABLE sequence_counters (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    current_sequence BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, store_id)
);
```

### 4. Event Store

**Location:** `src/infra/postgres/event_store.rs`

Append-only storage for sequenced events:

- **Immutability**: Events are never modified or deleted
- **Encryption**: Payload encryption at rest (optional)
- **Indexing**: Efficient queries by sequence, entity, and time
- **Range Reads**: Fetch events by sequence number range

```sql
CREATE TABLE events (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    sequence_number BIGINT NOT NULL,
    event_id UUID UNIQUE NOT NULL,
    entity_type VARCHAR(64) NOT NULL,
    entity_id VARCHAR(256) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    payload_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, store_id, sequence_number)
);
```

### 5. Projector

**Location:** `src/projection/handlers.rs`, `src/projection/runner.rs`

Applies events to domain projections:

- **Domain Handlers**: Entity-specific projection logic
- **Optimistic Concurrency**: Version checking prevents conflicts
- **Invariant Validation**: Rejects events violating business rules
- **Checkpoint Tracking**: Tracks last processed sequence per store

Supported entity types:
- **Order**: `order.created`, `order.confirmed`, `order.shipped`, etc.
- **Inventory**: `inventory.initialized`, `inventory.adjusted`, `inventory.reserved`
- **Product**: `product.created`, `product.updated`, `product.deactivated`
- **Customer**: `customer.created`, `customer.updated`, `customer.address_added`
- **Return**: `return.requested`, `return.approved`, `return.refunded`

### 6. Commitment Engine

**Location:** `src/infra/postgres/commitment.rs`

Creates Merkle tree commitments over event batches:

- **Merkle Roots**: SHA-256 trees over event payload hashes
- **State Roots**: Track state transitions (prev_root → new_root)
- **Inclusion Proofs**: Generate proofs for individual events
- **Batch Storage**: Persist commitments for later verification

```rust
pub struct BatchCommitment {
    pub batch_id: Uuid,
    pub tenant_id: TenantId,
    pub store_id: StoreId,
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub events_root: [u8; 32],      // Merkle root of payload hashes
    pub event_count: u32,
    pub sequence_range: (u64, u64),
    pub committed_at: DateTime<Utc>,
    pub chain_tx_hash: Option<[u8; 32]>,
}
```

### 7. Anchor Service

**Location:** `src/anchor.rs`

Submits commitments to Ethereum L2:

- **StateSetAnchor Contract**: On-chain batch commitment storage
- **Transaction Building**: Constructs and signs anchor transactions
- **Verification**: Confirms anchoring status on-chain
- **Gas Management**: Handles gas estimation and pricing

### 8. Compliance Proof Engine

**Location:** `src/domain/ves_compliance.rs`, `src/infra/ves_compliance.rs`

Stores and verifies zero-knowledge compliance proofs generated by `stateset-stark`:

- **Proof Storage**: Stores STARK proofs in `ves_compliance_proofs` table
- **Public Input Validation**: Ensures canonical public inputs match event data
- **Policy Verification**: Validates proof matches declared policy
- **Idempotency**: Deduplicates by `(event_id, proof_type, policy_hash)`

```sql
CREATE TABLE ves_compliance_proofs (
    id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES ves_events(event_id),
    proof_type VARCHAR(64) NOT NULL,       -- e.g., "stark.compliance.v1"
    proof_version INTEGER NOT NULL,
    policy_id VARCHAR(128) NOT NULL,       -- e.g., "aml.threshold"
    policy_params JSONB NOT NULL,          -- e.g., {"threshold": 10000}
    policy_hash BYTEA NOT NULL,            -- SHA256 of policy
    proof_hash BYTEA NOT NULL,             -- SHA256 of proof bytes
    proof_bytes BYTEA,                     -- Full STARK proof (~100-200KB)
    public_inputs JSONB NOT NULL,          -- Canonical JCS format
    witness_commitment BYTEA,              -- Rescue hash of private witness
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (event_id, proof_type, proof_version, policy_hash)
);
```

## stateset-stark (ZK Compliance Proofs)

**Repository:** `stateset-stark`

A STARK proving system that enables cryptographic verification of compliance policies on encrypted event payloads without revealing the underlying data.

### Purpose

When events contain encrypted payloads (e.g., order amounts), compliance rules (e.g., AML thresholds) need verification without exposing sensitive data. `stateset-stark` generates zero-knowledge proofs that:

1. The prover knows the plaintext payload
2. The payload satisfies the compliance policy
3. The payload matches the encrypted ciphertext hash

### Architecture

```
stateset-stark/
├── crates/
│   ├── ves-stark-primitives/    # Goldilocks field, Rescue hash
│   ├── ves-stark-air/           # AIR constraint definitions (167 constraints)
│   ├── ves-stark-prover/        # Proof generation
│   ├── ves-stark-verifier/      # Proof verification
│   ├── ves-stark-batch/         # Batch proofs (Phase 2)
│   ├── ves-stark-client/        # HTTP client for sequencer
│   └── ves-stark-cli/           # Command-line tool
```

### Cryptographic Foundation

| Component | Choice | Notes |
|-----------|--------|-------|
| Field | Goldilocks (p = 2^64 - 2^32 + 1) | 64-bit efficient arithmetic |
| Hash | Rescue-Prime | STARK-friendly algebraic hash |
| Commitment | Blake3-256 Merkle | Vector commitments |
| Security | ~100 bits | Default proof options |

### Supported Policies

| Policy ID | Constraint | Use Case |
|-----------|-----------|----------|
| `aml.threshold` | `amount < threshold` | AML compliance (strict less-than) |
| `order_total.cap` | `amount <= cap` | Order limits (less-than-or-equal) |

### Proof Generation Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Compliance Proof Generation                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Agent decrypts VES event payload (ephemeral, off-chain)             │
│                            │                                             │
│                            ▼                                             │
│  2. Extract witness data (e.g., order amount = 5000)                    │
│                            │                                             │
│                            ▼                                             │
│  3. Fetch canonical public inputs from sequencer                        │
│     GET /api/v1/ves/compliance/{event_id}/inputs                        │
│                            │                                             │
│                            ▼                                             │
│  4. Build ComplianceWitness + CompliancePublicInputs                    │
│                            │                                             │
│                            ▼                                             │
│  5. Generate STARK proof (ves-stark-prover)                             │
│     - Build execution trace (105 columns, 128+ rows)                    │
│     - Apply AIR constraints (167 total)                                 │
│     - Produce proof (~100-200KB)                                        │
│                            │                                             │
│                            ▼                                             │
│  6. Submit proof to sequencer                                           │
│     POST /api/v1/ves/compliance/{event_id}/proofs                       │
│                            │                                             │
│                            ▼                                             │
│  7. Sequencer verifies and stores proof                                 │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Public Inputs (Canonical JCS Format)

```json
{
  "eventId": "550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "tenant-uuid",
  "storeId": "store-uuid",
  "sequenceNumber": 42,
  "payloadKind": 1,
  "payloadPlainHash": "abc123...",
  "payloadCipherHash": "def456...",
  "eventSigningHash": "789abc...",
  "policyId": "aml.threshold",
  "policyParams": { "threshold": 10000 },
  "policyHash": "computed-sha256..."
}
```

### CLI Usage

```bash
# Generate a compliance proof
ves-stark prove --amount 5000 --limit 10000 --policy aml.threshold

# Verify a proof
ves-stark verify --proof proof.stark --inputs inputs.json --limit 10000

# Benchmark proving performance
ves-stark benchmark -n 10 --max-amount 10000 --limit 10000
```

### Integration Points

| Sequencer Endpoint | Purpose |
|--------------------|---------|
| `GET /api/v1/ves/compliance/{event_id}/inputs` | Fetch canonical public inputs |
| `POST /api/v1/ves/compliance/{event_id}/proofs` | Submit generated proof |
| `GET /api/v1/ves/compliance/{event_id}/proofs` | List proofs for event |
| `GET /api/v1/ves/compliance/proofs/{proof_id}` | Get proof by ID |
| `GET /api/v1/ves/compliance/proofs/{proof_id}/verify` | Verify proof |

## Data Flow

### Event Ingestion Flow

```
1. Agent creates event locally (SQLite outbox)
2. Agent signs event with Ed25519 private key
3. Agent POSTs to /api/v1/ves/events/ingest
4. Sequencer verifies signature against registered public key
5. Sequencer assigns sequence number atomically
6. Event stored in PostgreSQL events table
7. Sequencer returns receipt with sequence number
8. Agent marks event as synced locally
```

### Commitment Flow

```
1. Client requests commitment for sequence range
2. Commitment Engine reads events from Event Store
3. Engine builds Merkle tree from payload hashes
4. Engine computes state root transition
5. Commitment stored in commitments table
6. (Optional) Anchor Service submits to StateSetAnchor
7. Chain tx hash stored with commitment
```

### Verification Flow

```
1. Client requests inclusion proof for sequence N
2. Engine retrieves commitment containing N
3. Engine rebuilds Merkle tree for batch
4. Engine generates proof path for leaf N
5. Client verifies locally, then verifies the batch root is anchored on-chain
```

### Compliance Proof Flow

```
1. Agent creates encrypted VES event (payload encrypted with HPKE)
2. Agent syncs event to sequencer (receives sequence number)
3. Agent decrypts payload locally (ephemeral)
4. Agent extracts witness data (e.g., order.total = 5000)
5. Agent fetches canonical public inputs from sequencer
6. Agent generates STARK proof using stateset-stark:
   - Builds execution trace (witness decomposition, Rescue hash)
   - Applies 167 AIR constraints
   - Produces ~100-200KB proof
7. Agent submits proof to sequencer
8. Sequencer validates public inputs match event
9. Sequencer stores proof in ves_compliance_proofs
10. (Future) Sequencer cryptographically verifies proof
```

## Database Schema

### Core Tables

| Table | Purpose |
|-------|---------|
| `events` | Append-only event log |
| `ves_events` | VES v1.0 events with signatures |
| `sequence_counters` | Per-store sequence tracking |
| `batch_commitments` | Merkle commitment records |
| `ves_compliance_proofs` | STARK compliance proofs |
| `ves_validity_proofs` | Batch validity proofs (Phase 2) |
| `agent_keys` | Agent public key registry |
| `entity_versions` | Entity version tracking |
| `projection_checkpoints` | Projector progress |

### Indexes

```sql
-- Fast event lookups
CREATE INDEX idx_events_entity ON events(tenant_id, store_id, entity_type, entity_id);
CREATE INDEX idx_events_type ON events(tenant_id, store_id, event_type);
CREATE INDEX idx_events_created ON events(tenant_id, store_id, created_at);

-- Agent key lookups
CREATE INDEX idx_agent_keys_lookup ON agent_keys(tenant_id, agent_id, key_id);
```

## Cryptographic Design

### Signing Hash Construction

Per VES v1.0 Section 8.3:

```
signing_hash = SHA256(
    "VES_EVENTSIG_V1" ||      // Domain separator
    event_id ||
    tenant_id ||
    store_id ||
    agent_id ||
    entity_type ||
    entity_id ||
    event_type ||
    payload_plain_hash ||
    occurred_at
)

agent_signature = Ed25519.Sign(agent_private_key, signing_hash)
```

### Merkle Tree Construction

```
          [Root]
         /      \
     [H01]      [H23]
     /   \      /   \
  [H0]  [H1]  [H2]  [H3]
   |     |     |     |
  E0    E1    E2    E3    (Event payload hashes)

Domain-separated hashing:
- Leaf: SHA256("VES_LEAF_V1" || payload_hash)
- Node: SHA256("VES_NODE_V1" || left || right)
```

## Offline-First Architecture

Agents operate offline using SQLite:

```
┌─────────────────────────────────────────┐
│  Local Agent                            │
│                                         │
│  ┌─────────────┐    ┌───────────────┐  │
│  │  Business   │───▶│    Outbox     │  │
│  │   Logic     │    │   (SQLite)    │  │
│  └─────────────┘    └───────┬───────┘  │
│                             │           │
│                             ▼           │
│                     ┌───────────────┐  │
│                     │  Sync State   │  │
│                     │   Tracker     │  │
│                     └───────┬───────┘  │
└─────────────────────────────┼───────────┘
                              │
                              ▼ (when online)
                    ┌───────────────────┐
                    │ Remote Sequencer  │
                    └───────────────────┘
```

**SQLite Tables:**

```sql
-- Local event outbox
CREATE TABLE outbox (
    local_seq INTEGER PRIMARY KEY,
    event_id TEXT UNIQUE NOT NULL,
    payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    pushed_at TEXT,
    remote_seq INTEGER
);

-- Sync state tracking
CREATE TABLE sync_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

## Scalability Considerations

### Horizontal Scaling

- **Stateless API**: Multiple sequencer instances behind load balancer
- **Database Pooling**: Connection pooling per instance
- **Sequence Partitioning**: Each `(tenant_id, store_id)` is independent

### Performance Optimizations

- **Batch Inserts**: Events ingested in batches
- **Read Replicas**: Entity history queries on replicas
- **Commitment Caching**: Recent commitments cached in memory
- **Proof Memoization**: Common proof paths cached

### Capacity Planning

| Component | Recommended |
|-----------|-------------|
| PostgreSQL | 16+ GB RAM, SSD storage |
| Sequencer | 2-4 CPU cores, 4 GB RAM |
| Connections | 10-20 per instance |
| Events/sec | ~1000-5000 depending on payload size |

## Security Model

### Trust Boundaries

1. **Agent ↔ Sequencer**: TLS + Ed25519 signatures
2. **Sequencer ↔ Database**: Network isolation + credentials
3. **Sequencer ↔ L2 Chain**: Private key for signing

### Key Management

- Agent private keys: Never leave agent, stored securely
- Sequencer private key: For anchor transactions only
- Database credentials: Environment variables, not in code

See [SECURITY.md](docs/SECURITY.md) for detailed security guidance.

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Rust (Edition 2021) |
| Web Framework | Axum |
| Async Runtime | Tokio |
| Database | PostgreSQL 16+ |
| Local Storage | SQLite |
| Cryptography | ed25519-dalek, sha2, aes-gcm |
| Merkle Trees | rs_merkle (custom domain separation) |
| Blockchain | Alloy (Ethereum) |
| Serialization | serde, serde_json |

## Module Structure

```
src/
├── main.rs              # Entry point, router setup
├── lib.rs               # Library exports
├── api/
│   └── rest.rs          # HTTP handlers
├── domain/
│   ├── types.rs         # Core domain types
│   ├── event.rs         # EventEnvelope
│   ├── ves_event.rs     # VES v1.0 events
│   └── commitment.rs    # BatchCommitment, MerkleProof
├── infra/
│   ├── traits.rs        # Service traits
│   ├── postgres/        # PostgreSQL implementations
│   └── sqlite/          # SQLite outbox (agents)
├── auth/
│   ├── agent_keys.rs    # Agent key registry
│   └── middleware.rs    # Auth middleware
├── crypto/
│   ├── hash.rs          # Domain-separated hashing
│   ├── signing.rs       # Ed25519 operations
│   └── encrypt.rs       # HPKE encryption
├── projection/
│   ├── runner.rs        # Projection executor
│   └── handlers.rs      # Domain handlers
└── anchor.rs            # On-chain anchoring
```

## Related Documentation

- [Getting Started](GETTING_STARTED.md) - Quick start guide
- [VES Specification](docs/VES_SPEC.md) - Full protocol spec
- [API Reference](docs/API_REFERENCE.md) - REST API documentation
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment
- [Security Guide](docs/SECURITY.md) - Security best practices
- [ZK Integration Guide](docs/ZK_INTEGRATION_GUIDE.md) - STARK proof integration

## Related Repositories

| Repository | Purpose |
|------------|---------|
| `stateset-stark` | STARK proving system for compliance proofs |
| `@stateset/cli` | AI agent CLI with local SQLite outbox |
| `set-chain` | Ethereum L2 for anchoring commitments |
