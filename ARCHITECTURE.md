# StateSet Sequencer Architecture

This document describes the high-level architecture of the StateSet Sequencer, a Verifiable Event Sync (VES) v1.0 implementation for deterministic event ordering, cryptographic verification, and agent-to-agent payment sequencing.

## System Overview

```
                                    ┌──────────────────────────────────────────────────────────────────────────┐
                                    │                         StateSet Sequencer                               │
                                    │                                                                          │
┌──────────────────┐               │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐              │
│                  │  HTTP / gRPC  │  │             │    │             │    │                 │              │
│   AI Agent 1     │──────────────▶│  │   Ingest    │───▶│  Sequencer  │───▶│   Event Store   │              │
│  (Local SQLite)  │               │  │   Service   │    │             │    │   (PostgreSQL)  │              │
│                  │               │  │             │    │             │    │                 │              │
└──────────────────┘               │  └──────┬──────┘    └──────┬──────┘    └────────┬────────┘              │
                                    │         │                  │                    │                       │
┌──────────────────┐               │         ▼                  │                    │                       │
│                  │  HTTP / gRPC  │  ┌─────────────┐    ┌──────┴──────┐             │                       │
│   AI Agent 2     │──────────────▶│  │  Agent Key  │    │   Schema    │             │                       │
│  (Local SQLite)  │               │  │  Registry   │    │  Registry   │             │                       │
│                  │               │  │             │    │             │             │                       │
└──────────────────┘               │  └─────────────┘    └─────────────┘             │                       │
                                    │                                                 ▼                       │
┌──────────────────┐               │                     ┌─────────────┐    ┌─────────────────┐              │
│                  │  HTTP / gRPC  │                     │  Projector  │    │   Commitment    │              │
│   AI Agent N     │──────────────▶│                     │             │───▶│     Engine      │              │
│  (Local SQLite)  │               │                     │ (Domain     │    │   (Merkle)      │              │
│                  │               │                     │  Handlers)  │    │                 │              │
└──────────────────┘               │                     └──────┬──────┘    └────────┬────────┘              │
        │                          │                            │                    │                       │
        │                          │  ┌─────────────┐   ┌──────┴──────┐             │                       │
        │                          │  │  x402       │   │ Dead Letter │             │                       │
        │                          │  │  Payment    │   │   Queue     │             │                       │
        │                          │  │  Engine     │   └─────────────┘             │                       │
        │                          │  └──────┬──────┘                               │                       │
        │                          │         │                                       │                       │
        │                          │  ┌──────┴──────────────────────────────────────┴────────────────┐      │
        │                          │  │                  Operational Infrastructure                    │      │
        │                          │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐   │      │
        │                          │  │  │  Cache   │ │  Circuit │ │  Pool    │ │   Metrics &   │   │      │
        │                          │  │  │  Manager │ │  Breaker │ │  Monitor │ │   Telemetry   │   │      │
        │                          │  │  └──────────┘ └──────────┘ └──────────┘ └───────────────┘   │      │
        │                          │  └─────────────────────────────────────────────────────────────┘      │
        │                          │                                                                        │
        │                          │  ┌─────────────────────────────────────────┐                           │
        │                          │  │         Compliance Proof Engine         │                           │
        │                          │  │  (Verification + Storage)               │                           │
        │                          │  └──────────────────┬──────────────────────┘                           │
        │                          │                     │                                                   │
        │                          │  ┌─────────────────────────────────────────┐  ┌─────────────────┐      │
        │                          │  │       Validity Proof Registry           │  │  Anchor Service │      │
        │                          │  │  (External SNARK/ZK proofs)             │  │  (Ethereum L2)  │      │
        │                          │  └─────────────────────────────────────────┘  └────────┬────────┘      │
        │                          └────────────────────────────────────────────────────────┼────────────────┘
        │                                                                                   │
        │  ┌────────────────────┐                                                          ▼
        │  │                    │                                                 ┌─────────────────┐
        └─▶│   stateset-stark   │                                                 │   Set Chain     │
           │   (STARK Prover)   │                                                 │ (SetPaymentBatch│
           │                    │                                                 │  + StateSetAnchor)
           └────────────────────┘                                                 └─────────────────┘
```

### Component Relationships

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                                Full Stack Architecture                                         │
├───────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                │
│   ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐ │
│   │  AI Agent   │────▶│ stateset-sequencer│────▶│  stateset-stark  │────▶│    Set Chain     │ │
│   │   (CLI)     │     │   (Event Sync +  │     │  (ZK Proofs)     │     │ (L2: Anchors +   │ │
│   │             │     │    Payments)      │     │                  │     │  Payments)        │ │
│   └─────────────┘     └──────────────────┘     └──────────────────┘     └──────────────────┘ │
│         │                      │                        │                        │             │
│         ▼                      ▼                        ▼                        ▼             │
│   ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐ │
│   │   SQLite    │     │   PostgreSQL     │     │  STARK Proofs    │     │  On-Chain        │ │
│   │   Outbox    │     │  Event Store +   │     │  (~100-200KB)    │     │  Anchors +       │ │
│   │             │     │  Payment Intents │     │                  │     │  Settlements     │ │
│   └─────────────┘     └──────────────────┘     └──────────────────┘     └──────────────────┘ │
│                                                                                                │
│   Protocols:  HTTP REST  |  gRPC v1+v2 (streaming)  |  x402 (payments)  |  VES v1.0 (events) │
│                                                                                                │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Ingest Service

**Location:** `src/api/handlers/ingest.rs`, `src/server.rs`

The entry point for all events via HTTP REST and gRPC. Responsible for:

- **Authentication**: Validates API keys, JWT tokens, or agent Ed25519 signatures
- **Schema Validation**: Validates payloads against registered JSON Schemas (configurable: disabled, warn, strict)
- **Signature Verification**: Verifies Ed25519 agent signatures with domain-separated hashing
- **Deduplication**: Rejects duplicate `event_id` and `command_id` values
- **Batching**: Groups events for efficient processing with parallel partitioning
- **Rate Limiting**: Sliding-window per-tenant rate limiting

```
Request → Auth → Rate Limit → Validate Schema → Verify Sig → Dedupe → Sequencer
```

### 2. Agent Key Registry

**Location:** `src/auth/agent_keys.rs`, `src/infra/postgres/agent_key_registry.rs`

Manages agent public keys for signature verification:

- **Key Registration**: `POST /api/v1/agents/keys` (REST) and `RegisterAgentKey` (gRPC)
- **Key Lookup**: `(tenant_id, agent_id, key_id) -> public_key` with LRU caching
- **Key Types**: Ed25519 (signing) and X25519 (encryption)
- **Validity Windows**: Keys have `valid_from` and `valid_to` timestamps
- **Revocation**: Keys can be revoked to invalidate future signatures
- **Proof of Possession**: Registration requires a signature proving key ownership

```rust
pub struct AgentKeyEntry {
    pub public_key: [u8; 32],    // Ed25519 or X25519 public key
    pub key_type: KeyType,       // Signing or Encryption
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
- **Receipt Generation**: Produces signed receipts for each sequenced event (configurable via `VES_SEQUENCER_SIGNING_KEY`)
- **Sequencer Identity**: Optional pinned sequencer ID via `VES_SEQUENCER_ID`

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
- **Encryption-at-Rest**: Optional AES-256-GCM payload encryption (modes: disabled, optional, required)
- **Indexing**: Efficient queries by sequence, entity, and time
- **Range Reads**: Fetch events by sequence number range
- **Read/Write Splitting**: Reads served from replica pool when configured

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
- **Dead Letter Queue**: Failed projections are moved to DLQ for retry

Supported entity types:
- **Order**: `order.created`, `order.confirmed`, `order.shipped`, etc.
- **Inventory**: `inventory.initialized`, `inventory.adjusted`, `inventory.reserved`
- **Product**: `product.created`, `product.updated`, `product.deactivated`
- **Customer**: `customer.created`, `customer.updated`, `customer.address_added`
- **Return**: `return.requested`, `return.approved`, `return.refunded`
- **x402 Payment**: `x402_payment.created`, `x402_payment.sequenced`, `x402_payment.settled`
- **x402 Batch**: `x402_batch.created`, `x402_batch.committed`, `x402_batch.settled`

### 6. Commitment Engine

**Location:** `src/infra/postgres/commitment.rs`, `src/infra/ves_commitment.rs`

Creates Merkle tree commitments over event batches:

- **Merkle Roots**: SHA-256 trees over event payload hashes
- **State Roots**: Track state transitions (prev_root -> new_root)
- **Inclusion Proofs**: Generate proofs for individual events
- **Batch Storage**: Persist commitments for later verification
- **VES Commitments**: Separate commitment engine for VES v1.0 events

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
- **SetPaymentBatch Contract**: On-chain x402 payment batch settlement
- **Transaction Building**: Constructs and signs anchor transactions using Alloy
- **Verification**: Confirms anchoring status on-chain
- **Gas Management**: Handles gas estimation and pricing
- **Circuit Breaker Protected**: External calls guarded by circuit breaker

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

### 9. Validity Proof Registry

**Location:** `src/domain/ves_validity.rs`, `src/infra/ves_validity.rs`

External proof registry for SNARK/ZK proofs attesting to batch properties:

- **Proof Submission**: External provers submit validity proofs for committed batches
- **Proof Storage**: Persists proof bytes and public inputs
- **Proof Hashing**: SHA-256 hash of proof for integrity
- **Stream Matching**: Trigger enforces proofs reference valid batches

```sql
CREATE TABLE ves_validity_proofs (
    id UUID PRIMARY KEY,
    batch_id UUID NOT NULL REFERENCES ves_commitments(batch_id),
    proof_type VARCHAR(64) NOT NULL,
    proof_version INTEGER NOT NULL,
    proof_hash BYTEA NOT NULL,
    proof_bytes BYTEA,
    public_inputs JSONB NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
```

### 10. x402 Payment Engine

**Location:** `src/domain/x402_payment.rs`, `src/infra/postgres/x402_repository.rs`, `src/infra/x402_batch_worker.rs`, `src/api/handlers/x402.rs`

Implements the x402 protocol for agent-to-agent payment sequencing and batched L2 settlement:

- **Payment Intent Sequencing**: Signed payment intents assigned sequence numbers
- **Signature Verification**: Ed25519 signatures with `X402_PAYMENT_V1` domain separator
- **Nonce-Based Replay Protection**: Per-agent nonce tracking
- **Idempotency**: Optional idempotency keys for at-most-once delivery
- **Batch Assembly**: Configurable batch size (default 100, max 1000) and time thresholds
- **Merkle Commitments**: Merkle root computation over batched payment intents
- **Multi-Chain Settlement**: Settlement on Set Chain L2 via `SetPaymentBatch` contract
- **Multi-Asset Support**: USDC, USDT, ssUSD, wssUSD, DAI, ETH

```
AI Agent
    |
    | Creates X402PaymentIntent (signed)
    v
Sequencer
    |
    | 1. Validates signature
    | 2. Checks nonce (replay protection)
    | 3. Assigns sequence number
    | 4. Batches into X402PaymentBatch
    v
Set Chain L2 (SetPaymentBatch contract)
    |
    | Executes aggregated transfers
    v
Settlement complete (receipt with Merkle inclusion proof)
```

**Supported Networks:**

| Network | Chain ID | Type |
|---------|----------|------|
| Set Chain | 84532001 | Mainnet |
| Set Chain Testnet | 84532002 | Testnet |
| Arc | 5042001 | Mainnet |
| Base | 8453 | Mainnet |
| Ethereum | 1 | Mainnet |
| Arbitrum | 42161 | Mainnet |
| Optimism | 10 | Mainnet |

**Supported Assets:**

| Asset | Decimals | Description |
|-------|----------|-------------|
| USDC | 6 | USD Coin |
| USDT | 6 | Tether |
| ssUSD | 6 | StateSet USD (yield-bearing) |
| wssUSD | 6 | Wrapped StateSet USD (ERC-4626) |
| DAI | 18 | DAI stablecoin |
| ETH | 18 | Native ETH |

**Payment Intent Lifecycle:**

```
Pending -> Sequenced -> Batched -> Settled
                                -> Failed
                     -> Expired
```

### 11. Schema Registry

**Location:** `src/domain/schema.rs`, `src/infra/postgres/schema_store.rs`, `src/api/handlers/schemas.rs`

JSON Schema validation system for event payloads:

- **Schema Versioning**: Monotonically increasing version per `(tenant_id, event_type)`
- **Compatibility Modes**: Forward, Backward, Full, or None
- **Validation Modes**: Disabled, Optional (warn), Required, Strict
- **Status Lifecycle**: Active -> Deprecated -> Archived
- **LRU Caching**: Configurable cache size and TTL for hot schemas
- **Detailed Errors**: Validation errors include JSON paths and messages

```rust
pub struct Schema {
    pub id: SchemaId,
    pub tenant_id: TenantId,
    pub event_type: EventType,
    pub version: u32,
    pub schema_json: serde_json::Value,
    pub status: SchemaStatus,            // Active, Deprecated, Archived
    pub compatibility: SchemaCompatibility, // Forward, Backward, Full, None
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}
```

## gRPC API (v1 + v2)

**Location:** `src/grpc/`, `proto/sequencer.proto`, `proto/sequencer_v2.proto`

The sequencer exposes dual gRPC services alongside the REST API:

### gRPC v2 Service (Full VES v1.0 Protocol)

| RPC | Type | Description |
|-----|------|-------------|
| `Push` | Unary | Push a batch of events for sequencing |
| `PullEvents` | Unary | Pull events (simple polling) |
| `GetSyncState` | Unary | Get current sync state for store |
| `GetInclusionProof` | Unary | Get Merkle inclusion proof |
| `GetCommitment` | Unary | Get batch commitment |
| `GetEntityHistory` | Unary | Get entity event history |
| `GetHealth` | Unary | Health check |
| `StreamEvents` | Server streaming | Continuous event delivery with filters |
| `SyncStream` | Bidirectional streaming | Full-duplex agent sync |
| `SubscribeEntity` | Server streaming | Subscribe to entity updates |

### Key Management Service (gRPC)

| RPC | Description |
|-----|-------------|
| `RegisterAgentKey` | Register Ed25519/X25519 key with proof of possession |
| `GetAgentKeys` | List agent keys with optional filters |
| `RevokeAgentKey` | Revoke an agent key |

### Bidirectional Sync Protocol

The `SyncStream` RPC enables full-duplex communication:

```
Client -> Server:  Push, Pull, EventAck, Heartbeat
Server -> Client:  PushResponse, PullResponse, SequencedEvent, SyncState, Heartbeat
```

Agents can push events, receive real-time updates, and acknowledge processing in a single persistent connection with heartbeat-based liveness detection.

## Operational Infrastructure

### Authentication System

**Location:** `src/auth/`

Multi-method authentication with composable validators:

| Method | Description |
|--------|-------------|
| API Keys | SHA-256 hashed, scoped to tenant/store, stored in PostgreSQL |
| JWT Tokens | HS256/HS384/HS512 with configurable issuer/audience |
| Agent Keys | Ed25519 signature verification for VES events |
| Bootstrap Key | Initial admin key from `BOOTSTRAP_ADMIN_API_KEY` env var |

- **Rate Limiting**: Sliding-window algorithm, configurable per-minute limit
- **Permissions Model**: Read, Write, Admin scopes per key
- **gRPC Auth Interceptor**: Shared authenticator for gRPC services

### Cache Manager

**Location:** `src/infra/cache.rs`

Multi-layer LRU caching with configurable TTL per cache type:

| Cache | Default Max | Description |
|-------|-------------|-------------|
| Commitments | configurable | Merkle commitment lookups |
| Proofs | configurable | Inclusion proof results |
| VES Commitments | configurable | VES-specific commitments |
| VES Proofs | configurable | VES-specific proofs |
| Agent Keys | configurable | Agent public key lookups |
| Schemas | configurable | JSON Schema definitions |

### Pool Monitor

**Location:** `src/infra/pool_monitor.rs`

Real-time database connection pool health tracking (15-second polling):

- **Health States**: Healthy (< 50%), Moderate (50-80%), Stressed (80-95%), Critical (> 95%)
- **Metrics**: Active/idle connections, acquisition latency, slow acquisition tracking
- **Integrated**: Exposed via `/health/detailed` endpoint and Prometheus metrics

### Circuit Breaker Registry

**Location:** `src/infra/circuit_breaker.rs`

Failure resilience for external service calls (L2 anchoring, chain settlement):

- **States**: Closed (normal) -> Open (fail-fast) -> HalfOpen (testing recovery)
- **Exponential Backoff**: Configurable multiplier with jitter
- **Slow Call Detection**: Configurable threshold for degraded performance
- **Per-Service Tracking**: Independent breaker per external service

### Dead Letter Queue

**Location:** `src/infra/dead_letter.rs`

Handles events that fail projection processing:

- **Auto-Retry**: Exponential backoff (1 min initial, 1 hour max, 10 retries)
- **Categorized Reasons**: Schema validation, invariant violation, state transition errors
- **Non-Retryable**: Invariant violations and invalid state transitions skip retry
- **Admin Operations**: Retry, purge, and inspect via admin CLI

### Payload Encryption-at-Rest

**Location:** `src/infra/payload_encryption.rs`, `src/crypto/encrypt.rs`

Automatic event payload encryption in the database:

- **Modes**: Disabled, Optional, Required
- **Algorithm**: AES-256-GCM
- **HPKE Support**: Multi-recipient encryption via X25519-HKDF-SHA256
- **Key Rotation**: Supports key versioning and rotation

### Audit Logging

**Location:** `src/infra/audit.rs`

Comprehensive audit trail for administrative operations:

- API key management (create, revoke, update)
- Schema registry changes (register, deprecate, delete)
- Agent key operations (register, rotate, revoke)
- Authentication events (login, failure, token refresh)
- Dead letter queue operations (retry, purge)

### Metrics & Telemetry

**Location:** `src/metrics/`, `src/telemetry/`

- **Prometheus Export**: `/metrics` endpoint with 40+ predefined metric names
- **Component Metrics**: Background collection every 15 seconds (pool, circuit breaker stats)
- **OpenTelemetry**: OTLP export for distributed tracing (`OTEL_EXPORTER_OTLP_ENDPOINT`)
- **Structured Logging**: JSON or text format (`LOG_FORMAT`)
- **Counters, Gauges, Histograms**: Full metric type support with labels

### Graceful Shutdown

**Location:** `src/infra/graceful_shutdown.rs`

Coordinated shutdown with request draining:

- **Request Tracking**: Guard-based in-flight request monitoring
- **Shutdown Signals**: Coordinated signal propagation to background tasks
- **Deadline Enforcement**: Configurable drain timeout

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

## REST API Reference

### Event Ingestion

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/events/ingest` | Legacy event ingestion |
| `POST` | `/api/v1/ves/events/ingest` | VES v1.0 event ingestion with signatures |

### VES Commitments

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/ves/commitments` | List VES commitments |
| `POST` | `/api/v1/ves/commitments` | Create VES commitment |
| `POST` | `/api/v1/ves/commitments/anchor` | Commit and anchor |
| `GET` | `/api/v1/ves/commitments/:batch_id` | Get specific commitment |

### VES Proofs & Anchoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/ves/proofs/:sequence_number` | Get VES inclusion proof |
| `POST` | `/api/v1/ves/proofs/verify` | Verify VES proof |
| `POST` | `/api/v1/ves/anchor` | Anchor VES commitment |
| `GET` | `/api/v1/ves/anchor/:batch_id/verify` | Verify on-chain anchoring |

### VES Validity Proofs

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/ves/validity/:batch_id/inputs` | Get public inputs |
| `GET` | `/api/v1/ves/validity/:batch_id/proofs` | List validity proofs |
| `POST` | `/api/v1/ves/validity/:batch_id/proofs` | Submit validity proof |
| `GET` | `/api/v1/ves/validity/proofs/:proof_id` | Get proof by ID |
| `GET` | `/api/v1/ves/validity/proofs/:proof_id/verify` | Verify validity proof |

### VES Compliance Proofs

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/ves/compliance/:event_id/inputs` | Get public inputs |
| `GET` | `/api/v1/ves/compliance/:event_id/proofs` | List compliance proofs |
| `POST` | `/api/v1/ves/compliance/:event_id/proofs` | Submit compliance proof |
| `GET` | `/api/v1/ves/compliance/proofs/:proof_id` | Get proof by ID |
| `GET` | `/api/v1/ves/compliance/proofs/:proof_id/verify` | Verify compliance proof |

### x402 Payment Protocol

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/x402/payments` | Submit payment intent |
| `GET` | `/api/v1/x402/payments` | List payment intents |
| `GET` | `/api/v1/x402/payments/:intent_id` | Get payment intent |
| `GET` | `/api/v1/x402/payments/:intent_id/receipt` | Get payment receipt |
| `POST` | `/api/v1/x402/batches` | Create payment batch |
| `GET` | `/api/v1/x402/batches/:batch_id` | Get batch |
| `POST` | `/api/v1/x402/batches/settle` | Settle batch on-chain |

### Schema Registry

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/schemas` | List schemas |
| `POST` | `/api/v1/schemas` | Register schema |
| `POST` | `/api/v1/schemas/validate` | Validate payload |
| `GET` | `/api/v1/schemas/:schema_id` | Get schema |
| `PUT` | `/api/v1/schemas/:schema_id/status` | Update schema status |
| `DELETE` | `/api/v1/schemas/:schema_id` | Delete schema |
| `GET` | `/api/v1/schemas/event-type/:event_type` | Get schemas by event type |
| `GET` | `/api/v1/schemas/event-type/:event_type/latest` | Get latest schema |

### Legacy Events & Commitments

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/events` | List events |
| `GET` | `/api/v1/head` | Get current head sequence |
| `GET` | `/api/v1/entities/:entity_type/:entity_id` | Get entity history |
| `GET/POST` | `/api/v1/commitments` | List/create commitments |
| `GET` | `/api/v1/commitments/:batch_id` | Get commitment |
| `GET` | `/api/v1/proofs/:sequence_number` | Get inclusion proof |
| `POST` | `/api/v1/proofs/verify` | Verify proof |

### Health & Observability

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Basic health check |
| `GET` | `/health/detailed` | Detailed health (pool, circuit breakers) |
| `GET` | `/ready` | Readiness probe |
| `GET` | `/metrics` | Prometheus metrics |

## Data Flow

### Event Ingestion Flow

```
1. Agent creates event locally (SQLite outbox)
2. Agent signs event with Ed25519 private key
3. Agent POSTs to /api/v1/ves/events/ingest (or pushes via gRPC)
4. Sequencer authenticates request (API key, JWT, or agent signature)
5. Schema validation (if configured)
6. Sequencer verifies Ed25519 signature against registered public key
7. Sequencer deduplicates by event_id and command_id
8. Sequencer assigns sequence number atomically
9. Event stored in PostgreSQL events table (encrypted-at-rest if configured)
10. Sequencer returns receipt with sequence number
11. Agent marks event as synced locally
```

### x402 Payment Flow

```
1. Agent creates X402PaymentIntent with payer/payee/amount/asset
2. Agent signs intent with Ed25519 key (X402_PAYMENT_V1 domain separator)
3. Agent POSTs to /api/v1/x402/payments
4. Sequencer validates signature, checks nonce, verifies expiration
5. Sequencer assigns x402 sequence number atomically
6. Intent stored with status=Sequenced
7. Batch worker assembles intents into X402PaymentBatch (configurable size/time)
8. Batch worker computes Merkle root over payment intents
9. Batch submitted to SetPaymentBatch contract on Set Chain L2
10. On confirmation, intents marked Settled with tx_hash and block_number
11. Payment receipt with Merkle inclusion proof available for verification
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
| `events` | Append-only event log (legacy) |
| `ves_events` | VES v1.0 events with signatures |
| `sequence_counters` | Per-store sequence tracking |
| `ves_sequencer_receipts` | VES sequencer signed receipts |
| `commitments` | Legacy Merkle commitment records |
| `ves_commitments` | VES v1.0 Merkle commitments |
| `ves_compliance_proofs` | STARK compliance proofs |
| `ves_validity_proofs` | Batch validity proofs |
| `agent_signing_keys` | Agent public key registry with rotation |
| `entity_versions` | Entity version tracking (OCC) |
| `projection_checkpoints` | Projector progress |
| `agent_sync_state` | Agent sync state tracking |
| `rejected_events_log` | Event rejection audit log |
| `ves_rejections` | VES event rejection log |
| `x402_payment_intents` | x402 payment authorizations |
| `x402_payment_batches` | x402 aggregated payment batches |
| `x402_sequence_counters` | Per-store x402 sequence tracking |
| `x402_nonce_tracking` | x402 nonce replay protection |
| `api_keys` | API key management |

### Migrations

| Migration | Description |
|-----------|-------------|
| `001_production_postgres.sql` | Core event store, sequence counters, entity versions |
| `002_ves_v1_tables.sql` | VES v1.0 events, receipts, commitments, agent keys |
| `003_constraints.sql` | Unique indexes, chain TX hash validation |
| `004_ves_validity_proofs.sql` | Validity proof registry with stream matching |
| `005_ves_compliance_proofs.sql` | Compliance proof storage with stream matching |
| `006_key_rotation_policies.sql` | Agent key rotation policies |
| `007_encryption_groups.sql` | Encryption group management |
| `008_command_dedupe.sql` | Command deduplication indexes |
| `009_api_keys.sql` | API key management tables |
| `010_ves_sequence_counters.sql` | VES-specific sequence counters |
| `011_x402_payments.sql` | x402 payment intents and batches |

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

### x402 Payment Signing Hash

```
signing_hash = SHA256(
    "X402_PAYMENT_V1" ||      // Domain separator
    intent_id ||
    payer_address ||
    payee_address ||
    amount ||
    asset ||
    network ||
    chain_id ||
    nonce ||
    valid_until
)

payer_signature = Ed25519.Sign(agent_private_key, signing_hash)
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

### Encryption (HPKE)

Multi-recipient encryption for VES-ENC-1:

| Parameter | Value |
|-----------|-------|
| Mode | Base |
| KEM | X25519-HKDF-SHA256 |
| KDF | HKDF-SHA256 |
| AEAD | AES-256-GCM |

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
                    │ (HTTP or gRPC)    │
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
- **Read/Write Pool Splitting**: Separate connection pools for reads (replica) and writes (primary)
- **Database Pooling**: Configurable pool size, acquire timeout, idle timeout, max lifetime
- **Sequence Partitioning**: Each `(tenant_id, store_id)` is independent

### Performance Optimizations

- **Batch Inserts**: Events ingested in batches with parallel partitioning
- **Read Replicas**: Entity history and read queries served from replica pool
- **Multi-Layer Caching**: LRU caches for commitments, proofs, schemas, and agent keys
- **Proof Memoization**: Common proof paths cached with TTL
- **Connection Pool Monitoring**: Automatic health degradation detection

### Resilience

- **Circuit Breakers**: External service calls (L2 anchoring) protected with exponential backoff
- **Dead Letter Queue**: Failed projections queued with automatic retry
- **Graceful Shutdown**: Request draining on SIGTERM
- **Rate Limiting**: Per-tenant sliding-window rate limiter

### Capacity Planning

| Component | Recommended |
|-----------|-------------|
| PostgreSQL | 16+ GB RAM, SSD storage |
| Sequencer | 2-4 CPU cores, 4 GB RAM |
| Write Pool | 10-20 connections per instance |
| Read Pool | 10-20 connections per instance |
| Events/sec | ~1000-5000 depending on payload size |

## Security Model

### Trust Boundaries

1. **Agent <-> Sequencer**: TLS + Ed25519 signatures + API key/JWT auth
2. **Sequencer <-> Database**: Network isolation + credentials + session timeouts
3. **Sequencer <-> L2 Chain**: Private key for signing + circuit breaker
4. **Agent <-> Agent (payments)**: Ed25519 signed payment intents + nonce replay protection

### Key Management

- Agent private keys: Never leave agent, stored securely
- Sequencer signing key: For receipt signing (`VES_SEQUENCER_SIGNING_KEY`)
- Sequencer anchor key: For L2 transactions (`SEQUENCER_PRIVATE_KEY`)
- API keys: SHA-256 hashed, stored in PostgreSQL
- Database credentials: Environment variables, not in code
- Encryption keys: AES-256-GCM for payload encryption-at-rest

### Audit Trail

All administrative operations logged via the audit system:
- API key lifecycle (create, revoke, update)
- Schema registry changes
- Agent key operations
- Authentication events
- Dead letter queue operations

See [SECURITY.md](docs/SECURITY.md) for detailed security guidance.

## Configuration

### Feature Flags (Cargo Features)

| Feature | Default | Description |
|---------|---------|-------------|
| `full` | Yes | Enables all features |
| `grpc` | Yes | gRPC service (tonic/prost) |
| `telemetry` | Yes | OpenTelemetry distributed tracing |
| `anchoring` | Yes | L2 blockchain anchoring (alloy) |
| `schema-validation` | Yes | JSON Schema validation (jsonschema) |
| `sqlite` | No | SQLite backend for local agents |
| `encryption` | No | Payload encryption at rest |

### Key Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection URL (primary) |
| `READ_DATABASE_URL` | PostgreSQL connection URL (read replica) |
| `PORT` | HTTP listen port (default: 8080) |
| `GRPC_PORT` | gRPC listen port (default: PORT + 1) |
| `GRPC_DISABLED` | Disable gRPC server |
| `AUTH_MODE` | `required` (default) or `disabled` |
| `BOOTSTRAP_ADMIN_API_KEY` | Initial admin API key |
| `JWT_SECRET` | JWT signing secret |
| `VES_SEQUENCER_ID` | Pinned sequencer UUID |
| `VES_SEQUENCER_SIGNING_KEY` | Ed25519 key for receipt signing |
| `PAYLOAD_ENCRYPTION_MODE` | `disabled`, `optional`, `required` |
| `SCHEMA_VALIDATION_MODE` | `disabled`, `warn`, `required`, `strict` |
| `RATE_LIMIT_PER_MINUTE` | Request rate limit |
| `L2_RPC_URL` | Ethereum L2 RPC endpoint |
| `SET_REGISTRY_ADDRESS` | StateSetAnchor contract address |
| `SEQUENCER_PRIVATE_KEY` | Anchor transaction signing key |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry OTLP endpoint |
| `LOG_FORMAT` | `json` or `text` (default) |
| `CORS_ALLOW_ORIGINS` | Comma-separated origins or `*` |
| `DB_MIGRATE_ON_STARTUP` | Run migrations on boot (default: true) |
| `CACHE_*` | Cache size and TTL overrides |
| `MAX_DB_CONNECTIONS` | Write pool max connections |
| `READ_MAX_DB_CONNECTIONS` | Read pool max connections |
| `DB_STATEMENT_TIMEOUT_MS` | PostgreSQL statement timeout |
| `DB_IDLE_IN_TX_TIMEOUT_MS` | Idle-in-transaction timeout |

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Rust (Edition 2021) |
| Web Framework | Axum 0.7 |
| gRPC Framework | Tonic 0.12, Prost 0.13 |
| Async Runtime | Tokio |
| Database | PostgreSQL 16+ (sqlx 0.8) |
| Local Storage | SQLite (sqlx) |
| Cryptography | ed25519-dalek 2, sha2, aes-gcm |
| Key Exchange | x25519-dalek 2, hpke 0.12 |
| Merkle Trees | rs_merkle (custom domain separation) |
| Blockchain | Alloy 0.8 (Ethereum/EVM, Solidity ABI) |
| Schema Validation | jsonschema 0.26 |
| Authentication | jsonwebtoken 9 |
| Serialization | serde, serde_json, serde_json_canonicalizer (RFC 8785) |
| Observability | OpenTelemetry 0.24, tracing, Prometheus export |
| Testing | proptest, mockall, criterion, fake |

## Binaries

| Binary | Path | Description |
|--------|------|-------------|
| `stateset-sequencer` | `src/main.rs` | Main sequencer server (HTTP + gRPC) |
| `stateset-sequencer-admin` | `src/bin/admin.rs` | Admin CLI for key management, DLQ ops |

## Module Structure

```
src/
├── main.rs                  # Entry point
├── lib.rs                   # Library exports
├── server.rs                # HTTP + gRPC server bootstrap, config
├── anchor.rs                # On-chain anchoring (Alloy/Ethereum)
│
├── api/
│   ├── mod.rs               # REST router definition
│   └── handlers/
│       ├── agent_keys.rs    # Agent key registration
│       ├── anchoring.rs     # Commitment anchoring
│       ├── commitments.rs   # Commitment CRUD
│       ├── events.rs        # Event listing/retrieval
│       ├── health.rs        # Health, readiness, detailed checks
│       ├── ingest.rs        # Event ingestion pipeline
│       ├── proofs.rs        # Merkle proof generation/verification
│       ├── schemas.rs       # Schema registry management
│       ├── x402.rs          # x402 payment protocol
│       └── ves/
│           ├── mod.rs       # VES v1.0 handler organization
│           ├── anchoring.rs # VES commitment anchoring
│           ├── commitments.rs   # VES commitment management
│           ├── compliance_proofs.rs  # VES compliance proofs
│           ├── inclusion_proofs.rs   # VES inclusion proofs
│           └── validity_proofs.rs    # VES validity proofs
│
├── auth/
│   ├── mod.rs               # Auth module (Authenticator, ApiKeyValidator, JwtValidator)
│   ├── agent_keys.rs        # Agent key registry
│   └── middleware.rs         # Axum auth middleware + gRPC interceptor
│
├── crypto/
│   ├── hash.rs              # Domain-separated SHA-256 hashing
│   ├── signing.rs           # Ed25519 operations
│   └── encrypt.rs           # HPKE + AES-256-GCM encryption
│
├── domain/
│   ├── types.rs             # Core types (TenantId, StoreId, AgentId, etc.)
│   ├── event.rs             # EventEnvelope
│   ├── commitment.rs        # BatchCommitment, MerkleProof
│   ├── schema.rs            # Schema, SchemaId, SchemaCompatibility
│   ├── ves_event.rs         # VES v1.0 events
│   ├── ves_commitment.rs    # VES batch commitments
│   ├── ves_compliance.rs    # VES compliance proof types
│   ├── ves_validity.rs      # VES validity proof types
│   └── x402_payment.rs      # x402 payment intents, batches, receipts
│
├── grpc/
│   ├── mod.rs               # gRPC module
│   ├── service.rs           # gRPC v1 service implementation
│   ├── service_v2.rs        # gRPC v2 service (streaming, key management)
│   └── interceptor.rs       # gRPC auth interceptor
│
├── infra/
│   ├── mod.rs               # Infrastructure module + trait exports
│   ├── traits.rs            # Core service traits (EventStore, Sequencer, etc.)
│   ├── error.rs             # SequencerError, contextual errors
│   ├── audit.rs             # Audit logging
│   ├── batch.rs             # Batch operations, deduplication
│   ├── cache.rs             # Multi-layer LRU caching
│   ├── circuit_breaker.rs   # Circuit breaker pattern
│   ├── dead_letter.rs       # Dead letter queue
│   ├── graceful_shutdown.rs # Graceful shutdown coordination
│   ├── payload_encryption.rs # Encryption-at-rest configuration
│   ├── pool_monitor.rs      # Connection pool health monitoring
│   ├── retry.rs             # Exponential backoff retry
│   ├── schema_validation.rs # Schema validation mode handling
│   ├── x402_batch_worker.rs # x402 batch assembly background worker
│   ├── ves_commitment.rs    # PgVesCommitmentEngine
│   ├── ves_compliance.rs    # PgVesComplianceProofStore
│   ├── ves_validity.rs      # PgVesValidityProofStore
│   ├── postgres/
│   │   ├── sequencer.rs     # PgSequencer (legacy)
│   │   ├── ves_sequencer.rs # VesSequencer (VES v1.0)
│   │   ├── event_store.rs   # PgEventStore
│   │   ├── commitment.rs    # PgCommitmentEngine
│   │   ├── agent_key_registry.rs  # PgAgentKeyRegistry
│   │   ├── schema_store.rs  # PgSchemaStore
│   │   └── x402_repository.rs    # PgX402Repository
│   └── sqlite/
│       └── outbox.rs        # SqliteOutbox (local agents)
│
├── metrics/
│   └── mod.rs               # MetricsRegistry, ComponentMetrics, Prometheus export
│
├── migrations/
│   ├── mod.rs               # Migration runner
│   ├── postgres/            # 11 PostgreSQL migrations
│   └── sqlite/              # 1 SQLite migration
│
├── projection/
│   ├── runner.rs            # Projection executor
│   └── handlers.rs          # Domain projection handlers
│
├── proto/                   # Generated protobuf code
│   ├── mod.rs               # Proto module (v1 + v2)
│   └── v2/                  # gRPC v2 generated code
│
├── telemetry/
│   └── mod.rs               # OpenTelemetry setup, OTLP export
│
└── bin/
    └── admin.rs             # Admin CLI binary
```

## Related Documentation

- [Getting Started](GETTING_STARTED.md) - Quick start guide
- [System Overview](SYSTEM_OVERVIEW.md) - High-level system overview
- [VES Specification](docs/VES_SPEC.md) - Full protocol spec
- [API Reference](docs/API_REFERENCE.md) - REST API documentation
- [Event Types](docs/EVENT_TYPES.md) - Supported event types
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment
- [Runbook](docs/RUNBOOK.md) - Operational runbook
- [Security Guide](docs/SECURITY.md) - Security best practices
- [ZK Integration Guide](docs/ZK_INTEGRATION_GUIDE.md) - STARK proof integration
- [Agent Integration](docs/AGENT_INTEGRATION.md) - Agent SDK integration guide
- [Anchoring Overview](docs/ANCHORING_OVERVIEW.md) - On-chain anchoring details

## Related Repositories

| Repository | Purpose |
|------------|---------|
| `stateset-stark` | STARK proving system for compliance proofs |
| `@stateset/cli` | AI agent CLI with local SQLite outbox |
| `set-chain` | Ethereum L2 for anchoring commitments and payment settlement |
