# StateSet Sequencer

![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![codecov](https://codecov.io/gh/stateset/stateset-sequencer/branch/master/graph/badge.svg)

**Minimum supported Rust version: 1.90**, declared as `rust-version` in
`Cargo.toml` and enforced by a CI job that builds the default feature set on
exactly that toolchain. The floor is set by the `ves-stark-*` crates, which
require 1.90. CI also runs `cargo fmt`, `clippy -D warnings`, the full test
suite against PostgreSQL, `cargo audit` and `cargo deny` on every push.

Verifiable Event Sync (VES) v1.0 service for deterministic event ordering, state projection, cryptographic commitments, and zero-knowledge compliance proofs.

## Overview

The StateSet Sequencer is the **central truth clock** for distributed commerce systems, bridging AI agents with cryptographically verifiable infrastructure. It implements the complete VES v1.0 protocol specification.

### Key Features

- **Deterministic Event Ordering**: Monotonic sequence numbers per (tenant, store) pair
- **Exactly-Once Delivery**: Idempotent event ingestion with event_id and command_id deduplication
- **Cryptographic Commitments**: Merkle trees with domain-separated hashing for audit trails
- **Agent Signatures**: Ed25519 signature verification for event authenticity
- **STARK Compliance Proofs**: Zero-knowledge proofs for regulatory compliance
- **On-Chain Anchoring**: Ethereum L2 commitment anchoring for trustless verification
- **Offline-First**: SQLite outbox pattern for local CLI agents
- **Payload Encryption**: AES-GCM encryption at rest with key rotation support
- **Schema Validation**: JSON Schema validation for event payloads
- **x402 Payments**: Payment intents, nonce-replay protection, Merkle-batched
  settlement, and HTTP `402 Payment Required` gating for metered routes
- **Autonomous Settlement**: Optional worker that settles committed payment
  batches on-chain via the `SetPaymentBatch` contract
- **Distributed / HA**: Multiple nodes may run against one database; singleton
  workers (anchoring, batching, settlement) are leader-elected through
  PostgreSQL advisory locks with automatic failover

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API Layer (Axum)                               │
│  POST /api/v1/ves/events/ingest  │  GET /api/v1/ves/commitments            │
│  POST /api/v1/ves/validity-proofs │  POST /api/v1/ves/compliance-proofs    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Service Layer                                   │
│  Sequencer │ EventStore │ CommitmentEngine │ Projector │ AgentKeyRegistry  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PostgreSQL (Source of Truth)                           │
│  events │ ves_events │ sequence_counters │ batch_commitments │ api_keys    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
           ┌───────────────┐               ┌───────────────┐
           │ STARK Prover  │               │ Ethereum L2   │
           │ (ZK Proofs)   │               │ (Anchoring)   │
           └───────────────┘               └───────────────┘
```

### Data Flow

```
CLI Agent / AI Agent                 Sequencer                     PostgreSQL
       │                                │                              │
       │── POST /ves/events/ingest ────▶│                              │
       │   (signed event envelope)      │                              │
       │                                │── Verify Ed25519 signature ──│
       │                                │── SELECT FOR UPDATE ────────▶│
       │                                │   (atomic sequence assign)   │
       │                                │── INSERT ves_event ─────────▶│
       │                                │                              │
       │◀── IngestReceipt ─────────────│                              │
       │    (sequence #, signed receipt)│                              │
```

## Quick Start

### Using Docker Compose

```bash
# Start the sequencer and PostgreSQL
docker-compose up -d

# Check health
curl http://localhost:8080/health

# Check readiness (verifies database connectivity)
curl http://localhost:8080/ready

# Example: Get head sequence (with bootstrap admin key)
curl -H "Authorization: ApiKey dev_admin_key" \
  "http://localhost:8080/api/v1/ves/head?tenant_id=<uuid>&store_id=<uuid>"
```

### Local Development

```bash
# Build the project
cargo build

# Set required environment variables
export DATABASE_URL="postgres://sequencer:sequencer@localhost:5433/stateset_sequencer"
export BOOTSTRAP_ADMIN_API_KEY="dev_admin_key"
export ALLOW_INSECURE_LOCAL_DB=true

# Run the server (migrations run automatically)
cargo run

# Or run migrations manually
cargo run --bin stateset-sequencer-admin -- migrate

# Backfill VES state roots (if upgrading from older versions)
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots
```

### Cargo features

The default build enables `full`. Notable feature flags:

| Feature | Enables |
|---------|---------|
| `pqc` | Post-quantum crypto (ML-DSA-65, ML-KEM-768) |
| `stark` | STARK validity/compliance proof verification |
| `integration` | Test-only modules that need a live database |

gRPC, OpenTelemetry, L2 anchoring, JSON Schema validation and the SQLite outbox
are **always compiled in** and are not behind feature flags. They were once
listed as flags, but each was an empty feature that gated no code, so turning
one "off" changed nothing about the resulting binary. They were removed rather
than left as no-ops.

**The `stark` feature** depends on the `ves-stark-*` crates in the separate
[`stateset-starks`](https://github.com/stateset/stateset-starks) workspace, expected
at `../stateset-stark`. They are **path dependencies that cargo must resolve even
when the feature is off**, so that checkout must be present to build at all.

To build/test the core sequencer **without** the STARK proof endpoints (e.g. if
you don't have `stateset-stark` checked out alongside this repo, the proof
endpoints are simply not mounted):

```bash
cargo build --no-default-features --features pqc
```

### Upgrading the STARK dependency

`stateset-stark` is a **path dependency on a separate repository**, so its
commits are not captured by this repo's `Cargo.lock` on their own. CI pins it to
an exact commit via the `STARK_REF` variable in `.github/workflows/ci.yml`.

Tracking its default branch instead meant every upstream commit silently
invalidated `Cargo.lock` and turned every `--locked` CI job red, with no change
in this repository. Upgrade deliberately, in a single commit:

```bash
# 1. Move the local checkout to the commit you want
git -C ../stateset-stark checkout <new-sha>

# 2. Re-resolve the ves-stark-* crates
cargo update -p ves-stark-prover -p ves-stark-verifier \
             -p ves-stark-primitives -p ves-stark-batch

# 3. Verify, then commit Cargo.lock and the new STARK_REF together
cargo test --locked --all-targets
```

> **CI note:** CI fetches the `ves-stark-*` crates from the public
> [`stateset/stateset-starks`](https://github.com/stateset/stateset-starks)
> repository (note the trailing `s`) at the commit pinned by `STARK_REF`. No
> secret is required; a `STARK_REPO_TOKEN` repository secret is honoured if the
> repo is ever made private. The lint/test/coverage jobs build with the core feature
> set (no `stark`) so they don't compile the private crates.

## AI Agent SDKs and MCP

The Node.js and Python agent SDKs create correctly canonicalized and signed VES events,
performs idempotent retries, reads entity history, follows sequence cursors, and
retrieves inclusion proofs. It also exports OpenAI-compatible function tools and
a policy-constrained MCP stdio server. See [AI agent integration](docs/AGENT_INTEGRATION.md)
and the [Node SDK guide](cli/README.md) or [Python SDK guide](sdk/python/README.md).
Maintainers should complete the one-time trusted-publisher setup in the
[release guide](docs/RELEASING.md) before the first registry release.

Private signing keys remain inside the tool host and are never exposed to model
context. Local validation hooks run before signing, while authoritative
per-agent allowlists, optimistic-concurrency requirements, and payload limits
are enforced again by the sequencer.

## API Endpoints

### VES Event Ingestion

```bash
POST /api/v1/ves/events/ingest
Authorization: ApiKey <key>
Content-Type: application/json

{
  "agentId": "uuid",
  "events": [
    {
      "ves_version": 1,
      "event_id": "uuid",
      "tenant_id": "uuid",
      "store_id": "uuid",
      "source_agent_id": "uuid",
      "agent_key_id": 1,
      "entity_type": "order",
      "entity_id": "order-123",
      "event_type": "order.created",
      "created_at": "2026-09-04T12:00:00.000Z",
      "payload_kind": 0,
      "payload": { "customer_id": "cust-456", "total": 99.99 },
      "payload_plain_hash": "0x<32-byte-hash>",
      "payload_cipher_hash": "0x<32-zero-bytes>",
      "agent_signature": "0x<64-byte-ed25519-signature>",
      "command_id": "uuid",
      "base_version": 0
    }
  ]
}
```
Note: `events` must contain at least one event.

**Response:**
```json
{
  "eventsAccepted": 1,
  "eventsRejected": 0,
  "headSequence": 42,
  "receipts": [
    {
      "eventId": "uuid",
      "sequenceNumber": 42,
      "receiptHash": "0x<32-byte-hash>",
      "sequencerSignature": "0x<64-byte-ed25519-signature>"
    }
  ]
}
```

### VES Reads

```bash
# Canonical stream head and bounded range
GET /api/v1/ves/head?tenant_id=<uuid>&store_id=<uuid>
GET /api/v1/ves/events?tenant_id=<uuid>&store_id=<uuid>&from=1&limit=100

# Paged history for one entity
GET /api/v1/ves/entities/{entity_type}/{entity_id}?tenant_id=<uuid>&store_id=<uuid>&from=0&limit=100

# Read and monotonically acknowledge this agent's durable consumer cursor
GET /api/v1/ves/cursors/{agent_id}?tenant_id=<uuid>&store_id=<uuid>
PUT /api/v1/ves/cursors/{agent_id}
{
  "tenantId": "uuid",
  "storeId": "uuid",
  "sequenceNumber": 42
}
```

### VES Commitments

```bash
# List commitments
GET /api/v1/ves/commitments?tenant_id=<uuid>&store_id=<uuid>

# Create commitment for sequence range
POST /api/v1/ves/commitments
{
  "tenant_id": "uuid",
  "store_id": "uuid",
  "sequence_start": 1,
  "sequence_end": 100
}

# Anchor a commitment on-chain
POST /api/v1/ves/anchor
```

### VES Proofs

```bash
# Submit validity proof (batch ZK proof)
POST /api/v1/ves/validity-proofs
{
  "batch_id": "uuid",
  "proof_type": "stark",
  "proof_data": "base64-encoded-proof",
  "public_inputs": { ... }
}

# Submit compliance proof (per-event encrypted proof)
POST /api/v1/ves/compliance-proofs
{
  "event_id": "uuid",
  "proof_type": "stark",
  "encrypted_payload": "base64-encoded",
  "public_inputs": { ... }
}

# Get and verify a sequence inclusion proof
GET /api/v1/ves/proofs/{sequence_number}?tenant_id=<uuid>&store_id=<uuid>
POST /api/v1/ves/proofs/verify
```

### Agent Key Management

```bash
# Register agent public key
POST /api/v1/agents/keys
{
  "tenantId": "uuid",
  "agentId": "uuid",
  "keyId": 1,
  "publicKey": "0x<32-byte-ed25519-public-key>",
  "validFrom": "2026-01-01T00:00:00Z",
  "validTo": "2027-01-01T00:00:00Z"
}

# Read agent registration and manage its API credentials
GET /api/v1/agents/{agent_id}
GET /api/v1/agents/{agent_id}/api-keys
DELETE /api/v1/agents/{agent_id}/api-keys/{key_prefix}

# Admin: enforce the actions this agent may append
PUT /api/v1/agents/{agent_id}/policy
{
  "tenantId": "uuid",
  "allowedEventTypes": ["order.*", "inventory.reserved"],
  "allowedEntityTypes": ["order", "inventory_item"],
  "requireBaseVersion": true,
  "maxPayloadBytes": 65536,
  "enabled": true
}
GET /api/v1/agents/{agent_id}/policy?tenant_id=<uuid>
```

### Read APIs

```bash
# Get events (legacy format)
GET /api/v1/events?tenant_id=<uuid>&store_id=<uuid>&from=0&limit=100

# Get head sequence
GET /api/v1/head?tenant_id=<uuid>&store_id=<uuid>

# Get entity history
GET /api/v1/entities/{entity_type}/{entity_id}?tenant_id=<uuid>&store_id=<uuid>

# Get the latest durable materialized VES state (use source=legacy for the legacy ledger)
GET /api/v1/projections/{entity_type}/{entity_id}?tenant_id=<uuid>&store_id=<uuid>&source=ves
```

### x402 Payments

```bash
# Submit a payment intent (sequenced atomically with its nonce reservation)
POST /api/v1/x402/payments
curl -X POST http://localhost:8080/api/v1/x402/payments \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d @intent.json

# List / fetch intents
GET  /api/v1/x402/payments
GET  /api/v1/x402/payments/:intent_id
GET  /api/v1/x402/payments/:intent_id/receipt   # Merkle inclusion receipt

# Batches
POST /api/v1/x402/batches                       # create a batch
GET  /api/v1/x402/batches/:batch_id
POST /api/v1/x402/batches/settle                # settle a committed batch
```

A batch is committed atomically: its intents are claimed (`sequenced` →
`batched`), read back in sequence order, hashed into a Merkle root, and the
batch marked committed in one transaction — so a crash cannot strand intents
under an uncommitted batch.

### Metered Routes (HTTP 402)

Routes can be gated behind payment. The bundled example returns
`402 Payment Required` with the payment requirements until a valid intent is
presented:

```bash
GET /api/v1/x402/premium/insights
```

Configure via the `X402_PREMIUM_ROUTE_*` variables below.

### Health & Metrics

```bash
GET /health     # Basic health check
GET /ready      # Readiness check (database connectivity)
GET /metrics    # Prometheus metrics
```

## Supported Event Types

| Domain | Event Types |
|--------|-------------|
| **Orders** | `order.created`, `order.confirmed`, `order.shipped`, `order.delivered`, `order.cancelled` |
| **Inventory** | `inventory.initialized`, `inventory.adjusted`, `inventory.reserved`, `inventory.released` |
| **Products** | `product.created`, `product.updated`, `product.deactivated` |
| **Customers** | `customer.created`, `customer.updated`, `customer.address_added` |
| **Returns** | `return.requested`, `return.approved`, `return.received`, `return.refunded` |

## Configuration

The essentials for a local boot:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `PORT` | `8080` | HTTP listen port |
| `BOOTSTRAP_ADMIN_API_KEY` | (unset) | Admin API key for bootstrap/dev |
| `AUTH_MODE` | `required` | `required` or `disabled` (needs `ALLOW_AUTH_DISABLED=true`) |
| `PAYLOAD_ENCRYPTION_MODE` | `required` | `disabled`, `optional`, or `required` |
| `RUST_LOG` | `info` | Log level filter |

Everything else — database pool tuning, caching, authentication, client-IP /
proxy trust, rate limiting, payload encryption, anchoring, x402 payments,
autonomous settlement, durable projections, HA / leader election, STARK
verification and automated proof generation, and observability — is documented per-variable in
**[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**.

## Project Structure

```
stateset-sequencer/
├── src/
│   ├── main.rs                 # Binary entry point
│   ├── lib.rs                  # Library exports
│   ├── server.rs               # HTTP server bootstrap
│   ├── anchor.rs               # On-chain anchoring service
│   ├── settlement.rs           # On-chain x402 batch settlement
│   ├── migrations.rs           # Migration runner
│   ├── api/                    # REST API layer
│   │   ├── mod.rs              # Router configuration
│   │   ├── types.rs            # Request/response types
│   │   ├── auth_helpers.rs     # Auth extraction helpers
│   │   └── handlers/           # Endpoint handlers
│   │       ├── ingest.rs       # Event ingestion
│   │       ├── events.rs       # Event queries
│   │       ├── commitments.rs  # Batch commitments
│   │       ├── agent_keys.rs   # Agent key management
│   │       ├── agent_policies.rs # Server-enforced agent capabilities
│   │       ├── schemas.rs      # Schema registry
│   │       ├── x402.rs         # x402 payment intents & batches
│   │       └── ves/            # VES v1.0 endpoints
│   │   └── middleware/
│   │       └── payment_required.rs  # HTTP 402 gating for metered routes
│   ├── auth/                   # Authentication
│   │   ├── api_key.rs          # API key validation & storage
│   │   ├── jwt.rs              # JWT validation
│   │   ├── middleware.rs       # Auth middleware & rate limiting
│   │   └── agent_keys.rs       # Agent key types
│   ├── crypto/                 # Cryptographic utilities
│   │   ├── hash.rs             # Domain-separated SHA-256
│   │   ├── signing.rs          # Ed25519 signatures
│   │   └── encrypt.rs          # HPKE encryption
│   ├── domain/                 # Core domain types
│   │   ├── types.rs            # TenantId, StoreId, AgentId, Hash256
│   │   ├── event.rs            # EventEnvelope, SequencedEvent
│   │   ├── ves_event.rs        # VES v1.0 event types
│   │   ├── commitment.rs       # BatchCommitment, MerkleProof
│   │   ├── ves_commitment.rs   # VES commitment types
│   │   ├── ves_validity.rs     # Validity proof types
│   │   ├── ves_compliance.rs   # Compliance proof types
│   │   └── schema.rs           # Schema definitions
│   ├── infra/                  # Infrastructure implementations
│   │   ├── traits.rs           # Service trait definitions
│   │   ├── error.rs            # Error types
│   │   ├── net.rs              # Trusted-proxy client IP resolution
│   │   ├── x402_batch_worker.rs     # Payment batching worker
│   │   ├── settlement_worker.rs     # On-chain settlement worker
│   │   ├── postgres/           # PostgreSQL implementations
│   │   │   ├── sequencer.rs    # Atomic sequence assignment
│   │   │   ├── ves_sequencer.rs # VES v1.0 sequencer
│   │   │   ├── event_store.rs  # Event storage
│   │   │   ├── agent_keys.rs   # Agent key registry
│   │   │   ├── agent_policy.rs # Agent capability policies
│   │   │   ├── agent_cursor.rs # Durable consumer cursors
│   │   │   └── schema_store.rs # Schema storage
│   │   ├── sqlite/             # SQLite implementations
│   │   │   └── outbox.rs       # Local agent outbox
│   │   ├── commitment.rs       # Merkle tree engine
│   │   ├── ves_commitment.rs   # VES commitment engine
│   │   ├── ves_validity.rs     # Validity proof storage
│   │   ├── ves_compliance.rs   # Compliance proof storage
│   │   ├── payload_encryption.rs # AES-GCM encryption
│   │   └── schema_validation.rs  # JSON Schema validation
│   ├── projection/             # Event projection
│   │   ├── runner.rs           # Projection runner
│   │   └── handlers.rs         # Domain-specific handlers
│   ├── grpc/                   # gRPC service (optional)
│   ├── proto/                  # Protocol buffer definitions
│   └── metrics/                # Observability
├── migrations/
│   ├── postgres/               # Versioned PostgreSQL schema migrations
│   └── sqlite/                 # SQLite migrations (local agents)
├── tests/                      # Integration tests
├── benches/                    # Performance benchmarks
├── contracts/                  # Smart contracts (Ethereum L2)
├── schemas/                    # Event schema definitions
├── docs/                       # Additional documentation
├── Dockerfile
├── docker-compose.yml
└── Cargo.toml
```

## Security Features

| Feature | Implementation |
|---------|----------------|
| **API Key Hashing** | SHA-256 (never stored in plaintext) |
| **Agent Signatures** | Ed25519 with key rotation support |
| **Payload Encryption** | AES-256-GCM with per-tenant keyrings |
| **Rate Limiting** | Per-tenant with bounded memory (LRU eviction) |
| **Request Limits** | Configurable body size and batch limits |
| **Agent Capabilities** | Server-enforced event/entity allowlists, concurrency requirements, and payload limits |
| **Durable Consumption** | Monotonic per-agent cursors shared by REST and gRPC |
| **STARK Proofs** | Zero-knowledge compliance verification |
| **Amount Binding** | Compliance proofs are rejected unless the committed amount matches the amount re-derived from the stored payload |
| **Client IP Resolution** | Forwarded headers honoured only from trusted proxies, and read from the right of the chain (see [Client IP and Proxies](docs/CONFIGURATION.md#client-ip-and-proxies)) |
| **Admin IP Allowlist** | Optional IP/CIDR restriction on admin and metrics routes, layered on top of admin authentication |
| **Replay Protection** | Event/command ID deduplication and x402 nonce reservation, both inside the sequencing transaction |

## Cryptographic Guarantees

1. **Gap-Free Sequences**: No missing sequence numbers within a stream
2. **Linearizable Ordering**: Total ordering via PostgreSQL `SELECT FOR UPDATE`
3. **Verifiable History**: Merkle proofs for event inclusion verification
4. **Domain Separation**: All hashes include domain separators per VES spec
5. **Immutable Log**: Append-only event storage with no mutations

## Testing

```bash
# Unit tests and any integration test that needs no database
cargo test

# Everything, including the database-backed tests
export DATABASE_URL=postgres://user:pass@localhost:5432/stateset_sequencer
cargo test --tests -- --include-ignored

# Run with output
cargo test -- --nocapture

# Benchmarks (Criterion; see docs/PERFORMANCE_BENCHMARKS.md for recorded results)
cargo bench
```

Database-backed tests **skip** when `DATABASE_URL` is unset, and **fail** when
it is set but the database cannot be reached — a test is never allowed to pass
merely because its database was missing. Set `SEQUENCER_REQUIRE_DB_TESTS=1` (as
CI does) to turn a missing `DATABASE_URL` into a failure too, so a
misconfigured environment cannot be mistaken for a green run.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | (unset) | Database for the database-backed tests; unset skips them |
| `SEQUENCER_REQUIRE_DB_TESTS` | `false` | Fail rather than skip when `DATABASE_URL` is absent |

## Kubernetes

Two production-oriented deployment paths are maintained and validated in CI:

- `kubectl apply -k k8s` for the GKE/Cloud SQL Proxy deployment.
- `helm upgrade --install sequencer ./charts/stateset-sequencer` for portable
  Kubernetes deployments. See
  [`charts/stateset-sequencer/README.md`](charts/stateset-sequencer/README.md)
  for its required Secret and feature flags.

Both paths run the sequencer as a non-root user with privilege escalation
disabled, Linux capabilities dropped, health probes, and resource limits.

## Admin CLI

A second binary, `stateset-sequencer-admin`, handles operational tasks. Every
command takes `--database-url` (defaulting to `DATABASE_URL`).

```bash
cargo run --bin stateset-sequencer-admin -- <command> [options]
cargo run --bin stateset-sequencer-admin -- help <command>   # per-command help
```

| Command | Purpose |
|---------|---------|
| `migrate` | Run database migrations |
| `verify-proof` | Verify a Merkle inclusion proof |
| `export-events` | Export events to a JSON/NDJSON file |
| `rotate-keys` | Rotate agent signing keys |
| `list-agent-keys` | List agent keys for a tenant |
| `reencrypt-events` | Re-encrypt event payloads under a new key |
| `reencrypt-ves-validity-proofs` | Re-encrypt stored validity proofs |
| `reencrypt-ves-compliance-proofs` | Re-encrypt stored compliance proofs |
| `backfill-ves-state-roots` | Backfill VES state roots (upgrades from older versions) |
| `ves-commit-and-anchor` | Create a VES commitment and anchor it on-chain |
| `commands` | List available commands |

```bash
# Run migrations
cargo run --bin stateset-sequencer-admin -- migrate

# Backfill VES state roots
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots

# Preview changes without writing
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots --dry-run
```

## License

MIT
