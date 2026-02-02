# StateSet Sequencer

![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![codecov](https://codecov.io/gh/stateset/stateset-sequencer/branch/main/graph/badge.svg)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)
![Security](https://img.shields.io/badge/security-audited-green)
![Documentation](https://img.shields.io/badge/docs-passing-blue)

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
       │    (sequence #, merkle proof)  │                              │
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
  "http://localhost:8080/api/v1/head?tenant_id=<uuid>&store_id=<uuid>"
```

### Local Development

```bash
# Build the project
cargo build

# Set required environment variables
export DATABASE_URL="postgres://localhost/stateset_sequencer"
export BOOTSTRAP_ADMIN_API_KEY="dev_admin_key"

# Run the server (migrations run automatically)
cargo run

# Or run migrations manually
cargo run --bin stateset-sequencer-admin -- migrate

# Backfill VES state roots (if upgrading from older versions)
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots
```

## API Endpoints

### VES Event Ingestion

```bash
POST /api/v1/ves/events/ingest
Authorization: ApiKey <key>
Content-Type: application/json

{
  "events": [
    {
      "event_id": "uuid",
      "tenant_id": "uuid",
      "store_id": "uuid",
      "entity_type": "order",
      "entity_id": "order-123",
      "event_type": "order.created",
      "payload": { "customer_id": "cust-456", "total": 99.99 },
      "base_version": 0,
      "source_agent": "uuid",
      "signature": "base64-encoded-ed25519-signature",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

**Response:**
```json
{
  "receipts": [
    {
      "event_id": "uuid",
      "sequence_number": 42,
      "payload_hash": "sha256-hex",
      "merkle_proof": { ... },
      "sequencer_signature": "base64-encoded"
    }
  ]
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

# Anchor commitment on-chain
POST /api/v1/ves/commitments/{batch_id}/anchor
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

# Get inclusion proof for an event
GET /api/v1/ves/inclusion-proofs/{event_id}
```

### Agent Key Management

```bash
# Register agent public key
POST /api/v1/agent-keys
{
  "tenant_id": "uuid",
  "agent_id": "uuid",
  "public_key": "base64-encoded-ed25519-public-key",
  "valid_from": "2025-01-01T00:00:00Z",
  "valid_until": "2026-01-01T00:00:00Z"
}

# List agent keys
GET /api/v1/agent-keys?tenant_id=<uuid>&agent_id=<uuid>

# Revoke agent key
DELETE /api/v1/agent-keys/{key_id}
```

### Legacy Endpoints

```bash
# Get events (legacy format)
GET /api/v1/events?tenant_id=<uuid>&store_id=<uuid>&from=0&limit=100

# Get head sequence
GET /api/v1/head?tenant_id=<uuid>&store_id=<uuid>

# Get entity history
GET /api/v1/entities/{entity_type}/{entity_id}?tenant_id=<uuid>&store_id=<uuid>
```

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

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://localhost/stateset_sequencer` | PostgreSQL connection URL |
| `READ_DATABASE_URL` | (unset) | Optional read replica URL (routes read traffic to a separate pool) |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8080` | Server port |
| `MAX_DB_CONNECTIONS` | `10` | Write pool max connections |
| `MIN_DB_CONNECTIONS` | `0` | Write pool minimum idle connections |
| `READ_MAX_DB_CONNECTIONS` | `MAX_DB_CONNECTIONS` | Read pool max connections (if `READ_DATABASE_URL` set) |
| `READ_MIN_DB_CONNECTIONS` | `0` | Read pool minimum idle connections |
| `DB_APPLICATION_NAME` | `stateset-sequencer` | PostgreSQL `application_name` for write pool |
| `READ_DB_APPLICATION_NAME` | `${DB_APPLICATION_NAME}-read` | PostgreSQL `application_name` for read pool |
| `DB_MIGRATE_ON_STARTUP` | `true` | Auto-run SQL migrations on startup |
| `PUBLIC_AGENT_REGISTRATION_ENABLED` | `true` | Enable public agent self-registration |
| `TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-For` / `Forwarded` / `X-Real-IP` when extracting client IPs |

### Database Pool Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_ACQUIRE_TIMEOUT_MS` | (unset) | Write pool connection acquisition timeout |
| `DB_IDLE_TIMEOUT_SECS` | (unset) | Write pool idle connection timeout |
| `DB_MAX_LIFETIME_SECS` | (unset) | Write pool max connection lifetime |
| `READ_DB_ACQUIRE_TIMEOUT_MS` | (unset) | Read pool connection acquisition timeout |
| `READ_DB_IDLE_TIMEOUT_SECS` | (unset) | Read pool idle connection timeout |
| `READ_DB_MAX_LIFETIME_SECS` | (unset) | Read pool max connection lifetime |

### Database Session Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_STATEMENT_TIMEOUT_MS` | (unset) | PostgreSQL `statement_timeout` (ms) |
| `DB_IDLE_IN_TX_TIMEOUT_MS` | (unset) | PostgreSQL `idle_in_transaction_session_timeout` (ms) |
| `DB_LOCK_TIMEOUT_MS` | (unset) | PostgreSQL `lock_timeout` (ms) |

### Cache Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_COMMITMENT_MAX` | `1000` | Max legacy commitment cache entries |
| `CACHE_COMMITMENT_TTL_SECS` | `300` | Legacy commitment cache TTL (seconds) |
| `CACHE_PROOF_MAX` | `5000` | Max legacy proof cache entries |
| `CACHE_PROOF_TTL_SECS` | `600` | Legacy proof cache TTL (seconds) |
| `CACHE_VES_COMMITMENT_MAX` | `CACHE_COMMITMENT_MAX` | Max VES commitment cache entries |
| `CACHE_VES_COMMITMENT_TTL_SECS` | `CACHE_COMMITMENT_TTL_SECS` | VES commitment cache TTL (seconds) |
| `CACHE_VES_PROOF_MAX` | `CACHE_PROOF_MAX` | Max VES proof cache entries |
| `CACHE_VES_PROOF_TTL_SECS` | `CACHE_PROOF_TTL_SECS` | VES proof cache TTL (seconds) |
| `CACHE_AGENT_KEY_MAX` | `1000` | Max agent key cache entries |
| `CACHE_AGENT_KEY_TTL_SECS` | `3600` | Agent key cache TTL (seconds) |
| `CACHE_SCHEMA_MAX` | `1000` | Max schema cache entries |
| `CACHE_SCHEMA_TTL_SECS` | `600` | Schema cache TTL (seconds) |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_MODE` | `required` | `required` or `disabled` |
| `BOOTSTRAP_ADMIN_API_KEY` | (unset) | Admin API key for bootstrap/dev |
| `JWT_SECRET` | (unset) | HMAC secret for JWT validation |
| `JWT_ISSUER` | `stateset-sequencer` | Expected JWT issuer claim |
| `JWT_AUDIENCE` | `stateset-api` | Expected JWT audience claim |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_PER_MINUTE` | (unset) | Global per-tenant rate limit |
| `RATE_LIMIT_MAX_ENTRIES` | `10000` | Max tracked rate limit entries |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window duration |
| `PUBLIC_AGENT_REGISTRATION_RATE_LIMIT_PER_MINUTE` | (unset) | Per-IP rate limit for public agent registration |
| `PUBLIC_AGENT_REGISTRATION_MAX_ENTRIES` | `10000` | Max tracked public registration rate limit entries |
| `PUBLIC_AGENT_REGISTRATION_WINDOW_SECONDS` | `60` | Public registration rate limit window duration |

### Request Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_BODY_SIZE_BYTES` | `10485760` | Maximum request body size (10MB) |
| `MAX_EVENTS_PER_BATCH` | `1000` | Maximum events per ingest batch |
| `MAX_EVENT_PAYLOAD_SIZE` | `1048576` | Maximum payload size per event (1MB) |

### Payload Encryption

| Variable | Default | Description |
|----------|---------|-------------|
| `PAYLOAD_ENCRYPTION_MODE` | `required` | `disabled`, `optional`, or `required` |
| `PAYLOAD_ENCRYPTION_KEY` | (unset) | Single 32-byte key (hex or base64) |
| `PAYLOAD_ENCRYPTION_KEYS` | (unset) | Comma-separated keyring (current first) |
| `PAYLOAD_ENCRYPTION_KEYS_BY_TENANT` | (unset) | JSON map of tenant-specific keyrings |

### VES Sequencer

| Variable | Default | Description |
|----------|---------|-------------|
| `VES_SEQUENCER_SIGNING_KEY` | (unset) | Ed25519 private key for receipt signing |
| `SCHEMA_VALIDATION_MODE` | `warn` | `disabled`, `warn`, or `strict` |

### On-Chain Anchoring

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_RPC_URL` | (unset) | Ethereum L2 RPC endpoint |
| `SET_REGISTRY_ADDRESS` | (unset) | StateSet registry contract address |
| `SEQUENCER_PRIVATE_KEY` | (unset) | Private key for anchor transactions |
| `L2_CHAIN_ID` | (unset) | L2 chain ID |

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level filter |
| `LOG_FORMAT` | (unset) | Set to `json` for JSON logging |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (unset) | OpenTelemetry OTLP endpoint |
| `CORS_ALLOW_ORIGINS` | (unset) | CORS origins (`*` or comma-separated) |

## Project Structure

```
stateset-sequencer/
├── src/
│   ├── main.rs                 # Binary entry point
│   ├── lib.rs                  # Library exports
│   ├── server.rs               # HTTP server bootstrap
│   ├── anchor.rs               # On-chain anchoring service
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
│   │       ├── schemas.rs      # Schema registry
│   │       └── ves/            # VES v1.0 endpoints
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
│   │   ├── postgres/           # PostgreSQL implementations
│   │   │   ├── sequencer.rs    # Atomic sequence assignment
│   │   │   ├── ves_sequencer.rs # VES v1.0 sequencer
│   │   │   ├── event_store.rs  # Event storage
│   │   │   ├── agent_keys.rs   # Agent key registry
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
│   ├── postgres/               # PostgreSQL migrations (9 files)
│   │   ├── 001_production_postgres.sql
│   │   ├── 002_ves_v1_tables.sql
│   │   ├── 003_constraints.sql
│   │   ├── 004_ves_validity_proofs.sql
│   │   ├── 005_ves_compliance_proofs.sql
│   │   ├── 006_key_rotation_policies.sql
│   │   ├── 007_encryption_groups.sql
│   │   ├── 008_command_dedupe.sql
│   │   └── 009_api_keys.sql
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
| **STARK Proofs** | Zero-knowledge compliance verification |

## Cryptographic Guarantees

1. **Gap-Free Sequences**: No missing sequence numbers within a stream
2. **Linearizable Ordering**: Total ordering via PostgreSQL `SELECT FOR UPDATE`
3. **Verifiable History**: Merkle proofs for event inclusion verification
4. **Domain Separation**: All hashes include domain separators per VES spec
5. **Immutable Log**: Append-only event storage with no mutations

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

## Admin CLI

```bash
# Run migrations
cargo run --bin stateset-sequencer-admin -- migrate

# Backfill VES state roots
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots

# Dry run (preview changes)
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots --dry-run
```

## License

MIT
