# StateSet Sequencer

Verifiable Event Sync (VES) service for deterministic event ordering, state projection, and cryptographic commitments.

## Overview

The StateSet Sequencer bridges local CLI agents with production commerce infrastructure, implementing the foundational layer of the Verifiable Event Sync (VES) architecture.

### Key Features

- **Deterministic Event Ordering**: Monotonic sequence numbers per tenant/store
- **Exactly-Once Delivery**: Idempotent event ingestion with deduplication
- **Offline-First**: Local SQLite outbox pattern for CLI agents
- **Merkle Commitments**: Cryptographic proofs for audit trails
- **Event Sourcing**: Full event history with replay capabilities

## Architecture

```
┌─────────────┐
│ CLI Agent   │
│ (SQLite)    │
└─────┬───────┘
      │ sync push/pull
      ▼
┌─────────────────────────────────────────┐
│ StateSet Sequencer                       │
│                                         │
│  ┌─────────────┐  ┌─────────────┐       │
│  │ Ingest      │→ │ Sequencer   │       │
│  │ Service     │  │             │       │
│  └─────────────┘  └──────┬──────┘       │
│                          │              │
│  ┌─────────────┐  ┌──────▼──────┐       │
│  │ Commitment  │← │ Event Store │       │
│  │ Engine      │  │ (Postgres)  │       │
│  └─────────────┘  └─────────────┘       │
└─────────────────────────────────────────┘
```

## Quick Start

### Using Docker Compose

```bash
# Start the sequencer and PostgreSQL
docker-compose up -d

# Check health
curl http://localhost:8080/health

# Example authenticated API call (bootstrap admin key from docker-compose.yml)
curl -H "Authorization: ApiKey dev_admin_key" "http://localhost:8080/api/v1/head?tenant_id=<uuid>&store_id=<uuid>"
```

### Local Development

```bash
# Install dependencies
cargo build

# Set environment variables
export DATABASE_URL="postgres://localhost/stateset_sequencer"

# Run database migrations (optional; server also runs them on startup)
cargo run --bin stateset-sequencer-admin -- migrate

# Optional: backfill VES commitment-chain state roots (only needed if you created VES commitments on older versions)
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots --dry-run
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots

# Auth (pick one)
export BOOTSTRAP_ADMIN_API_KEY="dev_admin_key"   # recommended for local dev
# export AUTH_MODE="disabled"                    # disables auth middleware entirely

# Payload encryption-at-rest (legacy `events` table)
export PAYLOAD_ENCRYPTION_MODE="required"        # disabled|optional|required
export PAYLOAD_ENCRYPTION_KEYS="0x...,0x..."     # keyring (current first), 32-byte keys (hex or base64)
# or: export PAYLOAD_ENCRYPTION_KEY="0x..."      # single key (32 bytes, hex or base64)
# optional per-tenant overrides:
# export PAYLOAD_ENCRYPTION_KEYS_BY_TENANT='{"<tenant-uuid>":["0x...","0x..."]}'

# Start the server
cargo run
```

## API Endpoints

### Event Ingestion

```bash
POST /api/v1/events/ingest
Content-Type: application/json

{
  "agent_id": "uuid",
  "events": [
    {
      "event_id": "uuid",
      "tenant_id": "uuid",
      "store_id": "uuid",
      "entity_type": "order",
      "entity_id": "order-123",
      "event_type": "order.created",
      "payload": { ... },
      "payload_hash": "...",
      "created_at": "2025-01-01T00:00:00Z",
      "source_agent": "uuid"
    }
  ]
}
```

### Get Events

```bash
GET /api/v1/events?tenant_id=uuid&store_id=uuid&from=0&limit=100
```

### Get Head Sequence

```bash
GET /api/v1/head?tenant_id=uuid&store_id=uuid
```

### Get Entity History

```bash
GET /api/v1/entities/{entity_type}/{entity_id}?tenant_id=uuid&store_id=uuid
```

### Health Check

```bash
GET /health
GET /ready
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `DATABASE_URL` | `postgres://localhost/stateset_sequencer` | PostgreSQL connection URL |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8080` | Server port |
| `MAX_DB_CONNECTIONS` | `10` | Maximum database connections |
| `RUST_LOG` | `info` | Log level |
| `AUTH_MODE` | `required` | `required` (default) or `disabled` (local dev) |
| `BOOTSTRAP_ADMIN_API_KEY` | (unset) | Admin API key for bootstrap / local dev |
| `JWT_SECRET` | (unset) | HMAC secret for JWT validation (enables `Bearer` auth) |
| `JWT_ISSUER` | `stateset-sequencer` | Expected JWT issuer |
| `JWT_AUDIENCE` | `stateset-api` | Expected JWT audience |
| `RATE_LIMIT_PER_MINUTE` | (unset) | Optional global per-tenant rate limit |
| `CORS_ALLOW_ORIGINS` | (unset) | Optional CORS origins (`*` or comma-separated) |
| `DB_MIGRATE_ON_STARTUP` | `true` | Run SQL migrations on startup (`true|false`) |
| `PAYLOAD_ENCRYPTION_MODE` | `required` | Payload encryption-at-rest mode for legacy `events` table (`disabled|optional|required`) |
| `PAYLOAD_ENCRYPTION_KEY` | (unset) | Single 32-byte key for payload encryption-at-rest (hex or base64) |
| `PAYLOAD_ENCRYPTION_KEYS` | (unset) | Comma-separated keyring for payload encryption-at-rest (current first; supports rotation) |
| `PAYLOAD_ENCRYPTION_KEYS_BY_TENANT` | (unset) | JSON map of `tenant_id -> [keys...]` to override the default keyring |

## Project Structure

```
stateset-sequencer/
├── src/
│   ├── main.rs              # Thin binary wrapper
│   ├── server.rs            # HTTP server bootstrap
│   ├── api/                  # REST API handlers
│   │   ├── mod.rs
│   │   └── rest.rs
│   ├── domain/               # Core domain types
│   │   ├── mod.rs
│   │   ├── types.rs          # TenantId, StoreId, EntityType
│   │   ├── event.rs          # EventEnvelope, SequencedEvent
│   │   └── commitment.rs     # BatchCommitment, MerkleProof
│   └── infra/                # Infrastructure implementations
│       ├── mod.rs
│       ├── traits.rs         # Service traits
│       ├── error.rs          # Error types
│       ├── sqlite/           # SQLite outbox for local agents
│       ├── postgres/         # PostgreSQL event store
│       └── commitment.rs     # Merkle tree implementation
├── migrations/
│   ├── postgres/                     # PostgreSQL migrations (server)
│   └── sqlite/                       # SQLite migrations (local outbox)
├── Dockerfile
├── docker-compose.yml
└── Cargo.toml
```

## Phased Roadmap

### Phase 0 (Current)
- Event sequencing and storage
- SQLite outbox for local agents
- REST API for sync operations
- Off-chain Merkle commitments

### Phase 1 (Planned)
- On-chain root anchoring
- Inclusion proof generation
- CLI verification commands

### Phase 2 (Future)
- ZK validity proofs
- Trustless settlement
- Verifiable agent attestations

## License

MIT
