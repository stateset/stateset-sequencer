# Getting Started with StateSet Sequencer

This guide covers how to run the StateSet Sequencer and integrate it with AI agents and the `@stateset/cli`.

## Overview

The **StateSet Sequencer** implements the Verifiable Event Sync (VES) v1.0 protocol - a system for deterministic event ordering, cryptographic verification, and eventual on-chain settlement. It bridges local CLI agents with production commerce infrastructure.

**Key Capabilities:**
- Deterministic event ordering with monotonic sequence numbers
- Ed25519 cryptographic signatures for event verification
- Merkle tree commitments with inclusion proofs
- Offline-first architecture with SQLite outbox pattern
- On-chain anchoring to Ethereum L2

## Prerequisites

- **Docker & Docker Compose** (recommended) or
- **Rust 1.70+** and **PostgreSQL 14+** (for local development)
- **Node.js 18+** (for CLI tools)

## Quick Start with Docker

The fastest way to get running:

```bash
# Clone and navigate to the sequencer
cd stateset-sequencer

# Start the sequencer and PostgreSQL
docker-compose up -d

# Verify it's running
curl http://localhost:8080/health
# Response: {"status":"healthy"}

# Check readiness (database connected)
curl http://localhost:8080/ready
# Response: {"status":"ready"}

# Example authenticated call (bootstrap admin key from docker-compose.yml)
curl -H "Authorization: ApiKey dev_admin_key" "http://localhost:8080/api/v1/head?tenant_id=<uuid>&store_id=<uuid>"
```

This starts:
- **PostgreSQL** on port `5433`
- **Sequencer API** on port `8080`

## Local Development Setup

For development without Docker:

```bash
# Build the sequencer
cargo build

# Set up PostgreSQL and run migrations (optional; the server also runs migrations on startup)
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/stateset_sequencer"
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

# Start the sequencer
cargo run
```

## Configuration

Configure via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://localhost/stateset_sequencer` | PostgreSQL connection |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8080` | HTTP server port |
| `MAX_DB_CONNECTIONS` | `10` | Connection pool size |
| `RUST_LOG` | `info` | Log level (debug, info, warn, error) |
| `AUTH_MODE` | `required` | `required` (default) or `disabled` (local dev) |
| `BOOTSTRAP_ADMIN_API_KEY` | (unset) | Admin API key for bootstrap / local dev |
| `JWT_SECRET` | (unset) | HMAC secret for JWT validation (enables `Bearer` auth) |
| `JWT_ISSUER` | `stateset-sequencer` | Expected JWT issuer |
| `JWT_AUDIENCE` | `stateset-api` | Expected JWT audience |
| `RATE_LIMIT_PER_MINUTE` | (unset) | Optional global per-tenant rate limit |
| `RATE_LIMIT_MAX_ENTRIES` | `10000` | Max tracked rate limit entries |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window duration |
| `PUBLIC_AGENT_REGISTRATION_ENABLED` | `true` | Enable public agent self-registration |
| `PUBLIC_AGENT_REGISTRATION_RATE_LIMIT_PER_MINUTE` | (unset) | Per-IP rate limit for public agent registration |
| `PUBLIC_AGENT_REGISTRATION_MAX_ENTRIES` | `10000` | Max tracked public registration rate limit entries |
| `PUBLIC_AGENT_REGISTRATION_WINDOW_SECONDS` | `60` | Public registration rate limit window duration |
| `TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-For` / `Forwarded` / `X-Real-IP` for client IPs |
| `CORS_ALLOW_ORIGINS` | (unset) | Optional CORS origins (`*` or comma-separated) |
| `DB_MIGRATE_ON_STARTUP` | `true` | Run SQL migrations on startup (`true|false`) |
| `PAYLOAD_ENCRYPTION_MODE` | `required` | Payload encryption-at-rest mode for legacy `events` table (`disabled|optional|required`) |
| `PAYLOAD_ENCRYPTION_KEY` | (unset) | Single 32-byte key for payload encryption-at-rest (hex or base64) |
| `PAYLOAD_ENCRYPTION_KEYS` | (unset) | Comma-separated keyring for payload encryption-at-rest (current first; supports rotation) |
| `PAYLOAD_ENCRYPTION_KEYS_BY_TENANT` | (unset) | JSON map of `tenant_id -> [keys...]` to override the default keyring |

**On-Chain Anchoring (optional):**

| Variable | Description |
|----------|-------------|
| `L2_RPC_URL` | Ethereum L2 RPC endpoint |
| `SET_REGISTRY_ADDRESS` | StateSetAnchor contract address |
| `SEQUENCER_PRIVATE_KEY` | Private key for anchoring transactions |
| `L2_CHAIN_ID` | Target chain ID (default: `84532001`) |

---

## Integrating with AI Agents

AI agents interact with the sequencer through the VES v1.0 protocol. Here's the integration flow:

```
┌─────────────────────────────────────────────┐
│  AI Agent (Local SQLite)                    │
│  - Creates events locally                   │
│  - Signs with Ed25519 private key           │
│  - Stores in SQLite outbox                  │
└──────────────────┬──────────────────────────┘
                   │ HTTP POST
                   ▼
┌─────────────────────────────────────────────┐
│  StateSet Sequencer                         │
│  - Verifies agent signature                 │
│  - Assigns sequence numbers                 │
│  - Stores in PostgreSQL                     │
│  - Generates Merkle commitments             │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  On-Chain (Optional)                        │
│  - Anchors batch roots to L2                │
│  - Stores roots for verification            │
└─────────────────────────────────────────────┘
```

### Step 1: Register Your Agent's Public Key

Before an agent can submit events, register its Ed25519 public key:

```bash
curl -X POST http://localhost:8080/api/v1/agents/keys \
  -H "Authorization: ApiKey dev_admin_key" \
  -H "Content-Type: application/json" \
  -d '{
    "tenantId": "00000000-0000-0000-0000-000000000001",
    "agentId": "00000000-0000-0000-0000-000000000002",
    "keyId": 1,
    "publicKey": "0x<64-hex-ed25519-public-key-bytes>",
    "validFrom": "2024-01-01T00:00:00Z"
  }'
```

### Step 2: Submit Signed Events

Submit events with Ed25519 signatures:

```bash
curl -X POST http://localhost:8080/api/v1/ves/events/ingest \
  -H "Authorization: ApiKey dev_admin_key" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "00000000-0000-0000-0000-000000000002",
    "events": [{
      "ves_version": 1,
      "event_id": "00000000-0000-0000-0000-000000000003",
      "tenant_id": "00000000-0000-0000-0000-000000000001",
      "store_id": "00000000-0000-0000-0000-000000000010",
      "source_agent_id": "00000000-0000-0000-0000-000000000002",
      "agent_key_id": 1,
      "entity_type": "order",
      "entity_id": "order-123",
      "event_type": "order.created",
      "created_at": "2024-01-15T10:30:00Z",
      "payload_kind": 0,
      "payload": { "order_id": "order-123", "total": 99.99 },
      "payload_plain_hash": "0x<32-byte-hash>",
      "payload_cipher_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "agent_signature": "0x<64-byte-ed25519-signature>"
    }]
  }'
```

**Signature Construction:**

The `agent_signature` is computed over the signing hash:

```
signing_hash = SHA256(
  "VES_EVENTSIG_V1" ||
  event_id || tenant_id || store_id || agent_id ||
  entity_type || entity_id || event_type ||
  payload_plain_hash || occurred_at
)
```

### Step 3: Query Events

Retrieve sequenced events:

```bash
# Get the current head sequence
curl http://localhost:8080/api/v1/head?tenant_id=<uuid>&store_id=<uuid>

# List events in a range
curl "http://localhost:8080/api/v1/events?tenant_id=<uuid>&store_id=<uuid>&from_seq=1&to_seq=100"

# Get entity history
curl http://localhost:8080/api/v1/entities/order/order-123?tenant_id=<uuid>&store_id=<uuid>
```

---

## Using the @stateset/cli

The CLI provides convenient commands for local agent sync operations.

### Initialize Sync

Set up a local SQLite database for offline-first event creation:

```bash
stateset-sync init \
  --sequencer-url http://localhost:8080 \
  --tenant-id <your-tenant-uuid> \
  --store-id <your-store-uuid> \
  --db ./store.db
```

### Check Sync Status

View pending and synced events:

```bash
stateset-sync status --db ./store.db
```

Output:
```
Sync Status for store.db
─────────────────────────
Remote Sequencer: http://localhost:8080
Tenant ID: abc-123
Store ID: def-456

Local Events: 15
  - Pushed: 12
  - Pending: 3

Remote Head: 142
Last Ack Sequence: 139
```

### Push Events to Sequencer

Sync local outbox events to the remote sequencer:

```bash
stateset-sync push --db ./store.db
```

This will:
1. Read unpushed events from local SQLite outbox
2. Sign each event with your agent's Ed25519 key
3. POST to the sequencer's `/api/v1/ves/events/ingest` endpoint
4. Update local sync state with acknowledgments

### View Event History

Query the local event log:

```bash
stateset-sync history --db ./store.db
```

### Pull Events from Sequencer

Fetch new events from the sequencer to local storage:

```bash
stateset-sync pull --db ./store.db
```

---

## Working with Commitments and Proofs

### Create a Merkle Commitment

Bundle events into a cryptographic commitment:

```bash
curl -X POST http://localhost:8080/api/v1/commitments \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "<uuid>",
    "store_id": "<uuid>",
    "from_sequence": 1,
    "to_sequence": 100
  }'
```

Response includes the Merkle root and batch ID.

### Get Inclusion Proof

Prove an event is included in a commitment:

```bash
curl http://localhost:8080/api/v1/proofs/42?tenant_id=<uuid>&store_id=<uuid>
```

### Verify a Proof

```bash
curl -X POST http://localhost:8080/api/v1/proofs/verify \
  -H "Content-Type: application/json" \
  -d '{
    "leaf_hash": "<event-payload-hash>",
    "proof": ["<sibling-hash-1>", "<sibling-hash-2>"],
    "root": "<merkle-root>",
    "leaf_index": 5
  }'
```

---

## On-Chain Anchoring

If you've configured anchoring environment variables, you can anchor commitments to Ethereum L2:

```bash
# Check if anchoring is enabled
curl http://localhost:8080/api/v1/anchor/status

# Anchor a commitment
curl -X POST http://localhost:8080/api/v1/anchor \
  -H "Content-Type: application/json" \
  -d '{
    "batch_id": "<commitment-batch-id>"
  }'

# Verify on-chain anchor
curl http://localhost:8080/api/v1/anchor/<batch-id>/verify
```

---

## API Reference

### Events

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ves/events/ingest` | Ingest signed VES v1.0 events |
| GET | `/api/v1/events` | List events by sequence range |
| GET | `/api/v1/head` | Get current head sequence number |
| GET | `/api/v1/entities/{type}/{id}` | Get entity event history |

### Commitments

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/commitments` | Create Merkle commitment |
| GET | `/api/v1/commitments` | List commitments |
| GET | `/api/v1/commitments/{batch_id}` | Get specific commitment |

### Proofs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/proofs/{sequence}` | Get inclusion proof |
| POST | `/api/v1/proofs/verify` | Verify Merkle proof |

### Agent Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agents/keys` | Register agent public key |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check (DB connection) |

---

## Example: Full Agent Integration

Here's a complete Node.js example for integrating an AI agent:

```javascript
import { createHash } from 'crypto';
import * as ed from '@noble/ed25519';

const SEQUENCER_URL = 'http://localhost:8080';

// Generate agent keypair (do this once, store securely)
const privateKey = ed.utils.randomPrivateKey();
const publicKey = await ed.getPublicKeyAsync(privateKey);

// Register the agent's public key
await fetch(`${SEQUENCER_URL}/api/v1/agents/keys`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    tenantId: 'your-tenant-id',
    agentId: 'ai-agent-001',
    keyId: 'key-001',
    publicKeyHex: Buffer.from(publicKey).toString('hex'),
    validFrom: new Date().toISOString()
  })
});

// Create and sign an event
async function createEvent(entityType, entityId, eventType, payload) {
  const eventId = crypto.randomUUID();
  const occurredAt = new Date().toISOString();
  const payloadJson = JSON.stringify(payload);
  const payloadHash = createHash('sha256').update(payloadJson).digest('hex');

  // Build signing hash
  const signingData = Buffer.concat([
    Buffer.from('VES_EVENTSIG_V1'),
    Buffer.from(eventId),
    Buffer.from('your-tenant-id'),
    Buffer.from('your-store-id'),
    Buffer.from('ai-agent-001'),
    Buffer.from(entityType),
    Buffer.from(entityId),
    Buffer.from(eventType),
    Buffer.from(payloadHash, 'hex'),
    Buffer.from(occurredAt)
  ]);

  const signingHash = createHash('sha256').update(signingData).digest();
  const signature = await ed.signAsync(signingHash, privateKey);

  return {
    ves_version: 1,
    event_id: eventId,
    tenant_id: 'your-tenant-id',
    store_id: 'your-store-id',
    agent_id: 'ai-agent-001',
    agent_key_id: 'key-001',
    entity_type: entityType,
    entity_id: entityId,
    event_type: eventType,
    payload: payloadJson,
    payload_kind: 0,
    payload_plain_hash: payloadHash,
    occurred_at: occurredAt,
    agent_signature: Buffer.from(signature).toString('hex')
  };
}

// Submit events to sequencer
async function submitEvents(events) {
  const response = await fetch(`${SEQUENCER_URL}/api/v1/ves/events/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ events })
  });
  return response.json();
}

// Usage
const event = await createEvent(
  'order',
  'order-123',
  'order.created',
  { orderId: 'order-123', total: 99.99, items: ['item-1', 'item-2'] }
);

const result = await submitEvents([event]);
console.log('Sequenced events:', result);
```

---

## Troubleshooting

### Connection Refused

```bash
# Check if sequencer is running
docker-compose ps

# View logs
docker-compose logs sequencer
```

### Database Connection Failed

```bash
# Verify PostgreSQL is running
docker-compose logs postgres

# Check connection string
echo $DATABASE_URL
```

### Signature Verification Failed

- Ensure the public key is registered before submitting events
- Verify the signing hash construction matches the spec
- Check that the Ed25519 signature is hex-encoded (128 characters)

### Events Not Appearing

```bash
# Check event count
curl "http://localhost:8080/api/v1/head?tenant_id=<uuid>&store_id=<uuid>"

# Enable debug logging
RUST_LOG=debug docker-compose up
```

---

## Next Steps

- Read the [VES v1.0 Specification](docs/VES_SPEC.md) for full protocol details
- Review the [Anchoring Overview](docs/ANCHORING_OVERVIEW.md) for on-chain settlement
- Explore the [Local Sequencer Guide](local_sequencer_guide.md) for offline-first patterns

## Support

For issues and feature requests, visit the [GitHub repository](https://github.com/stateset/stateset-sequencer).
