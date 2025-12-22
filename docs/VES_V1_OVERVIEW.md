# VES v1.0 - Verifiable Event Sync

## Overview

VES (Verifiable Event Sync) v1.0 is a protocol for deterministic event ordering with cryptographic verification. It enables distributed agents to submit signed events to a central sequencer, which assigns canonical sequence numbers and produces verifiable receipts.

```
┌─────────────────┐         ┌─────────────────────┐         ┌──────────────────┐
│   CLI Agent     │         │     Sequencer       │         │    PostgreSQL    │
│                 │         │                     │         │                  │
│  ┌───────────┐  │  HTTP   │  ┌───────────────┐  │  SQL    │  ┌────────────┐  │
│  │  Outbox   │──┼────────►│  │ VesSequencer  │──┼────────►│  │ ves_events │  │
│  │ (SQLite)  │  │  POST   │  │               │  │         │  │            │  │
│  └───────────┘  │         │  │ - Validate    │  │         │  └────────────┘  │
│       │         │         │  │ - Verify Sig  │  │         │                  │
│       ▼         │         │  │ - Sequence    │  │         │  ┌────────────┐  │
│  ┌───────────┐  │         │  │ - Receipt     │  │         │  │agent_keys  │  │
│  │Ed25519 Key│  │         │  └───────────────┘  │         │  │            │  │
│  │  Signing  │  │◄────────┤       Receipt       │         │  └────────────┘  │
│  └───────────┘  │         │                     │         │                  │
└─────────────────┘         └─────────────────────┘         └──────────────────┘
```

## Key Concepts

### Domain Separation

All cryptographic operations use domain-separated hashing to prevent cross-protocol attacks:

| Domain Prefix | Purpose |
|---------------|---------|
| `VES_PAYLOAD_PLAIN_V1` | Plaintext payload hashing |
| `VES_PAYLOAD_AAD_V1` | Encryption AAD computation |
| `VES_PAYLOAD_CIPHER_V1` | Ciphertext bundle hashing |
| `VES_EVENTSIG_V1` | Event signing preimage |
| `VES_LEAF_V1` | Merkle leaf hashing |
| `VES_NODE_V1` | Merkle node hashing |
| `VES_RECEIPT_V1` | Sequencer receipt hashing |

### VES Event Envelope

Each event contains:

```json
{
  "ves_version": 1,
  "event_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "source_agent_id": "uuid",
  "agent_key_id": 1,
  "entity_type": "order",
  "entity_id": "ORD-001",
  "event_type": "order.created",
  "created_at": "2025-12-20T17:51:10.243Z",
  "payload_kind": 0,
  "payload": { ... },
  "payload_plain_hash": "0x7777c3fe...",
  "payload_cipher_hash": "0x00000000...",
  "agent_signature": "0xe01bf390..."
}
```

## Cryptographic Flow

### 1. Payload Hashing

The plaintext payload is hashed using RFC 8785 JSON Canonicalization:

```
payload_plain_hash = SHA256(
  "VES_PAYLOAD_PLAIN_V1" ||
  JCS(payload)
)
```

For plaintext events, `payload_cipher_hash` is 32 zero bytes.

### 2. Event Signing Hash

The agent computes a signing hash over all event fields:

```
event_signing_hash = SHA256(
  "VES_EVENTSIG_V1"      ||
  U32_BE(ves_version)    ||
  UUID(tenant_id)        ||    // 16 bytes
  UUID(store_id)         ||    // 16 bytes
  UUID(event_id)         ||    // 16 bytes
  UUID(source_agent_id)  ||    // 16 bytes
  U32_BE(agent_key_id)   ||
  ENC_STR(entity_type)   ||    // length-prefixed UTF-8
  ENC_STR(entity_id)     ||
  ENC_STR(event_type)    ||
  ENC_STR(created_at)    ||    // RFC 3339 timestamp
  U32_BE(payload_kind)   ||    // 0=plaintext, 1=encrypted
  payload_plain_hash     ||    // 32 bytes
  payload_cipher_hash         // 32 bytes
)
```

### 3. Agent Signature

The agent signs the hash using Ed25519:

```
agent_signature = Ed25519.Sign(agent_private_key, event_signing_hash)
```

### 4. Sequencer Verification

The sequencer:
1. Looks up the agent's public key by `(tenant_id, source_agent_id, agent_key_id)`
2. Recomputes the `event_signing_hash` from the envelope fields
3. Verifies: `Ed25519.Verify(agent_public_key, event_signing_hash, agent_signature)`

### 5. Sequencer Receipt

Upon acceptance, the sequencer issues a receipt:

```
receipt_hash = SHA256(
  "VES_RECEIPT_V1"       ||
  UUID(tenant_id)        ||
  UUID(store_id)         ||
  UUID(event_id)         ||
  U64_BE(sequence_number)||
  event_signing_hash
)
```

## API Endpoints

### POST /api/v1/ves/events/ingest

Submit a batch of signed VES events.

**Request:**
```json
{
  "agentId": "80441726-74e2-430a-95ae-97ce21c6351b",
  "events": [
    {
      "event_id": "861910c9-7a1d-4b6f-83d6-51bbf4ae2849",
      "tenant_id": "64527dd3-a654-4410-9327-e58a1492ce77",
      "store_id": "91def158-819a-4461-b5c9-7759750ad157",
      "source_agent_id": "80441726-74e2-430a-95ae-97ce21c6351b",
      "agent_key_id": 1,
      "entity_type": "order",
      "entity_id": "ORD-001",
      "event_type": "order.created",
      "ves_version": 1,
      "payload": { "orderId": "ORD-001", "total": 99.99 },
      "payload_kind": 0,
      "payload_plain_hash": "0x7777c3fe...",
      "payload_cipher_hash": "0x00000000...",
      "agent_signature": "0xe01bf390...",
      "created_at": "2025-12-20T17:51:10.243Z"
    }
  ]
}
```

**Response:**
```json
{
  "batchId": "a2d8ef4d-40e3-4f58-8530-ea08ac1189f9",
  "eventsAccepted": 1,
  "eventsRejected": 0,
  "sequenceStart": 9,
  "sequenceEnd": 9,
  "headSequence": 9,
  "rejections": [],
  "receipts": [
    {
      "sequencerId": "d30b94f9-3abd-4b24-86d8-4efa591a0a48",
      "eventId": "861910c9-7a1d-4b6f-83d6-51bbf4ae2849",
      "sequenceNumber": 9,
      "sequencedAt": "2025-12-20T17:59:43.286333896+00:00",
      "receiptHash": "719e0925...",
      "signatureAlg": "ed25519",
      "sequencerSignature": "..."
    }
  ]
}
```

### POST /api/v1/agents/keys

Register an agent's Ed25519 public key.

**Request:**
```json
{
  "tenantId": "64527dd3-a654-4410-9327-e58a1492ce77",
  "agentId": "80441726-74e2-430a-95ae-97ce21c6351b",
  "keyId": 1,
  "publicKey": "0x44c91e36d4d450f5fff43e69a95f838849692a2745f845bbfb7b97513b50ec8e"
}
```

## Rejection Reasons

| Code | Description |
|------|-------------|
| `duplicate_event_id` | Event ID already exists |
| `duplicate_command_id` | Command ID already processed |
| `invalid_payload_hash` | Payload hash verification failed |
| `invalid_cipher_hash` | Ciphertext hash verification failed |
| `invalid_signature` | Agent signature verification failed |
| `agent_key_invalid` | Agent key not found or revoked |
| `unsupported_version` | VES version not supported |

## CLI Usage

### Initialize Sync
```bash
stateset-sync init \
  --sequencer-url http://localhost:8080 \
  --tenant-id 64527dd3-a654-4410-9327-e58a1492ce77 \
  --store-id 91def158-819a-4461-b5c9-7759750ad157
```

### Generate Keys
```bash
stateset-sync keys:generate
# Creates Ed25519 signing key and X25519 encryption key
```

### Register Key with Sequencer
```bash
stateset-sync keys:register
# Registers the public key with the sequencer
```

### Add Events to Outbox
```javascript
import { createOutbox } from './sync/outbox.js';

const outbox = createOutbox(db, { configDir: '.stateset' });

await outbox.append({
  tenantId: config.identity.tenantId,
  storeId: config.identity.storeId,
  entityType: 'order',
  entityId: 'ORD-001',
  eventType: 'order.created',
  payload: { orderId: 'ORD-001', total: 99.99 },
  sourceAgent: config.identity.agentId,
});
```

### Push Events
```bash
stateset-sync push
```

## Cross-Platform Compatibility

VES v1.0 ensures identical hash computation across implementations:

| Component | JavaScript (Node.js) | Rust |
|-----------|---------------------|------|
| SHA-256 | `crypto.createHash('sha256')` | `sha2::Sha256` |
| Ed25519 | `crypto.sign(null, ...)` | `ed25519_dalek` |
| UUID bytes | `uuid.replace(/-/g, '')` → hex decode | `Uuid::as_bytes()` |
| String encoding | `u32BE(len) + utf8` | `u32_be(len) + utf8` |
| JSON canonical | RFC 8785 JCS | RFC 8785 JCS |

### Test Vector

Given these parameters:
```
tenant_id:     64527dd3-a654-4410-9327-e58a1492ce77
store_id:      91def158-819a-4461-b5c9-7759750ad157
event_id:      861910c9-7a1d-4b6f-83d6-51bbf4ae2849
source_agent:  80441726-74e2-430a-95ae-97ce21c6351b
agent_key_id:  1
entity_type:   "order"
entity_id:     "ORD-001"
event_type:    "order.created"
created_at:    "2025-12-20T17:51:10.243Z"
payload_kind:  0
plain_hash:    7777c3fef466a0e9df7e07ea4ff13dc8ffbb9e487098f1b65530cdce7b6bbbe7
cipher_hash:   0000000000000000000000000000000000000000000000000000000000000000
```

Expected signing hash:
```
e970dfc9ffc285c2c0ba59be5d9c653eee2d1ae4db9b7a02ea3cd62b8e7cf92b
```

## Architecture Files

```
stateset-sequencer/
├── src/
│   ├── crypto/
│   │   ├── hash.rs          # Domain-separated hashing
│   │   ├── signing.rs       # Ed25519 operations
│   │   └── encrypt.rs       # VES-ENC-1 encryption
│   ├── domain/
│   │   ├── types.rs         # Core type definitions
│   │   └── ves_event.rs     # VesEventEnvelope
│   ├── infra/postgres/
│   │   └── ves_sequencer.rs # Sequencer implementation
│   └── main.rs              # HTTP endpoints

cli/src/sync/
├── crypto.js    # JS crypto operations
├── keys.js      # Key management
├── outbox.js    # Local event capture
├── client.js    # Sequencer REST client
└── engine.js    # Sync orchestration
```

## Security Considerations

1. **Agent Key Rotation**: Support multiple keys per agent via `agent_key_id`
2. **Key Revocation**: Check key validity at `sequenced_at` time
3. **Replay Protection**: Events are idempotent by `event_id`
4. **Command Deduplication**: Optional `command_id` for intent-level deduplication
5. **Timestamp Integrity**: `created_at` is signed but not trusted for ordering
6. **Payload Binding**: Dual-hash (plain + cipher) binds payload to signature

## Future Extensions

- **Encrypted Payloads**: VES-ENC-1 with HPKE for end-to-end encryption
- **Merkle Commitments**: Batch commitment with on-chain anchoring
- **Inclusion Proofs**: Cryptographic proof of event inclusion
- **Sequencer Signatures**: Signed receipts for non-repudiation
