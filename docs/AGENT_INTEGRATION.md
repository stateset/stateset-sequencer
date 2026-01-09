# AI Agent Integration Guide

This guide explains how AI agents interact with the StateSet Sequencer using the **Verifiable Event Sync (VES)** protocol.

## Overview

The StateSet Sequencer provides AI agents with:

- **Cryptographic proof of authorship** - Events are signed with Ed25519 keys
- **Canonical ordering** - Deterministic sequence numbers across all agents
- **Sync state tracking** - Agents track their position in the event stream
- **Idempotent operations** - Safe retries via command IDs

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Agent A    │     │   AI Agent B    │     │   AI Agent C    │
│  (CLI/Service)  │     │  (Assistant)    │     │  (IoT Device)   │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  Sign & Push Events   │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                      STATESET SEQUENCER                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Signature   │  │  Sequence    │  │  Event Store         │  │
│  │  Verifier    │  │  Assigner    │  │  (PostgreSQL)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
         │                       │                       │
         │    Pull Events        │                       │
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Agent A    │     │   AI Agent B    │     │   AI Agent C    │
│  Sync State:    │     │  Sync State:    │     │  Sync State:    │
│  pulled: 100    │     │  pulled: 98     │     │  pulled: 100    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Agent Lifecycle

### 1. Key Registration (One-Time Setup)

Before an agent can submit events, it must register its Ed25519 public key:

```bash
# Generate key pair (agent-side)
openssl genpkey -algorithm ed25519 -out agent_private.pem
openssl pkey -in agent_private.pem -pubout -out agent_public.pem

# Register public key with sequencer
curl -X POST https://sequencer.example.com/api/v1/agents/keys \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "key_id": 1,
    "public_key": "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_to": "2026-01-01T00:00:00Z"
  }'
```

**Response:**
```json
{
  "status": "active",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "key_id": 1
}
```

### 2. Event Creation and Signing

Agents create events following the VES v1.0 envelope structure:

```rust
// Pseudocode for event creation
let event = VesEventEnvelope {
    ves_version: 1,
    event_id: Uuid::new_v4(),
    tenant_id: tenant_id,
    store_id: store_id,
    source_agent_id: my_agent_id,
    agent_key_id: 1,
    entity_type: "order",
    entity_id: "ORD-2024-001",
    event_type: "order.created",
    created_at: Utc::now().to_rfc3339(),
    payload: json!({
        "customer_id": "CUST-123",
        "items": [{"sku": "ITEM-001", "qty": 2}],
        "total": 99.99
    }),
    payload_plain_hash: sha256(payload),
    command_id: Some(idempotency_key),  // Optional: for retry safety
};

// Compute signing hash (domain-separated)
let signing_hash = sha256(
    b"VES_EVENTSIG_V1" +
    event.ves_version.to_be_bytes() +
    event.tenant_id.as_bytes() +
    event.store_id.as_bytes() +
    event.event_id.as_bytes() +
    event.source_agent_id.as_bytes() +
    event.agent_key_id.to_be_bytes() +
    encode_string(event.entity_type) +
    encode_string(event.entity_id) +
    encode_string(event.event_type) +
    encode_string(event.created_at) +
    event.payload_kind.to_be_bytes() +
    event.payload_plain_hash +
    event.payload_cipher_hash
);

// Sign with agent's private key
event.agent_signature = ed25519_sign(signing_hash, private_key);
```

### 3. Pushing Events to Sequencer

Submit signed events via the ingest endpoint:

```bash
curl -X POST https://sequencer.example.com/api/v1/ves/events/ingest \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "events": [{
      "ves_version": 1,
      "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
      "store_id": "660e8400-e29b-41d4-a716-446655440001",
      "source_agent_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "agent_key_id": 1,
      "entity_type": "order",
      "entity_id": "ORD-2024-001",
      "event_type": "order.created",
      "created_at": "2025-01-08T10:30:00Z",
      "payload_kind": 0,
      "payload": {
        "customer_id": "CUST-123",
        "total": 99.99
      },
      "payload_plain_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "payload_cipher_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "agent_signature": "b5d3c2a1..."
    }]
  }'
```

**Response:**
```json
{
  "batchId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "eventsAccepted": 1,
  "eventsRejected": 0,
  "sequenceStart": 42,
  "sequenceEnd": 42,
  "headSequence": 42,
  "rejections": [],
  "receipts": [{
    "sequencerId": "seq-001",
    "eventId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "sequenceNumber": 42,
    "sequencedAt": "2025-01-08T10:30:01.234Z",
    "receiptHash": "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
    "signatureAlg": "ed25519",
    "sequencerSignature": "c4e5f6a7..."
  }]
}
```

### 4. Pulling Events (Synchronization)

Agents fetch events they haven't seen yet:

```bash
# Get events starting from sequence 40
curl "https://sequencer.example.com/api/v1/events?tenant_id=550e8400...&store_id=660e8400...&from=40&limit=100" \
  -H "Authorization: Bearer $API_KEY"
```

**Response:**
```json
{
  "events": [
    {
      "sequence_number": 40,
      "event_id": "...",
      "entity_type": "order",
      "entity_id": "ORD-2024-001",
      "event_type": "order.created",
      "payload": {"customer_id": "CUST-123", "total": 99.99},
      "source_agent": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "created_at": "2025-01-08T10:30:00Z"
    },
    {
      "sequence_number": 41,
      "event_id": "...",
      "entity_type": "order",
      "entity_id": "ORD-2024-001",
      "event_type": "order.confirmed",
      "payload": {"confirmed_at": "2025-01-08T10:35:00Z"},
      "source_agent": "8d0f7780-8536-51ef-055c-f18ed2f01bf8",
      "created_at": "2025-01-08T10:35:00Z"
    }
  ],
  "count": 2,
  "head_sequence": 42
}
```

### 5. Sync State Management

Agents track their synchronization position:

```bash
# Get current sync state
curl "https://sequencer.example.com/api/v1/sync/state?agent_id=7c9e6679..." \
  -H "Authorization: Bearer $API_KEY"
```

**Response:**
```json
{
  "agent_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "store_id": "660e8400-e29b-41d4-a716-446655440001",
  "last_pushed_sequence": 42,
  "last_pulled_sequence": 41,
  "head_sequence": 42,
  "last_sync_at": "2025-01-08T10:30:01Z",
  "lag": 1
}
```

## Data Structures

### VES Event Envelope

| Field | Type | Description |
|-------|------|-------------|
| `ves_version` | u32 | Protocol version (currently 1) |
| `event_id` | UUID | Globally unique event identifier |
| `tenant_id` | UUID | Tenant isolation |
| `store_id` | UUID | Event stream scope |
| `source_agent_id` | UUID | Agent that created the event |
| `agent_key_id` | u32 | Which key version signed this event |
| `entity_type` | string | Entity category (1-64 chars) |
| `entity_id` | string | Entity identifier (1-256 chars) |
| `event_type` | string | Event name (1-64 chars) |
| `created_at` | string | RFC 3339 timestamp |
| `payload_kind` | u32 | 0=plaintext, 1=encrypted |
| `payload` | JSON | Event data (if plaintext) |
| `payload_encrypted` | bytes | Encrypted payload (if encrypted) |
| `payload_plain_hash` | Hash256 | SHA256 of plaintext payload |
| `payload_cipher_hash` | Hash256 | SHA256 of ciphertext (or zeros) |
| `agent_signature` | Signature64 | Ed25519 signature |
| `command_id` | UUID? | Optional idempotency key |
| `base_version` | u64? | Optional optimistic concurrency |

### Sync State

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | UUID | Agent identifier |
| `tenant_id` | UUID | Tenant scope |
| `store_id` | UUID | Store scope |
| `last_pushed_sequence` | u64 | Last event pushed by this agent |
| `last_pulled_sequence` | u64 | Last event pulled by this agent |
| `head_sequence` | u64 | Current head of the stream |
| `last_sync_at` | DateTime | Last sync timestamp |

## API Reference

### Agent Key Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/agents/keys` | POST | Register a new agent public key |
| `/api/v1/agents/keys` | GET | List keys for an agent |
| `/api/v1/agents/keys/{key_id}` | DELETE | Revoke a key |

### Event Operations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/ves/events/ingest` | POST | Submit signed events |
| `/api/v1/events` | GET | Fetch events from stream |
| `/api/v1/events/{event_id}` | GET | Get single event by ID |
| `/api/v1/head` | GET | Get current sequence head |

### Sync Operations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/sync/state` | GET | Get agent sync state |
| `/api/v1/sync/state` | PUT | Update agent sync state |

## Error Handling

### Rejection Reasons

| Code | Reason | Description |
|------|--------|-------------|
| `DUPLICATE_EVENT_ID` | Event ID already exists | Use a new UUID |
| `DUPLICATE_COMMAND_ID` | Command already processed | Idempotent - return cached result |
| `INVALID_SIGNATURE` | Signature verification failed | Check signing key and hash |
| `AGENT_KEY_INVALID` | Key not found or expired | Register key or use valid key_id |
| `INVALID_PAYLOAD_HASH` | Hash doesn't match payload | Recompute SHA256 of payload |
| `SCHEMA_VALIDATION` | Field validation failed | Check field lengths/formats |

### Example Error Response

```json
{
  "error": {
    "code": "INVALID_SIGNATURE",
    "numeric_code": 6002,
    "message": "Signature verification failed for event a1b2c3d4-...",
    "details": {
      "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "agent_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "key_id": 1
    }
  }
}
```

## Security Model

### Cryptographic Guarantees

1. **Authenticity**: Ed25519 signatures prove event authorship
2. **Integrity**: Payload hashes detect tampering
3. **Non-repudiation**: Agents cannot deny creating signed events
4. **Ordering**: Sequencer provides canonical, gap-free ordering

### Key Management Best Practices

- **Key Rotation**: Increment `key_id` when rotating keys
- **Validity Windows**: Set `valid_from` and `valid_to` for time-bounded keys
- **Revocation**: Revoke compromised keys immediately
- **Secure Storage**: Keep private keys in secure enclaves or HSMs

### Domain Separation

All hashes use domain-specific prefixes to prevent cross-protocol attacks:

| Purpose | Prefix |
|---------|--------|
| Event signing | `VES_EVENTSIG_V1` |
| Receipt signing | `VES_RECEIPT_V1` |
| Payload hashing | `VES_PAYLOAD_V1` |

## Use Cases

### 1. CLI Agent (Offline-First)

```
┌─────────────────┐
│  CLI Agent      │
│  ┌───────────┐  │
│  │  SQLite   │  │     Batch Sync
│  │  Outbox   │──────────────────►  Sequencer
│  └───────────┘  │
│  Local events   │
└─────────────────┘
```

CLI agents use the SQLite outbox pattern:
1. Create events locally in SQLite
2. Periodically sync batches to remote sequencer
3. Handle conflicts via command_id idempotency

### 2. Real-Time Service Agent

```
┌─────────────────┐
│  Service Agent  │
│                 │     Direct HTTP
│  Order Service  │◄────────────────►  Sequencer
│                 │     Real-time
└─────────────────┘
```

Service agents make direct API calls for real-time event streaming.

### 3. AI Assistant Agent

```
┌─────────────────┐
│  AI Assistant   │
│                 │
│  • Actions      │     Audit Trail
│  • Decisions    │─────────────────►  Sequencer
│  • Tool Calls   │
└─────────────────┘
```

AI assistants record actions and decisions as signed events for:
- Audit trails
- Reproducibility
- Compliance

## Example: Complete Agent Implementation

```python
import hashlib
import json
import uuid
from datetime import datetime
from nacl.signing import SigningKey
import requests

class VesAgent:
    def __init__(self, agent_id: str, private_key: bytes, sequencer_url: str):
        self.agent_id = agent_id
        self.signing_key = SigningKey(private_key)
        self.sequencer_url = sequencer_url
        self.key_id = 1

    def create_event(self, tenant_id: str, store_id: str,
                     entity_type: str, entity_id: str,
                     event_type: str, payload: dict,
                     command_id: str = None) -> dict:
        """Create and sign a VES event."""

        event_id = str(uuid.uuid4())
        created_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()

        # Build signing hash
        signing_data = self._build_signing_hash(
            ves_version=1,
            tenant_id=tenant_id,
            store_id=store_id,
            event_id=event_id,
            entity_type=entity_type,
            entity_id=entity_id,
            event_type=event_type,
            created_at=created_at,
            payload_hash=payload_hash
        )

        # Sign
        signature = self.signing_key.sign(signing_data).signature.hex()

        return {
            "ves_version": 1,
            "event_id": event_id,
            "tenant_id": tenant_id,
            "store_id": store_id,
            "source_agent_id": self.agent_id,
            "agent_key_id": self.key_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "created_at": created_at,
            "payload_kind": 0,
            "payload": payload,
            "payload_plain_hash": payload_hash,
            "payload_cipher_hash": "0" * 64,
            "agent_signature": signature,
            "command_id": command_id
        }

    def push_events(self, events: list) -> dict:
        """Push signed events to the sequencer."""
        response = requests.post(
            f"{self.sequencer_url}/api/v1/ves/events/ingest",
            json={"agentId": self.agent_id, "events": events},
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        return response.json()

    def pull_events(self, tenant_id: str, store_id: str,
                    from_seq: int = 0, limit: int = 100) -> list:
        """Pull events from the sequencer."""
        response = requests.get(
            f"{self.sequencer_url}/api/v1/events",
            params={
                "tenant_id": tenant_id,
                "store_id": store_id,
                "from": from_seq,
                "limit": limit
            },
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        return response.json()["events"]

# Usage
agent = VesAgent(
    agent_id="7c9e6679-7425-40de-944b-e07fc1f90ae7",
    private_key=bytes.fromhex("..."),
    sequencer_url="https://sequencer.example.com"
)

# Create and push an event
event = agent.create_event(
    tenant_id="550e8400-e29b-41d4-a716-446655440000",
    store_id="660e8400-e29b-41d4-a716-446655440001",
    entity_type="order",
    entity_id="ORD-2024-001",
    event_type="order.created",
    payload={"customer_id": "CUST-123", "total": 99.99},
    command_id=str(uuid.uuid4())  # Idempotency key
)

result = agent.push_events([event])
print(f"Event sequenced at: {result['sequenceStart']}")
```

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| `INVALID_SIGNATURE` | Wrong key or hash computation | Verify signing hash matches VES spec |
| `AGENT_KEY_INVALID` | Key not registered or expired | Register key or check validity window |
| `DUPLICATE_COMMAND_ID` | Retry of processed command | This is expected - use cached result |
| Sync lag increasing | Agent not pulling frequently enough | Increase pull frequency |
| Events out of order | Using `created_at` instead of `sequence_number` | Always order by `sequence_number` |

### Debug Mode

Enable verbose logging to debug signature issues:

```bash
RUST_LOG=stateset_sequencer::crypto=debug cargo run
```

## Related Documentation

- [VES v1.0 Protocol Specification](./VES_V1_OVERVIEW.md)
- [API Reference](./API_REFERENCE.md)
- [Security Model](./SECURITY.md)
- [Architecture Overview](../ARCHITECTURE.md)
