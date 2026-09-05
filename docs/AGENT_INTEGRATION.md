# AI Agent Integration Guide

This guide explains how AI agents interact with the StateSet Sequencer using the **Verifiable Event Sync (VES)** protocol.

## Production SDK and MCP

The Node.js package in [`cli`](../cli/README.md) provides the production client
for this protocol. It implements the same canonical payload and event-signing
hashes as Rust, authenticated idempotent ingest, entity reads, sequence cursors,
inclusion proofs, OpenAI-compatible function tools, and an MCP stdio server.

Keep API credentials and signing keys in the trusted tool host, never in model
context. Constrain MCP writes with `STATESET_ALLOWED_EVENT_TYPES`; if it is
unset, the MCP server is read-only. Existing-entity mutations require
`baseVersion` by default, and applications can install a deterministic
`validateAction` hook for monetary limits, approval evidence, or other policy.

The recommended agent loop is: read entity history, propose an action, validate
outside the model, reuse one `commandId` across retries, submit with the observed
`baseVersion`, persist the returned sequence cursor, and request an inclusion
proof when independent audit evidence is required.

### Verify inclusion without trusting the verification endpoint

Both SDKs expose a pure local verifier. Supply the expected root from a trusted
commitment or verified on-chain anchor and the expected leaf computed from the
event you intend to verify. Do not take either trust input from the same
untrusted proof response.

```javascript
import { verifyInclusionProofLocally } from '@stateset/sequencer-sdk';
const valid = verifyInclusionProofLocally(proof, trustedRootHex, expectedLeafHex);
```

```python
from stateset_sequencer import verify_inclusion_proof_locally
valid = verify_inclusion_proof_locally(proof, trusted_root_hex, expected_leaf_hex)
```

These functions validate VES_NODE_V1 Merkle membership, hash lengths, path
lengths, direction bits, and leaf position. They return false for malformed or
tampered proofs. They do not authenticate a commitment, verify a receipt
signature, or establish finality of an on-chain anchor. Leaf indices above the
JavaScript safe-integer range are rejected consistently in both SDKs.

### Signing versions and migration

VES v1 signatures bind event identity, payload hashes, and the fields specified
by VES_EVENTSIG_V1. They do not bind `command_id` or `base_version`. Keep the
submission path authenticated and trusted; do not treat those two fields as
cryptographically authenticated agent intent.

New Node and Python clients default to event signing version 2. V2 binds the
values and presence of both execution controls. Upgrade the server before
deploying these clients. For an older server, explicitly select
`signingVersion: 1` (Node) or `signing_version=1` (Python); no automatic downgrade
is performed. After all writers migrate, set
`REQUIRE_SIGNED_EXECUTION_CONTROLS=true` to reject new V1 events. Existing exact
replays can still return their stored receipts. Rust callers can set their
controls then call `event.sign_execution_controls(&ed25519_key)` to sign V2.

The V2 event signing hash is SHA-256 of the following concatenation:

```
UTF8("VES_EVENTSIG_V2") || V1Hash(ves_version=2) ||
U8(command_present) || [UUID(command_id)] ||
U8(base_present) || [U64_BE(base_version)]
```

Presence bytes are 0 or 1; bracketed bytes exist only when present. V1Hash uses
the existing VES_EVENTSIG_V1 encoding, with its version field set to 2. The
Merkle node/leaf and receipt formats are unchanged; they consume the resulting
event hash. SDK numeric inputs remain limited to JavaScript's safe integer
range for cross-language interoperability. Never change controls after signing.

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

### 0. (Optional) Self-Service Registration

If public registration is enabled, an agent can self-register to receive an API key:

```bash
curl -X POST https://sequencer.example.com/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "agent-name",
    "description": "Optional description",
    "storeIds": ["550e8400-e29b-41d4-a716-446655440000"],
    "readOnly": false
  }'
```

Constraints:
- `name` must be 1-128 characters.
- `description` is optional, max 1024 characters.
- `storeIds` is optional, max 50 entries.
- `rateLimit` is optional, 1-10000 requests per minute.

Rate limit headers (`RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`) are included when
public registration rate limiting is enabled. `Retry-After` is included on `429` responses.

The response includes an `apiKey`, `tenantId`, and `agentId`. Store the API key securely; it is
only returned once.

### 1. Key Registration (One-Time Setup)

Before an agent can submit events, it must register its Ed25519 public key:

```bash
# Generate key pair (agent-side)
openssl genpkey -algorithm ed25519 -out agent_private.pem
openssl pkey -in agent_private.pem -pubout -out agent_public.pem

# Register public key with sequencer
curl -X POST https://sequencer.example.com/api/v1/agents/keys \
  -H "Authorization: ApiKey $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenantId": "550e8400-e29b-41d4-a716-446655440000",
    "agentId": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "keyId": 1,
    "publicKey": "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
    "validFrom": "2026-01-01T00:00:00Z",
    "validTo": "2027-01-01T00:00:00Z"
  }'
```

**Response:**
```json
{
  "success": true,
  "tenantId": "550e8400-e29b-41d4-a716-446655440000",
  "agentId": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "keyId": 1,
  "keyAlgorithm": 0
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
  -H "Authorization: ApiKey $API_KEY" \
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
curl "https://sequencer.example.com/api/v1/ves/events?tenant_id=550e8400...&store_id=660e8400...&from=40&limit=100" \
  -H "Authorization: ApiKey $API_KEY"
```

**Response:**
```json
{
  "events": [
    {
      "envelope": {
        "sequence_number": 40,
        "event_id": "...",
        "entity_type": "order",
        "entity_id": "ORD-2024-001",
        "event_type": "order.created",
        "payload": {"customer_id": "CUST-123", "total": 99.99},
        "source_agent_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "created_at": "2026-09-04T10:30:00Z"
      },
      "sequenced_at": "2026-09-04T10:30:01Z"
    }
  ],
  "count": 1,
  "next_sequence": 41,
  "head_sequence": 42,
  "has_more": true
}
```

### 5. Sync State Management

REST consumers acknowledge completed work with
`PUT /api/v1/ves/cursors/{agent_id}` and resume from
`acknowledgedSequence + 1`. Cursor updates are monotonic, so a delayed retry
cannot move a consumer backwards. The response also includes `headSequence`
and `lag`. gRPC consumers use `SyncStream`; acknowledgements persist the same
server-side cursor, and `GetSyncState` returns its current value.

Administrators can constrain an agent with
`PUT /api/v1/agents/{agent_id}/policy`. Exact rules and namespace wildcards
such as `order.*` are supported for event and entity types. The server enforces
these capabilities, optional `base_version` requirements, payload limits, and
the policy's enabled state after signature verification and before sequencing.
An absent policy preserves backwards compatibility; an enabled policy with an
empty allowlist permits no values in that category.

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
| `entity_type` | string | Entity category (1-128 chars) |
| `entity_id` | string | Entity identifier (1-512 chars) |
| `event_type` | string | Event name (1-256 chars) |
| `created_at` | string | RFC 3339 timestamp |
| `payload_kind` | u32 | 0=plaintext, 1=encrypted |
| `payload` | JSON | Event data (if plaintext) |
| `payload_encrypted` | bytes | Encrypted payload (if encrypted) |
| `payload_plain_hash` | Hash256 | SHA256 of plaintext payload |
| `payload_cipher_hash` | Hash256 | SHA256 of ciphertext (or zeros) |
| `agent_signature` | Signature64 | Ed25519 signature |
| `command_id` | UUID? | Optional idempotency key |
| `base_version` | u64? | Optional optimistic concurrency |

### Durable Cursor State

| Field | Type | Description |
|-------|------|-------------|
| `agentId` | UUID | Agent identifier |
| `tenantId` | UUID | Tenant scope |
| `storeId` | UUID | Store scope |
| `acknowledgedSequence` | u64 | Highest durably processed sequence |
| `headSequence` | u64 | Current head of the stream |
| `lag` | u64 | Events between the cursor and stream head |
| `updatedAt` | DateTime? | Last acknowledgement time |

## API Reference

### Agent Key Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/agents/keys` | POST | Register a new agent public key |
| `/api/v1/agents/{agent_id}` | GET | Read an agent registration |
| `/api/v1/agents/{agent_id}/api-keys` | GET/POST | List or create API credentials |
| `/api/v1/agents/{agent_id}/api-keys/{key_prefix}` | DELETE | Revoke an API credential |
| `/api/v1/agents/{agent_id}/policy` | GET/PUT | Read or enforce an agent policy (admin) |

### Event Operations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/ves/events/ingest` | POST | Submit signed events |
| `/api/v1/ves/events` | GET | Fetch a bounded page from the VES stream |
| `/api/v1/ves/head` | GET | Get the VES stream head |
| `/api/v1/ves/entities/{entity_type}/{entity_id}` | GET | Read paged VES entity history |
| `/api/v1/ves/cursors/{agent_id}` | GET/PUT | Read or acknowledge a durable agent cursor |
| `/api/v1/ves/proofs/{sequence_number}` | GET | Read an inclusion proof |
| `/api/v1/ves/proofs/verify` | POST | Verify an inclusion proof |

REST and gRPC share the same durable cursor. In gRPC, include `tenant_id` and
`store_id` in `EventAck` and set `agent_head_sequence` only to the highest
contiguous sequence whose work is durable. The optional `sequence_numbers`
list acknowledges individual events but never advances across a gap.
`SyncState` returns `acknowledged_sequence` and `lag`.

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

```js
import { randomUUID } from 'node:crypto';
import { VesClient, loadVesPrivateKey } from '@stateset/sequencer-sdk';

const agent = new VesClient({
  baseUrl: process.env.STATESET_SEQUENCER_URL,
  tenantId: process.env.STATESET_TENANT_ID,
  storeId: process.env.STATESET_STORE_ID,
  agentId: process.env.STATESET_AGENT_ID,
  apiKey: process.env.STATESET_API_KEY,
  privateKey: loadVesPrivateKey(),
});

const current = await agent.getEntityHistory('order', 'ORD-2024-001');
const result = await agent.recordAction({
  entityType: 'order',
  entityId: 'ORD-2024-001',
  eventType: 'order.confirmed',
  payload: { approvedBy: 'fulfillment-agent' },
  commandId: randomUUID(),
  baseVersion: current.current_version,
});

console.log(`Event sequenced at ${result.receipt.sequenceNumber}`);
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
