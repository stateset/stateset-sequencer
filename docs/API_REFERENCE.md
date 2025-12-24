# API Reference

Complete REST API documentation for the StateSet Sequencer.

## Base URL

```
https://sequencer.stateset.com/api/v1
```

## Authentication

All API requests require authentication via Bearer token:

```bash
Authorization: Bearer <your-api-key>
```

## Common Headers

```http
Content-Type: application/json
Authorization: Bearer <token>
```

## Common Response Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 202 | Accepted (async processing) |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Missing/invalid auth |
| 404 | Not Found |
| 409 | Conflict - Duplicate event ID |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

---

## Events

### Ingest Events (Legacy)

Ingest a batch of events without signature verification.

```http
POST /v1/events/ingest
```

**Request Body:**
```json
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
      "payload": { "customer_id": "cust-456" },
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

**Response:**
```json
{
  "batch_id": "uuid",
  "events_accepted": 1,
  "events_rejected": 0,
  "assigned_sequence_start": 1,
  "assigned_sequence_end": 1,
  "head_sequence": 1,
  "rejections": []
}
```

---

### Ingest VES Events (Recommended)

Ingest events with Ed25519 signature verification per VES v1.0.

```http
POST /v1/ves/events/ingest
```

**Request Body:**
```json
{
  "agentId": "uuid",
  "events": [
    {
      "ves_version": 1,
      "event_id": "uuid",
      "tenant_id": "uuid",
      "store_id": "uuid",
      "agent_id": "uuid",
      "agent_key_id": 1,
      "entity_type": "order",
      "entity_id": "order-123",
      "event_type": "order.created",
      "payload": "{\"customer_id\": \"cust-456\"}",
      "payload_kind": 0,
      "payload_plain_hash": "hex-sha256-of-payload",
      "occurred_at": "2024-01-15T10:30:00Z",
      "agent_signature": "hex-ed25519-signature"
    }
  ]
}
```

**Response:**
```json
{
  "batchId": "uuid",
  "eventsAccepted": 1,
  "eventsRejected": 0,
  "sequenceStart": 1,
  "sequenceEnd": 1,
  "headSequence": 1,
  "rejections": [],
  "receipts": [
    {
      "sequencerId": "uuid",
      "eventId": "uuid",
      "sequenceNumber": 1,
      "sequencedAt": "2024-01-15T10:30:01Z",
      "receiptHash": "hex",
      "signatureAlg": "Ed25519",
      "sequencerSignature": "hex"
    }
  ]
}
```

**Error Response:**
```json
{
  "batchId": "uuid",
  "eventsAccepted": 0,
  "eventsRejected": 1,
  "rejections": [
    {
      "event_id": "uuid",
      "reason": "SignatureVerificationFailed",
      "message": "Invalid agent signature"
    }
  ]
}
```

---

### List Events

Retrieve events by sequence range.

```http
GET /v1/events
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant_id` | uuid | Yes | Tenant identifier |
| `store_id` | uuid | Yes | Store identifier |
| `from` | integer | No | Starting sequence (default: 0) |
| `limit` | integer | No | Max events to return (default: 100, max: 1000) |

**Example:**
```bash
curl "https://sequencer.example.com/api/v1/events?tenant_id=abc&store_id=def&from=1&limit=50"
```

**Response:**
```json
{
  "events": [
    {
      "sequence_number": 1,
      "event_id": "uuid",
      "tenant_id": "uuid",
      "store_id": "uuid",
      "entity_type": "order",
      "entity_id": "order-123",
      "event_type": "order.created",
      "payload": { ... },
      "payload_hash": "hex",
      "created_at": "2024-01-15T10:30:00Z",
      "sequenced_at": "2024-01-15T10:30:01Z"
    }
  ],
  "count": 1
}
```

---

### Get Head Sequence

Get the current head sequence number for a store.

```http
GET /v1/head
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant_id` | uuid | Yes | Tenant identifier |
| `store_id` | uuid | Yes | Store identifier |

**Response:**
```json
{
  "head_sequence": 142
}
```

---

### Get Entity History

Retrieve all events for a specific entity.

```http
GET /v1/entities/{entity_type}/{entity_id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `entity_type` | string | Entity type (e.g., "order") |
| `entity_id` | string | Entity identifier |

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant_id` | uuid | Yes | Tenant identifier |
| `store_id` | uuid | Yes | Store identifier |

**Example:**
```bash
curl "https://sequencer.example.com/api/v1/entities/order/order-123?tenant_id=abc&store_id=def"
```

**Response:**
```json
{
  "entity_type": "order",
  "entity_id": "order-123",
  "events": [
    {
      "sequence_number": 1,
      "event_type": "order.created",
      "payload": { ... },
      "created_at": "2024-01-15T10:30:00Z"
    },
    {
      "sequence_number": 5,
      "event_type": "order.confirmed",
      "payload": { ... },
      "created_at": "2024-01-15T11:00:00Z"
    }
  ],
  "count": 2
}
```

---

## Commitments

### Create Commitment

Create a Merkle commitment over a sequence range.

```http
POST /v1/commitments
```

**Request Body:**
```json
{
  "tenant_id": "uuid",
  "store_id": "uuid",
  "sequence_start": 1,
  "sequence_end": 100
}
```

**Response:**
```json
{
  "batch_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "prev_state_root": "hex-32-bytes",
  "new_state_root": "hex-32-bytes",
  "events_root": "hex-32-bytes",
  "event_count": 100,
  "sequence_start": 1,
  "sequence_end": 100,
  "committed_at": "2024-01-15T12:00:00Z"
}
```

---

### Get Commitment

Retrieve a specific commitment by batch ID.

```http
GET /v1/commitments/{batch_id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `batch_id` | uuid | Commitment batch identifier |

**Response:**
```json
{
  "batch_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "prev_state_root": "hex",
  "new_state_root": "hex",
  "events_root": "hex",
  "event_count": 100,
  "sequence_start": 1,
  "sequence_end": 100,
  "committed_at": "2024-01-15T12:00:00Z",
  "chain_tx_hash": null
}
```

---

### List Commitments

List commitments for a store.

```http
GET /v1/commitments
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant_id` | uuid | Yes | Tenant identifier |
| `store_id` | uuid | Yes | Store identifier |

**Response:**
```json
{
  "commitments": [
    {
      "batch_id": "uuid",
      "events_root": "hex",
      "event_count": 100,
      "sequence_start": 1,
      "sequence_end": 100,
      "committed_at": "2024-01-15T12:00:00Z",
      "is_anchored": false
    }
  ],
  "count": 1
}
```

---

### Create VES Commitment

Create a VES v1.0 Merkle commitment over a sequence range in `ves_events`.
Commitment ranges must be contiguous (the next commitment must start at `last_sequence_end + 1`).
`prev_state_root` / `new_state_root` are commitment-chain state roots (not an application projector root).

```http
POST /v1/ves/commitments
```

**Request Body:**
```json
{
  "tenant_id": "uuid",
  "store_id": "uuid",
  "sequence_start": 1,
  "sequence_end": 100
}
```

**Response:**
```json
{
  "batch_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "ves_version": 1,
  "tree_depth": 7,
  "leaf_count": 100,
  "padded_leaf_count": 128,
  "merkle_root": "hex-32-bytes",
  "prev_state_root": "hex-32-bytes",
  "new_state_root": "hex-32-bytes",
  "sequence_start": 1,
  "sequence_end": 100,
  "committed_at": "2024-01-15T12:00:00Z"
}
```

---

### Commit + Anchor VES Commitment (Admin)

Create a VES commitment and immediately submit it to the configured anchoring chain.

- If `sequence_start`/`sequence_end` are omitted, the sequencer auto-selects the next uncommitted contiguous range up to `max_events` (default: `1024`) using the current `ves_events` head.
- Requires the anchor service to be configured (see `ANCHORING_OVERVIEW.md`).
- Requires admin permission for the tenant/store.

```http
POST /v1/ves/commitments/anchor
```

**Request Body:**
```json
{
  "tenant_id": "uuid",
  "store_id": "uuid",
  "sequence_start": 1,
  "sequence_end": 100,
  "max_events": 1024
}
```

**Response (anchored):**
```json
{
  "batch_id": "uuid",
  "status": "anchored",
  "chain_id": 1234,
  "chain_tx_hash": "hex-32-bytes",
  "chain_block_number": 12345,
  "merkle_root": "hex-32-bytes",
  "prev_state_root": "hex-32-bytes",
  "new_state_root": "hex-32-bytes",
  "sequence_start": 1,
  "sequence_end": 100
}
```

---

### Get VES Commitment

Retrieve a specific VES commitment by batch ID.

```http
GET /v1/ves/commitments/{batch_id}
```

**Response:**
```json
{
  "batch_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "ves_version": 1,
  "tree_depth": 7,
  "leaf_count": 100,
  "padded_leaf_count": 128,
  "merkle_root": "hex",
  "prev_state_root": "hex",
  "new_state_root": "hex",
  "sequence_start": 1,
  "sequence_end": 100,
  "committed_at": "2024-01-15T12:00:00Z",
  "chain_id": null,
  "chain_tx_hash": null,
  "chain_block_number": null,
  "anchored_at": null,
  "is_anchored": false
}
```

---

### List VES Commitments

List VES commitments for a store.

```http
GET /v1/ves/commitments
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant_id` | uuid | Yes | Tenant identifier |
| `store_id` | uuid | Yes | Store identifier |

**Response:**
```json
{
  "commitments": [
    {
      "batch_id": "uuid",
      "merkle_root": "hex",
      "prev_state_root": "hex",
      "new_state_root": "hex",
      "leaf_count": 100,
      "padded_leaf_count": 128,
      "sequence_start": 1,
      "sequence_end": 100,
      "committed_at": "2024-01-15T12:00:00Z",
      "is_anchored": false
    }
  ],
  "count": 1
}
```

---

## VES Validity Proofs

Validity proofs are externally-generated artifacts (e.g., SNARKs) that attest to properties of a `ves_commitments` batch.
Proof bytes are stored encrypted at rest (same keyring and AEAD framing as legacy `events.payload_encrypted`).

### Get VES Validity Public Inputs

Return canonical public inputs for a batch (for external provers).

```http
GET /v1/ves/validity/{batch_id}/inputs
```

**Response:**
```json
{
  "batch_id": "uuid",
  "public_inputs": {
    "batchId": "uuid",
    "tenantId": "uuid",
    "storeId": "uuid",
    "vesVersion": 1,
    "treeDepth": 7,
    "leafCount": 100,
    "paddedLeafCount": 128,
    "merkleRoot": "hex-32-bytes",
    "prevStateRoot": "hex-32-bytes",
    "newStateRoot": "hex-32-bytes",
    "sequenceStart": 1,
    "sequenceEnd": 100
  },
  "public_inputs_hash": "hex-32-bytes"
}
```

### Submit VES Validity Proof (Admin)

Submit a validity proof for a batch. `publicInputs` (if provided) must match the canonical inputs returned by `/inputs`.

```http
POST /v1/ves/validity/{batch_id}/proofs
```

**Request Body:**
```json
{
  "proofType": "groth16",
  "proofVersion": 1,
  "proofB64": "base64",
  "publicInputs": { "..." : "..." }
}
```

**Response:**
```json
{
  "proof_id": "uuid",
  "batch_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "proof_type": "groth16",
  "proof_version": 1,
  "proof_hash": "hex-32-bytes",
  "public_inputs": { "..." : "..." },
  "submitted_at": "2024-01-15T12:00:00Z"
}
```

### List VES Validity Proofs

```http
GET /v1/ves/validity/{batch_id}/proofs
```

**Response:**
```json
{
  "batch_id": "uuid",
  "proofs": [
    {
      "proof_id": "uuid",
      "batch_id": "uuid",
      "tenant_id": "uuid",
      "store_id": "uuid",
      "proof_type": "groth16",
      "proof_version": 1,
      "proof_hash": "hex-32-bytes",
      "public_inputs": { "..." : "..." },
      "submitted_at": "2024-01-15T12:00:00Z"
    }
  ],
  "count": 1
}
```

### Get VES Validity Proof

Retrieve the full proof bytes by `proof_id`.

```http
GET /v1/ves/validity/proofs/{proof_id}
```

**Response:**
```json
{
  "proof_id": "uuid",
  "batch_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "proof_type": "groth16",
  "proof_version": 1,
  "proof_hash": "hex-32-bytes",
  "proof_b64": "base64",
  "public_inputs": { "..." : "..." },
  "submitted_at": "2024-01-15T12:00:00Z"
}
```

### Verify VES Validity Proof

Verify that a stored proof is internally consistent with the sequencer’s canonical public inputs for the referenced batch, and that the stored proof bytes match the recorded proof hash.
This does not perform cryptographic proof verification (SNARK verification is prover/system-specific); it validates `public_inputs` consistency and returns stable hashes for external verifiers.

```http
GET /v1/ves/validity/proofs/{proof_id}/verify
```

**Response:**
```json
{
  "proof_id": "uuid",
  "batch_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "proof_type": "groth16",
  "proof_version": 1,
  "proof_hash": "hex-32-bytes",
  "proof_hash_match": true,
  "public_inputs_hash": "hex-32-bytes",
  "canonical_public_inputs_hash": "hex-32-bytes",
  "public_inputs_match": true,
  "valid": true,
  "reason": null
}
```

---

## VES Compliance Proofs

Compliance proofs are externally-generated artifacts (e.g., STARKs/zkVM receipts) that attest to properties of encrypted VES event payloads without revealing the payload.
Proof bytes are stored encrypted at rest.

### Get VES Compliance Public Inputs

Return canonical public inputs for a specific event + policy (for external provers).

```http
POST /v1/ves/compliance/{event_id}/inputs
```

**Request Body:**
```json
{
  "policyId": "aml.amount_lt",
  "policyParams": { "threshold": 10000 }
}
```

**Response:**
```json
{
  "event_id": "uuid",
  "public_inputs": {
    "eventId": "uuid",
    "tenantId": "uuid",
    "storeId": "uuid",
    "sequenceNumber": 123,
    "payloadKind": 1,
    "payloadPlainHash": "hex-32-bytes",
    "payloadCipherHash": "hex-32-bytes",
    "eventSigningHash": "hex-32-bytes",
    "policyId": "aml.amount_lt",
    "policyParams": { "threshold": 10000 },
    "policyHash": "hex-32-bytes"
  },
  "public_inputs_hash": "hex-32-bytes"
}
```

### Submit VES Compliance Proof

Submit a compliance proof for an event + policy. `publicInputs` (if provided) must match the canonical inputs returned by `/inputs`.

```http
POST /v1/ves/compliance/{event_id}/proofs
```

**Request Body:**
```json
{
  "proofType": "stark",
  "proofVersion": 1,
  "policyId": "aml.amount_lt",
  "policyParams": { "threshold": 10000 },
  "proofB64": "base64",
  "publicInputs": { "..." : "..." }
}
```

**Response:**
```json
{
  "proof_id": "uuid",
  "event_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "proof_type": "stark",
  "proof_version": 1,
  "policy_id": "aml.amount_lt",
  "policy_params": { "threshold": 10000 },
  "policy_hash": "hex-32-bytes",
  "proof_hash": "hex-32-bytes",
  "public_inputs": { "..." : "..." },
  "submitted_at": "2024-01-15T12:00:00Z"
}
```

### List VES Compliance Proofs

```http
GET /v1/ves/compliance/{event_id}/proofs
```

**Response:**
```json
{
  "event_id": "uuid",
  "proofs": [
    {
      "proof_id": "uuid",
      "event_id": "uuid",
      "tenant_id": "uuid",
      "store_id": "uuid",
      "proof_type": "stark",
      "proof_version": 1,
      "policy_id": "aml.amount_lt",
      "policy_params": { "threshold": 10000 },
      "policy_hash": "hex-32-bytes",
      "proof_hash": "hex-32-bytes",
      "public_inputs": { "..." : "..." },
      "submitted_at": "2024-01-15T12:00:00Z"
    }
  ],
  "count": 1
}
```

### Get VES Compliance Proof

```http
GET /v1/ves/compliance/proofs/{proof_id}
```

**Response:**
```json
{
  "proof_id": "uuid",
  "event_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "proof_type": "stark",
  "proof_version": 1,
  "policy_id": "aml.amount_lt",
  "policy_params": { "threshold": 10000 },
  "policy_hash": "hex-32-bytes",
  "proof_hash": "hex-32-bytes",
  "proof_b64": "base64",
  "public_inputs": { "..." : "..." },
  "submitted_at": "2024-01-15T12:00:00Z"
}
```

### Verify VES Compliance Proof

Verify that a stored proof is internally consistent with the sequencer’s canonical public inputs for the referenced event + policy, and that the stored proof bytes match the recorded proof hash.
This does not perform cryptographic proof verification.

```http
GET /v1/ves/compliance/proofs/{proof_id}/verify
```

**Response:**
```json
{
  "proof_id": "uuid",
  "event_id": "uuid",
  "tenant_id": "uuid",
  "store_id": "uuid",
  "proof_type": "stark",
  "proof_version": 1,
  "policy_id": "aml.amount_lt",
  "policy_hash": "hex-32-bytes",
  "proof_hash": "hex-32-bytes",
  "proof_hash_match": true,
  "public_inputs_hash": "hex-32-bytes",
  "canonical_public_inputs_hash": "hex-32-bytes",
  "public_inputs_match": true,
  "valid": true,
  "reason": null
}
```

---

## Proofs

### Get Inclusion Proof

Generate a Merkle inclusion proof for an event.

```http
GET /v1/proofs/{sequence_number}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `sequence_number` | integer | Event sequence number |

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant_id` | uuid | Yes | Tenant identifier |
| `store_id` | uuid | Yes | Store identifier |
| `batch_id` | uuid | Yes | Commitment batch ID |

**Response:**
```json
{
  "sequence_number": 42,
  "batch_id": "uuid",
  "events_root": "hex-32-bytes",
  "leaf_hash": "hex-32-bytes",
  "leaf_index": 41,
  "proof_path": [
    "hex-32-bytes",
    "hex-32-bytes",
    "hex-32-bytes"
  ],
  "directions": [true, false, true]
}
```

---

### Verify Proof

Verify a Merkle inclusion proof.

```http
POST /v1/proofs/verify
```

**Request Body:**
```json
{
  "leaf_hash": "hex-32-bytes",
  "events_root": "hex-32-bytes",
  "proof_path": [
    "hex-32-bytes",
    "hex-32-bytes"
  ],
  "leaf_index": 5
}
```

**Response:**
```json
{
  "valid": true,
  "leaf_hash": "hex",
  "events_root": "hex"
}
```

---

### Get VES Inclusion Proof

Generate a VES v1.0 Merkle inclusion proof for an event in `ves_events`.

```http
GET /v1/ves/proofs/{sequence_number}
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant_id` | uuid | Yes | Tenant identifier |
| `store_id` | uuid | Yes | Store identifier |
| `batch_id` | uuid | Yes | VES commitment batch ID |

**Response:**
```json
{
  "sequence_number": 42,
  "batch_id": "uuid",
  "merkle_root": "hex-32-bytes",
  "leaf_hash": "hex-32-bytes",
  "leaf_index": 41,
  "proof_path": [
    "hex-32-bytes",
    "hex-32-bytes",
    "hex-32-bytes"
  ],
  "directions": [true, false, true]
}
```

---

### Verify VES Proof

Verify a VES v1.0 Merkle inclusion proof.

```http
POST /v1/ves/proofs/verify
```

**Request Body:**
```json
{
  "leaf_hash": "hex-32-bytes",
  "merkle_root": "hex-32-bytes",
  "proof_path": [
    "hex-32-bytes",
    "hex-32-bytes"
  ],
  "leaf_index": 5
}
```

**Response:**
```json
{
  "valid": true,
  "leaf_hash": "hex",
  "merkle_root": "hex"
}
```

---

## Anchoring

### Get Anchor Status

Check if on-chain anchoring is enabled.

```http
GET /v1/anchor/status
```

**Response (enabled):**
```json
{
  "anchor_enabled": true,
  "message": "Anchor service is configured and ready"
}
```

**Response (disabled):**
```json
{
  "anchor_enabled": false,
  "message": "Anchor service not configured. Set L2_RPC_URL, SET_REGISTRY_ADDRESS, SEQUENCER_PRIVATE_KEY"
}
```

---

### External Anchor Service Compatibility (Set Chain)

The separate Set Chain anchor service (`icommerce-app/set/anchor`) expects two root-level endpoints (no `/api` prefix) for pulling pending VES commitments and reporting successful anchoring.

```http
GET /v1/commitments/pending?limit=1000
POST /v1/commitments/{batch_id}/anchored
```

**Notify Request Body:**
```json
{
  "chain_tx_hash": "0x...",
  "chain_id": 84532001,
  "block_number": 123,
  "gas_used": 210000
}
```

---

### Anchor Commitment

Submit a commitment to the blockchain.

```http
POST /v1/anchor
```

**Request Body:**
```json
{
  "batch_id": "uuid"
}
```

**Response (success):**
```json
{
  "batch_id": "uuid",
  "status": "anchored",
  "chain_tx_hash": "0x...",
  "events_root": "hex",
  "sequence_start": 1,
  "sequence_end": 100
}
```

**Response (already anchored):**
```json
{
  "batch_id": "uuid",
  "status": "already_anchored",
  "chain_tx_hash": "0x..."
}
```

---

### Anchor VES Commitment

Submit a VES commitment (`merkle_root`) to the blockchain.

```http
POST /v1/ves/anchor
```

**Request Body:**
```json
{
  "batch_id": "uuid"
}
```

**Response (success):**
```json
{
  "batch_id": "uuid",
  "status": "anchored",
  "chain_tx_hash": "0x...",
  "chain_block_number": 123,
  "merkle_root": "hex",
  "sequence_start": 1,
  "sequence_end": 100
}
```

**Response (already anchored):**
```json
{
  "batch_id": "uuid",
  "status": "already_anchored",
  "chain_tx_hash": "0x..."
}
```

---

### Verify On-Chain Anchor

Verify a commitment exists on-chain.

```http
GET /v1/anchor/{batch_id}/verify
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `batch_id` | uuid | Commitment batch identifier |

**Response:**
```json
{
  "batch_id": "uuid",
  "anchored_on_chain": true
}
```

---

### Verify VES On-Chain Anchor

Verify a VES commitment exists on-chain.

```http
GET /v1/ves/anchor/{batch_id}/verify
```

**Response:**
```json
{
  "batch_id": "uuid",
  "anchored_on_chain": true
}
```

---

## Agent Keys

### Register Agent Key

Register an agent's Ed25519 public key for signature verification.

```http
POST /v1/agents/keys
```

**Request Body:**
```json
{
  "tenantId": "uuid",
  "agentId": "uuid",
  "keyId": 1,
  "publicKey": "hex-64-chars-ed25519-public-key",
  "validFrom": "2024-01-01T00:00:00Z",
  "validTo": "2025-01-01T00:00:00Z"
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tenantId` | uuid | Yes | Tenant identifier |
| `agentId` | uuid | Yes | Agent identifier |
| `keyId` | integer | Yes | Key version (increment for rotation) |
| `publicKey` | string | Yes | Hex-encoded Ed25519 public key (64 chars) |
| `validFrom` | datetime | No | Key validity start time |
| `validTo` | datetime | No | Key validity end time |

**Response:**
```json
{
  "success": true,
  "tenantId": "uuid",
  "agentId": "uuid",
  "keyId": 1,
  "message": "Agent key registered successfully"
}
```

---

## Health & Readiness

### Health Check

Check if the service is running.

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "stateset-sequencer",
  "version": "0.1.0"
}
```

---

### Readiness Check

Check if the service is ready to accept traffic.

```http
GET /ready
```

**Response (ready):**
```json
{
  "status": "ready",
  "database": "connected"
}
```

**Response (not ready):**
```http
HTTP/1.1 503 Service Unavailable

{
  "error": "Database unavailable: connection refused"
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Error description"
}
```

### Common Errors

**Invalid Event ID (duplicate):**
```json
{
  "error": "Event with ID abc-123 already exists"
}
```

**Signature Verification Failed:**
```json
{
  "error": "Signature verification failed: invalid agent signature"
}
```

**Agent Key Not Found:**
```json
{
  "error": "Key not found for tenant abc, agent def, key_id 1"
}
```

**Invalid Sequence Range:**
```json
{
  "error": "Sequence number not in commitment range"
}
```

---

## Rate Limits

| Endpoint | Limit | Burst |
|----------|-------|-------|
| `POST /v1/events/ingest` | 100/sec | 500 |
| `POST /v1/ves/events/ingest` | 100/sec | 500 |
| `GET /v1/events` | 1000/sec | 2000 |
| `POST /v1/commitments` | 10/sec | 50 |
| `POST /v1/anchor` | 1/sec | 5 |

Rate limit headers:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705312260
```

---

## Pagination

List endpoints support pagination:

```http
GET /v1/events?from=100&limit=50
```

Use the `from` parameter with the last `sequence_number` for cursor-based pagination.

---

## Webhooks (Future)

Coming soon: webhook notifications for events.

```json
{
  "webhook_url": "https://your-app.com/webhooks/events",
  "events": ["order.created", "order.shipped"],
  "secret": "whsec_..."
}
```

---

## SDKs

Official SDKs:
- **JavaScript/TypeScript**: `@stateset/sequencer-client`
- **Python**: `stateset-sequencer`
- **Rust**: `stateset-sequencer-client`

Example (JavaScript):
```javascript
import { SequencerClient } from '@stateset/sequencer-client';

const client = new SequencerClient({
  baseUrl: 'https://sequencer.stateset.io',
  apiKey: 'sk_live_...',
  tenantId: 'your-tenant-id',
  storeId: 'your-store-id',
});

// Ingest events
const result = await client.ingestVesEvents([
  {
    entityType: 'order',
    entityId: 'order-123',
    eventType: 'order.created',
    payload: { customer_id: 'cust-456' },
  },
]);

console.log(`Sequenced at: ${result.sequenceStart}`);
```
