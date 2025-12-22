# VES-SIG-1 Demo Guide

This guide provides hands-on examples for implementing VES-SIG-1 agent signatures.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Key Generation Demo](#key-generation-demo)
3. [Step-by-Step Signing Demo](#step-by-step-signing-demo)
4. [Step-by-Step Verification Demo](#step-by-step-verification-demo)
5. [Key Registry Demo](#key-registry-demo)
6. [Key Rotation Demo](#key-rotation-demo)
7. [Integration Examples](#integration-examples)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites

**Rust:**
```toml
# Cargo.toml
[dependencies]
ed25519-dalek = "2.0"
sha2 = "0.10"
rand = "0.8"
uuid = "1.0"
hex = "0.4"
```

**Node.js:**
```bash
npm install @noble/ed25519 @noble/hashes uuid
```

**Python:**
```bash
pip install pynacl
```

### Minimal Signing Example (Node.js)

```javascript
import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';

// 1. Generate key pair
const privateKey = ed25519.utils.randomPrivateKey();
const publicKey = await ed25519.getPublicKeyAsync(privateKey);

// 2. Create message hash
const message = new TextEncoder().encode('Hello, VES!');
const hash = sha256(message);

// 3. Sign
const signature = await ed25519.signAsync(hash, privateKey);
console.log('Signature:', Buffer.from(signature).toString('hex'));

// 4. Verify
const valid = await ed25519.verifyAsync(signature, hash, publicKey);
console.log('Valid:', valid);
```

---

## Key Generation Demo

### Generate Ed25519 Key Pair (Node.js)

```javascript
import * as ed25519 from '@noble/ed25519';

async function generateAgentKeyPair() {
  // Generate cryptographically secure private key
  const privateKey = ed25519.utils.randomPrivateKey();

  // Derive public key
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);

  // Convert to hex for storage/display
  const privateKeyHex = '0x' + Buffer.from(privateKey).toString('hex');
  const publicKeyHex = '0x' + Buffer.from(publicKey).toString('hex');

  console.log('=== Agent Key Pair Generated ===');
  console.log('Private Key (KEEP SECRET!):', privateKeyHex);
  console.log('Public Key:', publicKeyHex);
  console.log('');

  return { privateKey, publicKey, privateKeyHex, publicKeyHex };
}

// Example usage
const keyPair = await generateAgentKeyPair();
```

### Generate Ed25519 Key Pair (Rust)

```rust
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn generate_agent_key_pair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
    // Generate random signing key
    let signing_key = SigningKey::generate(&mut OsRng);

    // Derive verifying (public) key
    let verifying_key = signing_key.verifying_key();

    println!("=== Agent Key Pair Generated ===");
    println!("Private Key: 0x{}", hex::encode(signing_key.to_bytes()));
    println!("Public Key: 0x{}", hex::encode(verifying_key.to_bytes()));

    (signing_key, verifying_key)
}
```

### Generate Ed25519 Key Pair (Python)

```python
from nacl.signing import SigningKey

def generate_agent_key_pair():
    # Generate key pair
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    # Convert to hex
    private_key_hex = '0x' + signing_key.encode().hex()
    public_key_hex = '0x' + verify_key.encode().hex()

    print('=== Agent Key Pair Generated ===')
    print(f'Private Key (KEEP SECRET!): {private_key_hex}')
    print(f'Public Key: {public_key_hex}')

    return signing_key, verify_key

# Example usage
signing_key, verify_key = generate_agent_key_pair()
```

---

## Step-by-Step Signing Demo

This demo walks through signing a VES event step by step.

### Step 1: Define Event Context

```javascript
// Event metadata
const event = {
  vesVersion: 1,
  tenantId: '00000000-0000-0000-0000-000000000001',
  storeId: '00000000-0000-0000-0000-000000000002',
  eventId: '11111111-1111-1111-1111-111111111111',
  sourceAgentId: '22222222-2222-2222-2222-222222222222',
  agentKeyId: 1,
  entityType: 'InventoryItem',
  entityId: 'WIDGET-001',
  eventType: 'InventoryAdjusted',
  createdAt: '2025-01-01T12:00:00Z',
  payloadKind: 0,  // plaintext
};

// Payload
const payload = {
  delta: 100,
  reason: 'shipment_receive',
  location_bin: 'A-12'
};

console.log('Event:', JSON.stringify(event, null, 2));
console.log('Payload:', JSON.stringify(payload, null, 2));
```

### Step 2: Compute Payload Hash

```javascript
import canonicalize from 'canonicalize';
import { sha256 } from '@noble/hashes/sha256';

const DOMAIN_PAYLOAD_PLAIN = new TextEncoder().encode('VES_PAYLOAD_PLAIN_V1');

// Canonicalize payload (RFC 8785)
const canonicalJson = canonicalize(payload);
console.log('Canonical JSON:', canonicalJson);

// Compute payload_plain_hash
const payloadPlainHash = sha256(
  concat(DOMAIN_PAYLOAD_PLAIN, new TextEncoder().encode(canonicalJson))
);

console.log('payload_plain_hash:', '0x' + hex(payloadPlainHash));

// For plaintext, cipher hash is all zeros
const payloadCipherHash = new Uint8Array(32);
console.log('payload_cipher_hash:', '0x' + hex(payloadCipherHash));
```

### Step 3: Build Event Signing Params

```javascript
const signingParams = {
  vesVersion: event.vesVersion,
  tenantId: event.tenantId,
  storeId: event.storeId,
  eventId: event.eventId,
  sourceAgentId: event.sourceAgentId,
  agentKeyId: event.agentKeyId,
  entityType: event.entityType,
  entityId: event.entityId,
  eventType: event.eventType,
  createdAt: event.createdAt,
  payloadKind: event.payloadKind,
  payloadPlainHash: payloadPlainHash,
  payloadCipherHash: payloadCipherHash,
};
```

### Step 4: Build Signing Preimage

```javascript
const DOMAIN_EVENTSIG = new TextEncoder().encode('VES_EVENTSIG_V1');

function buildEventSigningPreimage(params) {
  const parts = [
    // Domain prefix
    DOMAIN_EVENTSIG,

    // Protocol version
    u32be(params.vesVersion),

    // UUIDs (16 bytes each)
    uuidBytes(params.tenantId),
    uuidBytes(params.storeId),
    uuidBytes(params.eventId),
    uuidBytes(params.sourceAgentId),

    // Key ID
    u32be(params.agentKeyId),

    // Length-prefixed strings
    encStr(params.entityType),
    encStr(params.entityId),
    encStr(params.eventType),
    encStr(params.createdAt),

    // Payload kind
    u32be(params.payloadKind),

    // Payload hashes
    params.payloadPlainHash,
    params.payloadCipherHash,
  ];

  return concat(...parts);
}

const preimage = buildEventSigningPreimage(signingParams);
console.log('Preimage length:', preimage.length, 'bytes');
console.log('Preimage (first 100 bytes):', hex(preimage.slice(0, 100)));
```

### Step 5: Compute Event Signing Hash

```javascript
const eventSigningHash = sha256(preimage);
console.log('event_signing_hash:', '0x' + hex(eventSigningHash));
```

### Step 6: Sign with Ed25519

```javascript
import * as ed25519 from '@noble/ed25519';

// Agent's private key (from key generation)
const privateKey = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');

// Sign the hash
const agentSignature = await ed25519.signAsync(eventSigningHash, privateKey);

console.log('agent_signature:', '0x' + hex(agentSignature));
console.log('Signature length:', agentSignature.length, 'bytes');
```

### Step 7: Assemble Complete Event

```javascript
const signedEvent = {
  ves_version: event.vesVersion,
  event_id: event.eventId,
  tenant_id: event.tenantId,
  store_id: event.storeId,
  source_agent_id: event.sourceAgentId,
  agent_key_id: event.agentKeyId,
  entity_type: event.entityType,
  entity_id: event.entityId,
  event_type: event.eventType,
  created_at: event.createdAt,
  payload_kind: event.payloadKind,
  payload: payload,
  payload_plain_hash: '0x' + hex(payloadPlainHash),
  payload_cipher_hash: '0x' + hex(payloadCipherHash),
  agent_signature: '0x' + hex(agentSignature),
};

console.log('\n=== Signed Event ===');
console.log(JSON.stringify(signedEvent, null, 2));
```

---

## Step-by-Step Verification Demo

### Step 1: Parse Event

```javascript
// Received signed event (from API, storage, etc.)
const receivedEvent = {
  ves_version: 1,
  event_id: '11111111-1111-1111-1111-111111111111',
  tenant_id: '00000000-0000-0000-0000-000000000001',
  store_id: '00000000-0000-0000-0000-000000000002',
  source_agent_id: '22222222-2222-2222-2222-222222222222',
  agent_key_id: 1,
  entity_type: 'InventoryItem',
  entity_id: 'WIDGET-001',
  event_type: 'InventoryAdjusted',
  created_at: '2025-01-01T12:00:00Z',
  payload_kind: 0,
  payload: { delta: 100, reason: 'shipment_receive', location_bin: 'A-12' },
  payload_plain_hash: '0x...',
  payload_cipher_hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
  agent_signature: '0x...',
};
```

### Step 2: Lookup Agent Public Key

```javascript
async function lookupAgentPublicKey(tenantId, agentId, keyId) {
  // In production, query the key registry
  const response = await fetch(
    `/api/v1/keys/${tenantId}/${agentId}/${keyId}`
  );
  const keyEntry = await response.json();

  if (keyEntry.status !== 'active') {
    throw new Error(`Key is ${keyEntry.status}`);
  }

  return hexToBytes(keyEntry.public_key);
}

const publicKey = await lookupAgentPublicKey(
  receivedEvent.tenant_id,
  receivedEvent.source_agent_id,
  receivedEvent.agent_key_id
);

console.log('Agent public key:', '0x' + hex(publicKey));
```

### Step 3: Verify Payload Hash

```javascript
// Recompute payload_plain_hash
const canonicalPayload = canonicalize(receivedEvent.payload);
const computedPlainHash = sha256(
  concat(DOMAIN_PAYLOAD_PLAIN, new TextEncoder().encode(canonicalPayload))
);

const expectedPlainHash = hexToBytes(receivedEvent.payload_plain_hash.slice(2));

if (!constantTimeEqual(computedPlainHash, expectedPlainHash)) {
  throw new Error('Payload hash mismatch - payload may be tampered');
}

console.log('Payload hash verified!');

// For plaintext events, verify cipher hash is zeros
if (receivedEvent.payload_kind === 0) {
  const expectedCipherHash = new Uint8Array(32);
  const actualCipherHash = hexToBytes(receivedEvent.payload_cipher_hash.slice(2));
  if (!constantTimeEqual(actualCipherHash, expectedCipherHash)) {
    throw new Error('Plaintext event must have zero cipher hash');
  }
}
```

### Step 4: Recompute Event Signing Hash

```javascript
const verifyParams = {
  vesVersion: receivedEvent.ves_version,
  tenantId: receivedEvent.tenant_id,
  storeId: receivedEvent.store_id,
  eventId: receivedEvent.event_id,
  sourceAgentId: receivedEvent.source_agent_id,
  agentKeyId: receivedEvent.agent_key_id,
  entityType: receivedEvent.entity_type,
  entityId: receivedEvent.entity_id,
  eventType: receivedEvent.event_type,
  createdAt: receivedEvent.created_at,
  payloadKind: receivedEvent.payload_kind,
  payloadPlainHash: hexToBytes(receivedEvent.payload_plain_hash.slice(2)),
  payloadCipherHash: hexToBytes(receivedEvent.payload_cipher_hash.slice(2)),
};

const preimage = buildEventSigningPreimage(verifyParams);
const computedSigningHash = sha256(preimage);

console.log('Computed signing hash:', '0x' + hex(computedSigningHash));
```

### Step 5: Verify Ed25519 Signature

```javascript
const signature = hexToBytes(receivedEvent.agent_signature.slice(2));

const valid = await ed25519.verifyAsync(
  signature,
  computedSigningHash,
  publicKey
);

if (!valid) {
  throw new Error('Signature verification failed');
}

console.log('Signature verified successfully!');
```

### Complete Verification Function

```javascript
async function verifyVesEvent(event, keyRegistry) {
  // 1. Lookup agent key
  const publicKey = await keyRegistry.getPublicKey(
    event.tenant_id,
    event.source_agent_id,
    event.agent_key_id
  );

  // 2. Verify payload hash
  if (event.payload_kind === 0) {
    const canonicalPayload = canonicalize(event.payload);
    const computedPlainHash = sha256(
      concat(DOMAIN_PAYLOAD_PLAIN, new TextEncoder().encode(canonicalPayload))
    );
    const expectedPlainHash = hexToBytes(event.payload_plain_hash.slice(2));

    if (!constantTimeEqual(computedPlainHash, expectedPlainHash)) {
      return { valid: false, error: 'Payload hash mismatch' };
    }
  }

  // 3. Recompute event signing hash
  const params = {
    vesVersion: event.ves_version,
    tenantId: event.tenant_id,
    storeId: event.store_id,
    eventId: event.event_id,
    sourceAgentId: event.source_agent_id,
    agentKeyId: event.agent_key_id,
    entityType: event.entity_type,
    entityId: event.entity_id,
    eventType: event.event_type,
    createdAt: event.created_at,
    payloadKind: event.payload_kind,
    payloadPlainHash: hexToBytes(event.payload_plain_hash.slice(2)),
    payloadCipherHash: hexToBytes(event.payload_cipher_hash.slice(2)),
  };

  const signingHash = sha256(buildEventSigningPreimage(params));

  // 4. Verify signature
  const signature = hexToBytes(event.agent_signature.slice(2));
  const valid = await ed25519.verifyAsync(signature, signingHash, publicKey);

  return { valid, error: valid ? null : 'Invalid signature' };
}
```

---

## Key Registry Demo

### Register a New Key

```javascript
async function registerAgentKey(tenantId, agentId, publicKey) {
  // Get next key ID
  const nextKeyId = await getNextKeyId(tenantId, agentId);

  const keyEntry = {
    tenant_id: tenantId,
    agent_id: agentId,
    key_id: nextKeyId,
    public_key: '0x' + hex(publicKey),
    status: 'active',
    valid_from: new Date().toISOString(),
    valid_to: null,  // No expiry initially
  };

  const response = await fetch('/api/v1/keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(keyEntry),
  });

  if (!response.ok) {
    throw new Error('Failed to register key');
  }

  console.log(`Registered key_id=${nextKeyId} for agent ${agentId}`);
  return nextKeyId;
}
```

### SQL: Register Key

```sql
-- Register a new agent signing key
INSERT INTO agent_signing_keys (
    tenant_id, agent_id, key_id, public_key, status, valid_from
) VALUES (
    '00000000-0000-0000-0000-000000000001',  -- tenant_id
    '22222222-2222-2222-2222-222222222222',  -- agent_id
    1,                                        -- key_id
    '\xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    'active',
    NOW()
);

-- Verify registration
SELECT * FROM agent_signing_keys
WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
  AND agent_id = '22222222-2222-2222-2222-222222222222';
```

### Revoke a Key

```javascript
async function revokeAgentKey(tenantId, agentId, keyId, reason) {
  const response = await fetch(
    `/api/v1/keys/${tenantId}/${agentId}/${keyId}/revoke`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    }
  );

  if (!response.ok) {
    throw new Error('Failed to revoke key');
  }

  console.log(`Revoked key_id=${keyId} for agent ${agentId}`);
}
```

### SQL: Revoke Key

```sql
-- Revoke a key
UPDATE agent_signing_keys
SET status = 'revoked',
    revoked_at = NOW(),
    rotation_reason = 'security_concern'
WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
  AND agent_id = '22222222-2222-2222-2222-222222222222'
  AND key_id = 1;

-- Log the revocation
INSERT INTO key_rotation_audit_log (
    tenant_id, agent_id, key_type, action, old_key_id, actor_type, metadata
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    '22222222-2222-2222-2222-222222222222',
    'signing',
    'key_revoked',
    1,
    'admin',
    '{"reason": "security_concern"}'::jsonb
);
```

---

## Key Rotation Demo

### Perform Key Rotation

```javascript
async function rotateAgentKey(tenantId, agentId, currentKeyId) {
  // 1. Generate new key pair
  const newPrivateKey = ed25519.utils.randomPrivateKey();
  const newPublicKey = await ed25519.getPublicKeyAsync(newPrivateKey);

  // 2. Register new key (next key_id)
  const newKeyId = await registerAgentKey(tenantId, agentId, newPublicKey);

  // 3. Set expiry on old key with grace period
  const gracePeriodHours = 72;
  await setKeyExpiry(tenantId, agentId, currentKeyId, gracePeriodHours);

  // 4. Log rotation
  await logKeyRotation(tenantId, agentId, currentKeyId, newKeyId);

  console.log(`Rotated key: ${currentKeyId} -> ${newKeyId}`);
  console.log(`Old key valid for ${gracePeriodHours} more hours`);

  return {
    newKeyId,
    newPrivateKey,
    newPublicKey,
  };
}
```

### SQL: Key Rotation

```sql
-- 1. Register new key
INSERT INTO agent_signing_keys (tenant_id, agent_id, key_id, public_key, status, valid_from)
SELECT
    tenant_id,
    agent_id,
    (SELECT COALESCE(MAX(key_id), 0) + 1
     FROM agent_signing_keys
     WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
       AND agent_id = '22222222-2222-2222-2222-222222222222'),
    '\x...',  -- new public key
    'active',
    NOW()
FROM agent_signing_keys
WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
  AND agent_id = '22222222-2222-2222-2222-222222222222'
  AND key_id = 1
LIMIT 1
RETURNING key_id as new_key_id;

-- 2. Set grace period on old key
UPDATE agent_signing_keys
SET expires_at = NOW(),
    grace_until = NOW() + INTERVAL '72 hours',
    rotation_reason = 'scheduled_rotation'
WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
  AND agent_id = '22222222-2222-2222-2222-222222222222'
  AND key_id = 1;

-- 3. Log rotation
INSERT INTO key_rotation_audit_log (
    tenant_id, agent_id, key_type, action, old_key_id, new_key_id, actor_type
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    '22222222-2222-2222-2222-222222222222',
    'signing',
    'key_rotated',
    1,
    2,
    'system'
);
```

---

## Integration Examples

### REST API: Submit Signed Event

```bash
curl -X POST https://api.stateset.io/v1/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ves_version": 1,
    "event_id": "11111111-1111-1111-1111-111111111111",
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "store_id": "00000000-0000-0000-0000-000000000002",
    "source_agent_id": "22222222-2222-2222-2222-222222222222",
    "agent_key_id": 1,
    "entity_type": "InventoryItem",
    "entity_id": "WIDGET-001",
    "event_type": "InventoryAdjusted",
    "created_at": "2025-01-01T12:00:00Z",
    "payload_kind": 0,
    "payload": {
      "delta": 100,
      "reason": "shipment_receive"
    },
    "payload_plain_hash": "0x7f8a...",
    "payload_cipher_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "agent_signature": "0x3f8a..."
  }'
```

### Complete Client Example

```javascript
class VesClient {
  constructor(baseUrl, signingKey, agentId, keyId) {
    this.baseUrl = baseUrl;
    this.signingKey = signingKey;
    this.agentId = agentId;
    this.keyId = keyId;
  }

  async submitEvent(tenantId, storeId, entityType, entityId, eventType, payload) {
    const eventId = crypto.randomUUID();
    const createdAt = new Date().toISOString();

    // Compute payload hash
    const canonicalPayload = canonicalize(payload);
    const payloadPlainHash = sha256(
      concat(DOMAIN_PAYLOAD_PLAIN, new TextEncoder().encode(canonicalPayload))
    );
    const payloadCipherHash = new Uint8Array(32);

    // Build signing params
    const params = {
      vesVersion: 1,
      tenantId,
      storeId,
      eventId,
      sourceAgentId: this.agentId,
      agentKeyId: this.keyId,
      entityType,
      entityId,
      eventType,
      createdAt,
      payloadKind: 0,
      payloadPlainHash,
      payloadCipherHash,
    };

    // Compute signing hash
    const preimage = buildEventSigningPreimage(params);
    const signingHash = sha256(preimage);

    // Sign
    const signature = await ed25519.signAsync(signingHash, this.signingKey);

    // Build event
    const event = {
      ves_version: 1,
      event_id: eventId,
      tenant_id: tenantId,
      store_id: storeId,
      source_agent_id: this.agentId,
      agent_key_id: this.keyId,
      entity_type: entityType,
      entity_id: entityId,
      event_type: eventType,
      created_at: createdAt,
      payload_kind: 0,
      payload,
      payload_plain_hash: '0x' + hex(payloadPlainHash),
      payload_cipher_hash: '0x' + hex(payloadCipherHash),
      agent_signature: '0x' + hex(signature),
    };

    // Submit
    const response = await fetch(`${this.baseUrl}/v1/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
    });

    if (!response.ok) {
      throw new Error(`Submit failed: ${response.statusText}`);
    }

    const result = await response.json();
    return {
      eventId,
      sequenceNumber: result.sequence_number,
    };
  }
}

// Usage
const client = new VesClient(
  'https://api.stateset.io',
  privateKey,
  '22222222-2222-2222-2222-222222222222',
  1
);

const result = await client.submitEvent(
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000002',
  'InventoryItem',
  'WIDGET-001',
  'InventoryAdjusted',
  { delta: 100, reason: 'shipment_receive' }
);

console.log('Event submitted:', result);
```

---

## Troubleshooting

### Common Issues

**Issue: "Signature verification failed"**

Causes:
1. Event signing hash computed differently
2. Wrong public key for agent_key_id
3. Signature corrupted during transmission

Solution:
- Log the computed signing hash on both sides
- Verify key lookup returns correct public key
- Check hex encoding/decoding is correct

**Issue: "Key not found"**

Causes:
1. Key not registered in registry
2. Wrong tenant/agent/key_id combination
3. Key has been revoked

Solution:
- Verify key registration in database
- Check lookup parameters match event
- Query key status

**Issue: "Payload hash mismatch"**

Causes:
1. JSON canonicalization differs
2. Domain prefix incorrect
3. Payload modified after signing

Solution:
- Test canonicalization with known vectors
- Verify domain is `VES_PAYLOAD_PLAIN_V1`
- Compare original and received payload

### Debug Logging

```javascript
function debugSigning(step, data) {
  console.log(`[VES-SIG-1] ${step}:`);
  if (data instanceof Uint8Array) {
    console.log(`  hex: ${hex(data)}`);
    console.log(`  len: ${data.length} bytes`);
  } else if (typeof data === 'object') {
    console.log(`  ${JSON.stringify(data, null, 2)}`);
  } else {
    console.log(`  ${data}`);
  }
}

// Usage
debugSigning('Canonical JSON', canonicalJson);
debugSigning('payload_plain_hash', payloadPlainHash);
debugSigning('Preimage', preimage);
debugSigning('event_signing_hash', signingHash);
debugSigning('agent_signature', signature);
```

---

## Helper Functions Reference

```javascript
// Hex encode
function hex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Hex decode (strips 0x prefix)
function hexToBytes(hex) {
  hex = hex.startsWith('0x') ? hex.slice(2) : hex;
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

// Concatenate Uint8Arrays
function concat(...arrays) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// Big-endian u32
function u32be(n) {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, n, false);
  return buf;
}

// Encode string (length-prefixed UTF-8)
function encStr(s) {
  const bytes = new TextEncoder().encode(s);
  return concat(u32be(bytes.length), bytes);
}

// UUID to bytes
function uuidBytes(uuid) {
  return hexToBytes(uuid.replace(/-/g, ''));
}

// Constant-time comparison
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
```

---

*For the complete specification, see [VES_SIG_1_SPECIFICATION.md](./VES_SIG_1_SPECIFICATION.md).*
