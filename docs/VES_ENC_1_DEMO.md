# VES-ENC-1 Demo Guide

This guide provides hands-on examples for implementing VES-ENC-1 encrypted payloads.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Step-by-Step Encryption Demo](#step-by-step-encryption-demo)
3. [Step-by-Step Decryption Demo](#step-by-step-decryption-demo)
4. [Multi-Recipient Encryption](#multi-recipient-encryption)
5. [Key Generation](#key-generation)
6. [Integration Examples](#integration-examples)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites

**Rust:**
```toml
# Cargo.toml
[dependencies]
aes-gcm = "0.10"
hpke = "0.11"
sha2 = "0.10"
rand = "0.8"
serde_json = "1.0"
base64 = "0.21"
uuid = "1.0"
```

**Node.js:**
```bash
npm install @noble/hpke @noble/ed25519 canonicalize
```

**Python:**
```bash
pip install cryptography canonicaljson pyhpke
```

### Minimal Encryption Example (Node.js)

```javascript
import { webcrypto } from 'crypto';

// 1. Setup
const payload = { delta: 100, reason: "shipment_receive" };
const salt = webcrypto.getRandomValues(new Uint8Array(16));
const dek = webcrypto.getRandomValues(new Uint8Array(32));
const nonce = webcrypto.getRandomValues(new Uint8Array(12));

// 2. Canonicalize and prepare plaintext
const canonicalJson = JSON.stringify(payload, Object.keys(payload).sort());
const plaintext = concat(salt, new TextEncoder().encode(canonicalJson));

// 3. Encrypt with AES-256-GCM
const key = await webcrypto.subtle.importKey('raw', dek, 'AES-GCM', false, ['encrypt']);
const ciphertext = await webcrypto.subtle.encrypt(
  { name: 'AES-GCM', iv: nonce },
  key,
  plaintext
);

console.log('Encrypted payload:', base64url(new Uint8Array(ciphertext)));
```

---

## Step-by-Step Encryption Demo

This demo walks through encrypting a payload for a single recipient.

### Step 1: Prepare the Payload

```javascript
// Sample inventory adjustment event
const payload = {
  delta: 100,
  reason: "shipment_receive",
  location_bin: "A-12",
  po_number: "PO-2025-001"
};

console.log("Original payload:", JSON.stringify(payload, null, 2));
```

### Step 2: Canonicalize with RFC 8785 JCS

```javascript
import canonicalize from 'canonicalize';

const canonicalJson = canonicalize(payload);
console.log("Canonical JSON:", canonicalJson);
// Output: {"delta":100,"location_bin":"A-12","po_number":"PO-2025-001","reason":"shipment_receive"}
```

### Step 3: Generate Random Values

```javascript
const salt = crypto.getRandomValues(new Uint8Array(16));
const dek = crypto.getRandomValues(new Uint8Array(32));
const nonce = crypto.getRandomValues(new Uint8Array(12));

console.log("Salt:", hex(salt));
console.log("DEK:", hex(dek));
console.log("Nonce:", hex(nonce));
```

### Step 4: Compute payload_plain_hash

```javascript
const DOMAIN_PAYLOAD_PLAIN = new TextEncoder().encode("VES_PAYLOAD_PLAIN_V1");

// Prepare plaintext: salt || JCS(payload)
const canonicalBytes = new TextEncoder().encode(canonicalJson);
const plaintext = concat(salt, canonicalBytes);

// Hash with domain separator
const hashInput = concat(DOMAIN_PAYLOAD_PLAIN, plaintext);
const payloadPlainHash = await sha256(hashInput);

console.log("payload_plain_hash:", "0x" + hex(payloadPlainHash));
```

### Step 5: Compute Payload AAD

```javascript
const DOMAIN_PAYLOAD_AAD = new TextEncoder().encode("VES_PAYLOAD_AAD_V1");

// Event context
const eventContext = {
  vesVersion: 1,
  tenantId: "00000000-0000-0000-0000-000000000001",
  storeId: "00000000-0000-0000-0000-000000000002",
  eventId: "11111111-1111-1111-1111-111111111111",
  sourceAgentId: "22222222-2222-2222-2222-222222222222",
  agentKeyId: 1,
  entityType: "InventoryItem",
  entityId: "WIDGET-001",
  eventType: "InventoryAdjusted",
  createdAt: "2025-01-01T12:00:00Z"
};

// Build AAD preimage
const aadPreimage = concat(
  DOMAIN_PAYLOAD_AAD,
  u32be(eventContext.vesVersion),
  uuidBytes(eventContext.tenantId),
  uuidBytes(eventContext.storeId),
  uuidBytes(eventContext.eventId),
  uuidBytes(eventContext.sourceAgentId),
  u32be(eventContext.agentKeyId),
  encStr(eventContext.entityType),
  encStr(eventContext.entityId),
  encStr(eventContext.eventType),
  encStr(eventContext.createdAt),
  payloadPlainHash
);

const payloadAad = await sha256(aadPreimage);
console.log("payload_aad:", "0x" + hex(payloadAad));
```

### Step 6: Encrypt with AES-256-GCM

```javascript
const key = await crypto.subtle.importKey(
  'raw', dek, { name: 'AES-GCM' }, false, ['encrypt']
);

const ciphertextWithTag = new Uint8Array(await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: nonce, additionalData: payloadAad },
  key,
  plaintext
));

const ciphertext = ciphertextWithTag.slice(0, -16);
const tag = ciphertextWithTag.slice(-16);

console.log("Ciphertext:", base64url(ciphertext));
console.log("Tag:", base64url(tag));
```

### Step 7: Wrap DEK with HPKE

```javascript
import * as hpke from '@noble/hpke';

// Recipient's X25519 public key
const recipientPublicKey = hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
const recipientKid = 1;

// HPKE encryption
const suite = hpke.CipherSuite.default; // X25519-HKDF-SHA256/AES-256-GCM
const { enc, ciphertext: wrappedDek } = await suite.seal(
  { recipientPublicKey, info: payloadAad },
  dek
);

console.log("HPKE enc:", base64url(enc));
console.log("Wrapped DEK:", base64url(wrappedDek));
```

### Step 8: Build Recipients Array

```javascript
const recipients = [
  {
    recipient_kid: recipientKid,
    enc_b64u: base64url(enc),
    ct_b64u: base64url(wrappedDek)
  }
];

// Sort by kid (already sorted for single recipient)
recipients.sort((a, b) => a.recipient_kid - b.recipient_kid);
```

### Step 9: Compute recipients_hash

```javascript
const DOMAIN_RECIPIENTS = new TextEncoder().encode("VES_RECIPIENTS_V1");

let recipientsPreimage = DOMAIN_RECIPIENTS;
for (const r of recipients) {
  const encBytes = base64urlDecode(r.enc_b64u);
  const ctBytes = base64urlDecode(r.ct_b64u);
  recipientsPreimage = concat(
    recipientsPreimage,
    u32be(r.recipient_kid),
    u32be(encBytes.length), encBytes,
    u32be(ctBytes.length), ctBytes
  );
}

const recipientsHash = await sha256(recipientsPreimage);
console.log("recipients_hash:", "0x" + hex(recipientsHash));
```

### Step 10: Compute payload_cipher_hash

```javascript
const DOMAIN_PAYLOAD_CIPHER = new TextEncoder().encode("VES_PAYLOAD_CIPHER_V1");

const cipherPreimage = concat(
  DOMAIN_PAYLOAD_CIPHER,
  u32be(1),                        // enc_version
  nonce,
  payloadAad,
  u32be(ciphertext.length), ciphertext,
  tag,
  recipientsHash
);

const payloadCipherHash = await sha256(cipherPreimage);
console.log("payload_cipher_hash:", "0x" + hex(payloadCipherHash));
```

### Step 11: Assemble Final Encrypted Payload

```javascript
const payloadEncrypted = {
  enc_version: 1,
  aead: "AES-256-GCM",
  nonce_b64u: base64url(nonce),
  ciphertext_b64u: base64url(ciphertext),
  tag_b64u: base64url(tag),
  hpke: {
    mode: "base",
    kem: "X25519-HKDF-SHA256",
    kdf: "HKDF-SHA256",
    aead: "AES-256-GCM"
  },
  recipients: recipients
};

console.log("Encrypted Payload:", JSON.stringify(payloadEncrypted, null, 2));
```

---

## Step-by-Step Decryption Demo

### Step 1: Parse Encrypted Payload

```javascript
// Assume we have received payloadEncrypted from step 11 above
const { enc_version, nonce_b64u, ciphertext_b64u, tag_b64u, recipients } = payloadEncrypted;

// Recipient's private key
const recipientPrivateKey = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
const myKid = 1;
```

### Step 2: Find Recipient Entry

```javascript
const myRecipient = recipients.find(r => r.recipient_kid === myKid);
if (!myRecipient) {
  throw new Error("Recipient not found");
}
```

### Step 3: Recompute Payload AAD

```javascript
// Use the expected payload_plain_hash from the event
const expectedPlainHash = hexToBytes("7f8a9b3c...");

// Recompute AAD (same as encryption step 5)
const payloadAad = await computeAad(eventContext, expectedPlainHash);
```

### Step 4: Unwrap DEK with HPKE

```javascript
const enc = base64urlDecode(myRecipient.enc_b64u);
const wrappedDek = base64urlDecode(myRecipient.ct_b64u);

const suite = hpke.CipherSuite.default;
const dek = await suite.open(
  { recipientPrivateKey, enc, info: payloadAad },
  wrappedDek
);

console.log("Recovered DEK:", hex(dek));
```

### Step 5: Decrypt with AES-256-GCM

```javascript
const nonce = base64urlDecode(nonce_b64u);
const ciphertext = base64urlDecode(ciphertext_b64u);
const tag = base64urlDecode(tag_b64u);

const key = await crypto.subtle.importKey(
  'raw', dek, { name: 'AES-GCM' }, false, ['decrypt']
);

const plaintext = new Uint8Array(await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: nonce, additionalData: payloadAad },
  key,
  concat(ciphertext, tag)
));

console.log("Decrypted plaintext length:", plaintext.length);
```

### Step 6: Extract Salt and Payload

```javascript
const salt = plaintext.slice(0, 16);
const jsonBytes = plaintext.slice(16);
const payload = JSON.parse(new TextDecoder().decode(jsonBytes));

console.log("Recovered salt:", hex(salt));
console.log("Decrypted payload:", payload);
```

### Step 7: Verify payload_plain_hash

```javascript
const computedHash = await sha256(concat(
  DOMAIN_PAYLOAD_PLAIN,
  plaintext
));

if (!constantTimeEqual(computedHash, expectedPlainHash)) {
  throw new Error("Payload hash mismatch - data may be tampered");
}

console.log("Payload hash verified successfully!");
```

---

## Multi-Recipient Encryption

### Encrypting for Multiple Recipients

```javascript
// Multiple recipient public keys
const recipientKeys = [
  { kid: 1, publicKey: hexToBytes("8520f009...") },  // Agent A
  { kid: 2, publicKey: hexToBytes("a5b8c012...") },  // Agent B
  { kid: 5, publicKey: hexToBytes("f3e2d1c0...") },  // Agent C (auditor)
];

// Generate single DEK
const dek = crypto.getRandomValues(new Uint8Array(32));

// Wrap DEK for each recipient
const recipients = [];
for (const { kid, publicKey } of recipientKeys) {
  const { enc, ciphertext: wrappedDek } = await hpkeSeal(publicKey, dek, payloadAad);
  recipients.push({
    recipient_kid: kid,
    enc_b64u: base64url(enc),
    ct_b64u: base64url(wrappedDek)
  });
}

// IMPORTANT: Sort by kid
recipients.sort((a, b) => a.recipient_kid - b.recipient_kid);

// Continue with encryption as normal...
```

### Using Encryption Groups

```sql
-- Create a group for warehouse team
INSERT INTO encryption_key_groups (group_id, tenant_id, name, created_by)
VALUES ('g1', 't1', 'Warehouse Team', 'admin');

-- Add members with their encryption keys
SELECT add_group_member('g1', 'agent_a', 1, 'admin', 'member');
SELECT add_group_member('g1', 'agent_b', 1, 'admin', 'member');
SELECT add_group_member('g1', 'auditor', 2, 'admin', 'member');

-- Get all recipient keys for the group
SELECT * FROM get_group_recipient_keys('g1');
```

---

## Key Generation

### Generate X25519 Key Pair (Node.js)

```javascript
import { x25519 } from '@noble/curves/ed25519';

// Generate private key
const privateKey = crypto.getRandomValues(new Uint8Array(32));

// Derive public key
const publicKey = x25519.getPublicKey(privateKey);

console.log("Private key (keep secret!):", hex(privateKey));
console.log("Public key (share with senders):", hex(publicKey));
```

### Generate X25519 Key Pair (Rust)

```rust
use x25519_dalek::{StaticSecret, PublicKey};
use rand::rngs::OsRng;

let private_key = StaticSecret::random_from_rng(OsRng);
let public_key = PublicKey::from(&private_key);

println!("Private key: {:?}", private_key.to_bytes());
println!("Public key: {:?}", public_key.as_bytes());
```

### Register Encryption Key

```sql
INSERT INTO agent_encryption_keys (tenant_id, agent_id, key_id, public_key, status)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  '22222222-2222-2222-2222-222222222222',
  1,
  '\x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
  'active'
);
```

---

## Integration Examples

### REST API: Submit Encrypted Event

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
    "payload_kind": 1,
    "payload_encrypted": {
      "enc_version": 1,
      "aead": "AES-256-GCM",
      "nonce_b64u": "dGVzdG5vbmNl",
      "ciphertext_b64u": "...",
      "tag_b64u": "...",
      "hpke": {
        "mode": "base",
        "kem": "X25519-HKDF-SHA256",
        "kdf": "HKDF-SHA256",
        "aead": "AES-256-GCM"
      },
      "recipients": [
        {
          "recipient_kid": 1,
          "enc_b64u": "...",
          "ct_b64u": "..."
        }
      ]
    },
    "payload_plain_hash": "0x7f8a...",
    "payload_cipher_hash": "0x9b2c...",
    "agent_signature": "0x..."
  }'
```

### Verify Event Without Decryption (Sequencer)

```javascript
async function verifyEncryptedEvent(event) {
  // 1. Verify agent signature
  const signingHash = computeEventSigningHash(event);
  const agentPublicKey = await getAgentPublicKey(
    event.tenant_id,
    event.source_agent_id,
    event.agent_key_id
  );
  if (!ed25519.verify(event.agent_signature, signingHash, agentPublicKey)) {
    throw new Error("Invalid agent signature");
  }

  // 2. Verify payload_cipher_hash (without decryption!)
  const payloadAad = await computeAad(event, hexToBytes(event.payload_plain_hash));
  const computedCipherHash = await computeCipherHash(
    event.payload_encrypted,
    payloadAad
  );
  if (hex(computedCipherHash) !== event.payload_cipher_hash.slice(2)) {
    throw new Error("Cipher hash mismatch");
  }

  // 3. Assign sequence number
  const sequenceNumber = await assignSequenceNumber(event.tenant_id, event.store_id);

  return { valid: true, sequenceNumber };
}
```

---

## Troubleshooting

### Common Issues

**Issue: "Decryption failed: authentication tag mismatch"**

Causes:
1. AAD was computed differently during encryption vs decryption
2. Ciphertext or tag was corrupted
3. Wrong recipient private key

Solution:
- Verify event context matches exactly
- Check base64url decoding is correct
- Confirm you're using the correct key for the recipient_kid

**Issue: "Payload hash mismatch"**

Causes:
1. JSON canonicalization differs between implementations
2. Salt was not prepended correctly
3. Domain separator is wrong

Solution:
- Test canonicalization with known test vectors
- Verify salt is first 16 bytes of plaintext
- Check domain separator is exactly `VES_PAYLOAD_PLAIN_V1`

**Issue: "HPKE decryption failed"**

Causes:
1. Info bytes (AAD) don't match
2. Wrong HPKE suite
3. Key format mismatch

Solution:
- Ensure payload_aad is computed identically
- Verify HPKE suite is X25519-HKDF-SHA256/AES-256-GCM
- Check key is raw 32-byte X25519 format

### Debug Logging

```javascript
function debugEncryption(step, data) {
  console.log(`[VES-ENC-1] ${step}:`);
  if (data instanceof Uint8Array) {
    console.log(`  hex: ${hex(data)}`);
    console.log(`  len: ${data.length} bytes`);
  } else {
    console.log(`  ${JSON.stringify(data, null, 2)}`);
  }
}

// Usage
debugEncryption("Salt", salt);
debugEncryption("Canonical JSON", canonicalJson);
debugEncryption("Plaintext", plaintext);
debugEncryption("payload_plain_hash", payloadPlainHash);
debugEncryption("payload_aad", payloadAad);
```

---

## Helper Functions Reference

```javascript
// Base64url encode (no padding)
function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Base64url decode
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// Hex encode
function hex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Hex decode
function hexToBytes(hex) {
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

// SHA-256
async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
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

*For the complete specification, see [VES_ENC_1_SPECIFICATION.md](./VES_ENC_1_SPECIFICATION.md).*
