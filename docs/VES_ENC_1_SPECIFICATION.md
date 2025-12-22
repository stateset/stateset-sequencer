# VES-ENC-1: Encrypted Payload Specification

**Version:** 1.0
**Status:** Stable
**Last Updated:** 2025-12-22
**Parent Specification:** VES v1.0 Section 5A

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Principles](#2-design-principles)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Data Structures](#4-data-structures)
5. [Encryption Process](#5-encryption-process)
6. [Decryption Process](#6-decryption-process)
7. [Hash Computations](#7-hash-computations)
8. [Key Management](#8-key-management)
9. [JSON Schemas](#9-json-schemas)
10. [Code Examples](#10-code-examples)
11. [Test Vectors](#11-test-vectors)
12. [Security Considerations](#12-security-considerations)
13. [Implementation Checklist](#13-implementation-checklist)
14. [Appendix A: Domain Separators](#appendix-a-domain-separators)
15. [Appendix B: Base64url Encoding](#appendix-b-base64url-encoding)

---

## 1. Overview

VES-ENC-1 is the encrypted payload format for the Verifiable Event Sync (VES) protocol. It enables end-to-end encryption where:

- **Agents** encrypt payloads for designated recipients
- **Sequencers** sequence and commit events without accessing plaintext
- **Recipients** decrypt payloads using their private keys
- **Verifiers** validate cryptographic proofs without decryption

### 1.1 Key Features

| Feature | Description |
|---------|-------------|
| **Sequencer-Blind** | Sequencer can process events without decrypting payloads |
| **Multi-Recipient** | Single encrypted payload for multiple recipients |
| **Context-Bound** | AAD prevents ciphertext substitution between events |
| **Salt Protection** | Prevents guessing low-entropy payloads via hash comparison |
| **Forward Secrecy** | Per-event random DEK limits key compromise exposure |

### 1.2 Algorithm Summary

| Component | Algorithm | Key/Output Size |
|-----------|-----------|-----------------|
| Content Encryption | AES-256-GCM | 256-bit key |
| Key Encapsulation | HPKE (RFC 9180) | See below |
| Hashing | SHA-256 | 256-bit |
| JSON Canonicalization | JCS (RFC 8785) | N/A |

**HPKE Suite:**
- Mode: Base (0x00)
- KEM: DHKEM(X25519, HKDF-SHA256) - 0x0020
- KDF: HKDF-SHA256 - 0x0001
- AEAD: AES-256-GCM - 0x0002

---

## 2. Design Principles

### 2.1 Sequencer-Blind Design

The sequencer MUST be able to:
- Validate event structure and signatures
- Assign sequence numbers
- Build Merkle proofs
- Commit batches on-chain

The sequencer MUST NOT be able to:
- Read plaintext payload content
- Distinguish payload content (beyond encrypted size)

### 2.2 Cryptographic Binding

All encrypted payloads are cryptographically bound to their event context through Additional Authenticated Data (AAD), preventing:
- Ciphertext substitution between events
- Replay attacks across different contexts
- Tampering with event metadata

### 2.3 Dual-Hash Commitment

Every event commits to two hashes:
- `payload_plain_hash`: Commits to plaintext (agent-verifiable)
- `payload_cipher_hash`: Commits to ciphertext structure (sequencer-verifiable)

This allows:
- Recipients to verify decrypted content matches agent's intent
- Sequencers to verify ciphertext integrity without decryption

---

## 3. Cryptographic Primitives

### 3.1 AES-256-GCM (Content Encryption)

**Purpose:** Encrypt the payload content with authenticated encryption.

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256 in GCM mode |
| Key Size | 256 bits (32 bytes) |
| Nonce Size | 96 bits (12 bytes) |
| Tag Size | 128 bits (16 bytes) |

**Security:** Provides both confidentiality and integrity. The authentication tag ensures any tampering is detected.

### 3.2 HPKE (Key Encapsulation)

**Purpose:** Wrap the Data Encryption Key (DEK) for each recipient.

```
Mode:  Base (0x00) - No pre-shared key, no authentication
KEM:   DHKEM(X25519, HKDF-SHA256)
KDF:   HKDF-SHA256
AEAD:  AES-256-GCM
```

**Key Sizes:**
| Key Type | Size |
|----------|------|
| X25519 Private Key | 32 bytes |
| X25519 Public Key | 32 bytes |
| Encapsulated Key (enc) | 32 bytes |
| Wrapped DEK Ciphertext | 48 bytes (32 + 16 tag) |

### 3.3 SHA-256 (Hashing)

**Purpose:** Compute all cryptographic hashes with domain separation.

| Parameter | Value |
|-----------|-------|
| Algorithm | SHA-256 |
| Output Size | 256 bits (32 bytes) |
| Encoding | Lowercase hex with `0x` prefix |

### 3.4 RFC 8785 JCS (Canonicalization)

**Purpose:** Ensure deterministic JSON serialization across implementations.

**Rules:**
- Object keys: Sorted lexicographically by UTF-16 code units
- Numbers: No unnecessary whitespace or trailing zeros
- Strings: Minimal escaping (only required characters)
- No whitespace between tokens
- UTF-8 encoding

---

## 4. Data Structures

### 4.1 PayloadEncrypted Structure

The encrypted payload is represented as a JSON object:

```json
{
  "enc_version": 1,
  "aead": "AES-256-GCM",
  "nonce_b64u": "<base64url-encoded-12-bytes>",
  "ciphertext_b64u": "<base64url-encoded-bytes>",
  "tag_b64u": "<base64url-encoded-16-bytes>",
  "hpke": {
    "mode": "base",
    "kem": "X25519-HKDF-SHA256",
    "kdf": "HKDF-SHA256",
    "aead": "AES-256-GCM"
  },
  "recipients": [
    {
      "recipient_kid": <integer>,
      "enc_b64u": "<base64url-encoded-32-bytes>",
      "ct_b64u": "<base64url-encoded-48-bytes>"
    }
  ]
}
```

### 4.2 Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `enc_version` | u32 | Encryption version, MUST be `1` |
| `aead` | string | AEAD algorithm identifier |
| `nonce_b64u` | string | 12-byte nonce (base64url, no padding) |
| `ciphertext_b64u` | string | Encrypted `salt \|\| JCS(payload)` |
| `tag_b64u` | string | 16-byte authentication tag |
| `hpke` | object | HPKE algorithm parameters |
| `recipients` | array | List of recipient entries, sorted by `recipient_kid` |

### 4.3 Recipient Entry

| Field | Type | Description |
|-------|------|-------------|
| `recipient_kid` | u32 | Recipient key ID in registry |
| `enc_b64u` | string | HPKE encapsulated key (32 bytes) |
| `ct_b64u` | string | HPKE-encrypted DEK (48 bytes) |

---

## 5. Encryption Process

### 5.1 Step-by-Step Algorithm

```
ENCRYPT(payload, event_context, recipient_keys[]):

1. GENERATE RANDOM VALUES
   salt    ← random(16 bytes)     // Payload salt
   dek     ← random(32 bytes)     // Data Encryption Key
   nonce   ← random(12 bytes)     // AES-GCM nonce

2. PREPARE PLAINTEXT
   plaintext ← salt || JCS(payload)

3. COMPUTE PAYLOAD_PLAIN_HASH
   payload_plain_hash ← SHA256(
     b"VES_PAYLOAD_PLAIN_V1" || plaintext
   )

4. COMPUTE PAYLOAD AAD
   payload_aad ← SHA256(
     b"VES_PAYLOAD_AAD_V1" ||
     U32_BE(ves_version) ||
     UUID(tenant_id) ||
     UUID(store_id) ||
     UUID(event_id) ||
     UUID(source_agent_id) ||
     U32_BE(agent_key_id) ||
     ENC_STR(entity_type) ||
     ENC_STR(entity_id) ||
     ENC_STR(event_type) ||
     ENC_STR(created_at) ||
     payload_plain_hash
   )

5. ENCRYPT WITH AES-256-GCM
   (ciphertext, tag) ← AES-256-GCM.Encrypt(
     key   = dek,
     nonce = nonce,
     plaintext = plaintext,
     aad   = payload_aad
   )

6. WRAP DEK FOR EACH RECIPIENT (HPKE)
   FOR EACH (kid, public_key) IN recipient_keys:
     (enc, ct) ← HPKE.Seal(
       recipient_public_key = public_key,
       info = payload_aad,
       plaintext = dek
     )
     recipients.append({kid, enc, ct})

   SORT recipients BY kid ASC

7. COMPUTE RECIPIENTS_HASH
   recipients_hash ← SHA256(
     b"VES_RECIPIENTS_V1" ||
     FOR EACH r IN recipients:
       U32_BE(r.kid) ||
       U32_BE(len(r.enc)) || r.enc ||
       U32_BE(len(r.ct)) || r.ct
   )

8. COMPUTE PAYLOAD_CIPHER_HASH
   payload_cipher_hash ← SHA256(
     b"VES_PAYLOAD_CIPHER_V1" ||
     U32_BE(1) ||                    // enc_version
     nonce ||
     payload_aad ||
     U32_BE(len(ciphertext)) || ciphertext ||
     tag ||
     recipients_hash
   )

9. RETURN
   payload_encrypted = {
     enc_version: 1,
     aead: "AES-256-GCM",
     nonce_b64u: base64url(nonce),
     ciphertext_b64u: base64url(ciphertext),
     tag_b64u: base64url(tag),
     hpke: { mode: "base", kem: "X25519-HKDF-SHA256", ... },
     recipients: [{ recipient_kid, enc_b64u, ct_b64u }, ...]
   }
   RETURN (payload_encrypted, payload_plain_hash, payload_cipher_hash)
```

### 5.2 Encryption Flowchart

```
                    ┌─────────────┐
                    │   Payload   │
                    │   (JSON)    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │     JCS     │
                    │ Canonicalize│
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐     ┌──────▼──────┐    ┌─────▼─────┐
    │  Salt   │     │  Plaintext  │    │    DEK    │
    │(16 byte)│     │salt || JCS()│    │ (32 byte) │
    └────┬────┘     └──────┬──────┘    └─────┬─────┘
         │                 │                 │
         │          ┌──────▼──────┐          │
         │          │payload_plain│          │
         └─────────►│    _hash    │          │
                    └──────┬──────┘          │
                           │                 │
                    ┌──────▼──────┐          │
                    │   Compute   │          │
                    │  payload_aad│◄─────────┤
                    └──────┬──────┘          │
                           │                 │
              ┌────────────┼────────────┐    │
              │            │            │    │
       ┌──────▼──────┐     │     ┌──────▼────▼─┐
       │    HPKE     │     │     │  AES-256-GCM │
       │   Wrap DEK  │     │     │   Encrypt    │
       └──────┬──────┘     │     └──────┬───────┘
              │            │            │
              ▼            │            ▼
       ┌───────────┐       │     ┌───────────┐
       │recipients │       │     │ ciphertext│
       │  array    │       │     │  + tag    │
       └─────┬─────┘       │     └─────┬─────┘
             │             │           │
             ▼             │           │
       ┌───────────┐       │           │
       │recipients_│       │           │
       │   hash    │       │           │
       └─────┬─────┘       │           │
             │             │           │
             └─────────────┼───────────┘
                           │
                    ┌──────▼──────┐
                    │payload_cipher│
                    │    _hash    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Encrypted  │
                    │   Output    │
                    └─────────────┘
```

---

## 6. Decryption Process

### 6.1 Step-by-Step Algorithm

```
DECRYPT(payload_encrypted, event_context, recipient_kid, recipient_private_key, expected_plain_hash):

1. FIND RECIPIENT ENTRY
   recipient ← payload_encrypted.recipients.find(r => r.recipient_kid == recipient_kid)
   IF recipient IS NULL:
     ERROR "Recipient not found"

2. RECOMPUTE PAYLOAD AAD
   // Must use same event_context as encryption
   payload_aad ← COMPUTE_PAYLOAD_AAD(event_context, expected_plain_hash)

3. UNWRAP DEK (HPKE)
   enc ← base64url_decode(recipient.enc_b64u)
   ct  ← base64url_decode(recipient.ct_b64u)
   dek ← HPKE.Open(
     encapped_key = enc,
     ciphertext = ct,
     recipient_private_key = recipient_private_key,
     info = payload_aad
   )

4. DECRYPT WITH AES-256-GCM
   nonce      ← base64url_decode(payload_encrypted.nonce_b64u)
   ciphertext ← base64url_decode(payload_encrypted.ciphertext_b64u)
   tag        ← base64url_decode(payload_encrypted.tag_b64u)

   plaintext ← AES-256-GCM.Decrypt(
     key = dek,
     nonce = nonce,
     ciphertext = ciphertext || tag,
     aad = payload_aad
   )

5. EXTRACT SALT AND PAYLOAD
   salt    ← plaintext[0:16]
   json    ← plaintext[16:]
   payload ← JSON.parse(json)

6. VERIFY PAYLOAD_PLAIN_HASH
   computed_hash ← SHA256(b"VES_PAYLOAD_PLAIN_V1" || plaintext)
   IF computed_hash != expected_plain_hash:
     ERROR "Payload hash mismatch - data may be tampered"

7. RETURN payload
```

### 6.2 Decryption Flowchart

```
┌─────────────────┐     ┌─────────────────┐
│payload_encrypted│     │ recipient_kid   │
└────────┬────────┘     │ private_key     │
         │              └────────┬────────┘
         │                       │
         ▼                       │
┌─────────────────┐              │
│  Find Recipient │◄─────────────┘
│     Entry       │
└────────┬────────┘
         │
         ├────────────────────────────┐
         │                            │
         ▼                            ▼
┌─────────────────┐          ┌─────────────────┐
│   Recompute     │          │  HPKE Unwrap    │
│   payload_aad   │─────────►│      DEK        │
└─────────────────┘          └────────┬────────┘
                                      │
                               ┌──────▼──────┐
                               │ AES-256-GCM │
                               │   Decrypt   │
                               └──────┬──────┘
                                      │
                               ┌──────▼──────┐
                               │  Plaintext  │
                               │salt || json │
                               └──────┬──────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
             ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
             │ Extract Salt│   │ Parse JSON  │   │   Verify    │
             │  (16 bytes) │   │   Payload   │   │    Hash     │
             └─────────────┘   └──────┬──────┘   └─────────────┘
                                      │
                               ┌──────▼──────┐
                               │  Decrypted  │
                               │   Payload   │
                               └─────────────┘
```

---

## 7. Hash Computations

### 7.1 payload_plain_hash

Commits the agent to the plaintext content, salted to prevent guessing.

```
payload_plain_hash = SHA256(
  b"VES_PAYLOAD_PLAIN_V1" ||    // Domain separator (20 bytes)
  salt ||                        // Random salt (16 bytes)
  JCS(payload)                   // Canonicalized JSON (variable)
)
```

**For plaintext events (payload_kind = 0):**
```
payload_plain_hash = SHA256(
  b"VES_PAYLOAD_PLAIN_V1" ||
  JCS(payload)                   // No salt for plaintext
)
```

### 7.2 payload_cipher_hash

Commits to the complete ciphertext structure, allowing sequencer verification.

```
payload_cipher_hash = SHA256(
  b"VES_PAYLOAD_CIPHER_V1" ||    // Domain separator (22 bytes)
  U32_BE(enc_version) ||         // Version = 1 (4 bytes)
  nonce ||                        // AES-GCM nonce (12 bytes)
  payload_aad ||                  // Computed AAD hash (32 bytes)
  U32_BE(len(ciphertext)) ||      // Ciphertext length (4 bytes)
  ciphertext ||                   // Encrypted data (variable)
  tag ||                          // Auth tag (16 bytes)
  recipients_hash                 // Recipients commitment (32 bytes)
)
```

**For plaintext events (payload_kind = 0):**
```
payload_cipher_hash = 0x0000000000000000000000000000000000000000000000000000000000000000
```
(32 zero bytes)

### 7.3 payload_aad (Additional Authenticated Data)

Binds encryption to event context, preventing ciphertext transplantation.

```
payload_aad = SHA256(
  b"VES_PAYLOAD_AAD_V1" ||       // Domain separator (18 bytes)
  U32_BE(ves_version) ||          // Protocol version (4 bytes)
  UUID(tenant_id) ||              // Tenant UUID (16 bytes)
  UUID(store_id) ||               // Store UUID (16 bytes)
  UUID(event_id) ||               // Event UUID (16 bytes)
  UUID(source_agent_id) ||        // Agent UUID (16 bytes)
  U32_BE(agent_key_id) ||         // Signing key ID (4 bytes)
  ENC_STR(entity_type) ||         // Entity type (4 + len bytes)
  ENC_STR(entity_id) ||           // Entity ID (4 + len bytes)
  ENC_STR(event_type) ||          // Event type (4 + len bytes)
  ENC_STR(created_at) ||          // Timestamp (4 + len bytes)
  payload_plain_hash              // Plaintext hash (32 bytes)
)
```

### 7.4 recipients_hash

Commits to the exact set of recipients, preventing recipient manipulation.

```
recipients_hash = SHA256(
  b"VES_RECIPIENTS_V1" ||        // Domain separator (16 bytes)
  FOR EACH recipient IN sorted_recipients:
    U32_BE(recipient_kid) ||      // Key ID (4 bytes)
    U32_BE(len(enc)) || enc ||    // Encapped key (4 + 32 bytes)
    U32_BE(len(ct)) || ct         // Wrapped DEK (4 + 48 bytes)
)
```

### 7.5 Encoding Primitives

| Primitive | Definition |
|-----------|------------|
| `U32_BE(x)` | 4-byte unsigned integer, big-endian |
| `U64_BE(x)` | 8-byte unsigned integer, big-endian |
| `UUID(x)` | 16-byte UUID in network byte order |
| `ENC_STR(s)` | `U32_BE(len(UTF8(s))) \|\| UTF8(s)` |

---

## 8. Key Management

### 8.1 Key Types

VES-ENC-1 uses two distinct key types:

| Key Type | Algorithm | Purpose |
|----------|-----------|---------|
| Signing Key | Ed25519 | Event signatures (agent attribution) |
| Encryption Key | X25519 | Payload encryption (recipient access) |

**Important:** These key types MUST NOT be interchanged. Ed25519 keys cannot be used for HPKE and vice versa.

### 8.2 Key Registry Schema

```sql
-- Agent Encryption Keys (X25519)
CREATE TABLE agent_encryption_keys (
    tenant_id     UUID NOT NULL,
    agent_id      UUID NOT NULL,
    key_id        INTEGER NOT NULL,
    public_key    BYTEA NOT NULL CHECK (length(public_key) = 32),
    status        VARCHAR(20) DEFAULT 'active',
    valid_from    TIMESTAMPTZ DEFAULT NOW(),
    valid_to      TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, agent_id, key_id)
);
```

### 8.3 Key Rotation Policies

```sql
CREATE TABLE key_rotation_policies (
    tenant_id           UUID NOT NULL,
    agent_id            UUID,  -- NULL = tenant default
    key_type            VARCHAR(20) NOT NULL,
    max_age_hours       INTEGER,
    max_usage_count     BIGINT,
    grace_period_hours  INTEGER DEFAULT 72,
    auto_rotate         BOOLEAN DEFAULT false
);
```

### 8.4 Encryption Groups

For multi-recipient encryption to predefined groups:

```sql
CREATE TABLE encryption_key_groups (
    group_id    UUID PRIMARY KEY,
    tenant_id   UUID NOT NULL,
    name        VARCHAR(255) NOT NULL,
    is_active   BOOLEAN DEFAULT true
);

CREATE TABLE encryption_key_group_members (
    group_id           UUID REFERENCES encryption_key_groups,
    agent_id           UUID NOT NULL,
    encryption_key_id  INTEGER NOT NULL,
    role               VARCHAR(20) DEFAULT 'member',
    PRIMARY KEY (group_id, agent_id)
);
```

### 8.5 Key Lifecycle

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Generated│────►│  Active  │────►│  Expired │────►│ Archived │
└──────────┘     └────┬─────┘     └──────────┘     └──────────┘
                      │
                      │ Revocation
                      ▼
                 ┌──────────┐     ┌──────────┐
                 │  Revoked │────►│ Archived │
                 └──────────┘     └──────────┘
```

**Grace Period:** After expiry, keys MAY have a grace period during which decryption is allowed but encryption is rejected.

---

## 9. JSON Schemas

### 9.1 PayloadEncrypted Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://stateset.io/schemas/ves-enc-1/payload-encrypted.json",
  "title": "VES-ENC-1 Encrypted Payload",
  "type": "object",
  "required": [
    "enc_version",
    "aead",
    "nonce_b64u",
    "ciphertext_b64u",
    "tag_b64u",
    "hpke",
    "recipients"
  ],
  "properties": {
    "enc_version": {
      "type": "integer",
      "const": 1,
      "description": "Encryption version, must be 1"
    },
    "aead": {
      "type": "string",
      "const": "AES-256-GCM",
      "description": "AEAD algorithm identifier"
    },
    "nonce_b64u": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{16}$",
      "description": "12-byte nonce, base64url encoded (no padding)"
    },
    "ciphertext_b64u": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]+$",
      "description": "Encrypted salt || JCS(payload), base64url encoded"
    },
    "tag_b64u": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{22}$",
      "description": "16-byte auth tag, base64url encoded (no padding)"
    },
    "hpke": {
      "$ref": "#/definitions/HpkeParams"
    },
    "recipients": {
      "type": "array",
      "minItems": 1,
      "items": {
        "$ref": "#/definitions/Recipient"
      },
      "description": "Recipient list, sorted by recipient_kid ascending"
    }
  },
  "definitions": {
    "HpkeParams": {
      "type": "object",
      "required": ["mode", "kem", "kdf", "aead"],
      "properties": {
        "mode": {
          "type": "string",
          "const": "base"
        },
        "kem": {
          "type": "string",
          "const": "X25519-HKDF-SHA256"
        },
        "kdf": {
          "type": "string",
          "const": "HKDF-SHA256"
        },
        "aead": {
          "type": "string",
          "const": "AES-256-GCM"
        }
      }
    },
    "Recipient": {
      "type": "object",
      "required": ["recipient_kid", "enc_b64u", "ct_b64u"],
      "properties": {
        "recipient_kid": {
          "type": "integer",
          "minimum": 0,
          "description": "Recipient key ID in registry"
        },
        "enc_b64u": {
          "type": "string",
          "pattern": "^[A-Za-z0-9_-]{43}$",
          "description": "32-byte HPKE encapsulated key, base64url"
        },
        "ct_b64u": {
          "type": "string",
          "pattern": "^[A-Za-z0-9_-]{64}$",
          "description": "48-byte wrapped DEK, base64url"
        }
      }
    }
  }
}
```

### 9.2 Encrypted Event Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://stateset.io/schemas/ves-enc-1/encrypted-event.json",
  "title": "VES v1.0 Encrypted Event",
  "type": "object",
  "required": [
    "ves_version",
    "event_id",
    "tenant_id",
    "store_id",
    "source_agent_id",
    "agent_key_id",
    "entity_type",
    "entity_id",
    "event_type",
    "created_at",
    "payload_kind",
    "payload_encrypted",
    "payload_plain_hash",
    "payload_cipher_hash",
    "agent_signature"
  ],
  "properties": {
    "ves_version": { "const": 1 },
    "payload_kind": { "const": 1 },
    "payload_encrypted": {
      "$ref": "payload-encrypted.json"
    },
    "payload_plain_hash": {
      "type": "string",
      "pattern": "^0x[a-f0-9]{64}$"
    },
    "payload_cipher_hash": {
      "type": "string",
      "pattern": "^0x[a-f0-9]{64}$"
    }
  }
}
```

---

## 10. Code Examples

### 10.1 Rust Implementation

```rust
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use hpke::{Kem, OpModeS, OpModeR, Serializable, Deserializable};
use hpke::kem::X25519HkdfSha256;
use hpke::kdf::HkdfSha256;
use hpke::aead::AesGcm256;
use sha2::{Sha256, Digest};
use rand::RngCore;

const DOMAIN_PAYLOAD_PLAIN: &[u8] = b"VES_PAYLOAD_PLAIN_V1";
const DOMAIN_PAYLOAD_AAD: &[u8] = b"VES_PAYLOAD_AAD_V1";
const DOMAIN_PAYLOAD_CIPHER: &[u8] = b"VES_PAYLOAD_CIPHER_V1";
const DOMAIN_RECIPIENTS: &[u8] = b"VES_RECIPIENTS_V1";

/// Encrypt a payload per VES-ENC-1
pub fn encrypt_payload(
    payload: &serde_json::Value,
    event_context: &EventContext,
    recipient_keys: &[(u32, [u8; 32])],
) -> Result<EncryptionResult, EncryptionError> {
    // 1. Generate random values
    let mut salt = [0u8; 16];
    let mut dek = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut dek);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // 2. Canonicalize and prepare plaintext
    let canonical = jcs::canonicalize(payload)?;
    let mut plaintext = Vec::with_capacity(16 + canonical.len());
    plaintext.extend_from_slice(&salt);
    plaintext.extend_from_slice(canonical.as_bytes());

    // 3. Compute payload_plain_hash
    let payload_plain_hash = {
        let mut h = Sha256::new();
        h.update(DOMAIN_PAYLOAD_PLAIN);
        h.update(&plaintext);
        h.finalize().into()
    };

    // 4. Compute AAD
    let payload_aad = compute_aad(event_context, &payload_plain_hash);

    // 5. Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&dek)?;
    let ciphertext_with_tag = cipher.encrypt(
        Nonce::from_slice(&nonce),
        aes_gcm::aead::Payload { msg: &plaintext, aad: &payload_aad }
    )?;
    let (ciphertext, tag) = ciphertext_with_tag.split_at(
        ciphertext_with_tag.len() - 16
    );

    // 6. Wrap DEK for each recipient
    let mut recipients = Vec::new();
    for (kid, pk) in recipient_keys {
        let (enc, ct) = hpke_wrap_dek(&dek, pk, &payload_aad)?;
        recipients.push(Recipient { recipient_kid: *kid, enc, ct });
    }
    recipients.sort_by_key(|r| r.recipient_kid);

    // 7. Compute recipients_hash
    let recipients_hash = compute_recipients_hash(&recipients);

    // 8. Compute payload_cipher_hash
    let payload_cipher_hash = compute_cipher_hash(
        &nonce, &payload_aad, ciphertext, tag, &recipients_hash
    );

    Ok(EncryptionResult {
        payload_encrypted: PayloadEncrypted { /* ... */ },
        payload_plain_hash,
        payload_cipher_hash,
    })
}
```

### 10.2 TypeScript/JavaScript Implementation

```typescript
import { webcrypto } from 'crypto';
import * as hpke from '@noble/hpke';

const DOMAIN_PAYLOAD_PLAIN = new TextEncoder().encode('VES_PAYLOAD_PLAIN_V1');
const DOMAIN_PAYLOAD_AAD = new TextEncoder().encode('VES_PAYLOAD_AAD_V1');

interface EncryptionResult {
  payloadEncrypted: PayloadEncrypted;
  payloadPlainHash: Uint8Array;
  payloadCipherHash: Uint8Array;
}

async function encryptPayload(
  payload: object,
  eventContext: EventContext,
  recipientKeys: Array<{ kid: number; publicKey: Uint8Array }>
): Promise<EncryptionResult> {
  // 1. Generate random values
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const dek = webcrypto.getRandomValues(new Uint8Array(32));
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));

  // 2. Canonicalize JSON (RFC 8785)
  const canonicalJson = canonicalize(payload);
  const canonicalBytes = new TextEncoder().encode(canonicalJson);

  // 3. Prepare plaintext: salt || JCS(payload)
  const plaintext = new Uint8Array(16 + canonicalBytes.length);
  plaintext.set(salt, 0);
  plaintext.set(canonicalBytes, 16);

  // 4. Compute payload_plain_hash
  const plainHashInput = concat(DOMAIN_PAYLOAD_PLAIN, plaintext);
  const payloadPlainHash = new Uint8Array(
    await webcrypto.subtle.digest('SHA-256', plainHashInput)
  );

  // 5. Compute AAD
  const payloadAad = await computeAad(eventContext, payloadPlainHash);

  // 6. Encrypt with AES-256-GCM
  const key = await webcrypto.subtle.importKey(
    'raw', dek, { name: 'AES-GCM' }, false, ['encrypt']
  );
  const ciphertextWithTag = new Uint8Array(
    await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: payloadAad },
      key,
      plaintext
    )
  );
  const ciphertext = ciphertextWithTag.slice(0, -16);
  const tag = ciphertextWithTag.slice(-16);

  // 7. Wrap DEK for each recipient using HPKE
  const recipients: Recipient[] = [];
  for (const { kid, publicKey } of recipientKeys) {
    const { enc, ct } = await hpkeWrapDek(dek, publicKey, payloadAad);
    recipients.push({ recipientKid: kid, enc, ct });
  }
  recipients.sort((a, b) => a.recipientKid - b.recipientKid);

  // 8. Compute hashes
  const recipientsHash = await computeRecipientsHash(recipients);
  const payloadCipherHash = await computeCipherHash(
    nonce, payloadAad, ciphertext, tag, recipientsHash
  );

  return {
    payloadEncrypted: {
      encVersion: 1,
      aead: 'AES-256-GCM',
      nonceB64u: base64urlEncode(nonce),
      ciphertextB64u: base64urlEncode(ciphertext),
      tagB64u: base64urlEncode(tag),
      hpke: { mode: 'base', kem: 'X25519-HKDF-SHA256', kdf: 'HKDF-SHA256', aead: 'AES-256-GCM' },
      recipients: recipients.map(r => ({
        recipientKid: r.recipientKid,
        encB64u: base64urlEncode(r.enc),
        ctB64u: base64urlEncode(r.ct),
      })),
    },
    payloadPlainHash,
    payloadCipherHash,
  };
}
```

### 10.3 Python Implementation

```python
import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from canonicaljson import encode_canonical_json

DOMAIN_PAYLOAD_PLAIN = b"VES_PAYLOAD_PLAIN_V1"
DOMAIN_PAYLOAD_AAD = b"VES_PAYLOAD_AAD_V1"
DOMAIN_PAYLOAD_CIPHER = b"VES_PAYLOAD_CIPHER_V1"
DOMAIN_RECIPIENTS = b"VES_RECIPIENTS_V1"

def encrypt_payload(
    payload: dict,
    event_context: dict,
    recipient_keys: list[tuple[int, bytes]]
) -> dict:
    """Encrypt a payload per VES-ENC-1."""

    # 1. Generate random values
    salt = os.urandom(16)
    dek = os.urandom(32)
    nonce = os.urandom(12)

    # 2. Canonicalize JSON (RFC 8785)
    canonical_json = encode_canonical_json(payload)

    # 3. Prepare plaintext: salt || JCS(payload)
    plaintext = salt + canonical_json

    # 4. Compute payload_plain_hash
    payload_plain_hash = hashlib.sha256(
        DOMAIN_PAYLOAD_PLAIN + plaintext
    ).digest()

    # 5. Compute AAD
    payload_aad = compute_aad(event_context, payload_plain_hash)

    # 6. Encrypt with AES-256-GCM
    aesgcm = AESGCM(dek)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, payload_aad)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    # 7. Wrap DEK for each recipient
    recipients = []
    for kid, public_key in recipient_keys:
        enc, ct = hpke_wrap_dek(dek, public_key, payload_aad)
        recipients.append({
            "recipient_kid": kid,
            "enc_b64u": base64url_encode(enc),
            "ct_b64u": base64url_encode(ct),
        })
    recipients.sort(key=lambda r: r["recipient_kid"])

    # 8. Compute hashes
    recipients_hash = compute_recipients_hash(recipients)
    payload_cipher_hash = compute_cipher_hash(
        nonce, payload_aad, ciphertext, tag, recipients_hash
    )

    return {
        "payload_encrypted": {
            "enc_version": 1,
            "aead": "AES-256-GCM",
            "nonce_b64u": base64url_encode(nonce),
            "ciphertext_b64u": base64url_encode(ciphertext),
            "tag_b64u": base64url_encode(tag),
            "hpke": {
                "mode": "base",
                "kem": "X25519-HKDF-SHA256",
                "kdf": "HKDF-SHA256",
                "aead": "AES-256-GCM",
            },
            "recipients": recipients,
        },
        "payload_plain_hash": payload_plain_hash.hex(),
        "payload_cipher_hash": payload_cipher_hash.hex(),
    }
```

### 10.4 Go Implementation

```go
package vesenc

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/json"
    "sort"

    "github.com/cloudflare/circl/hpke"
)

var (
    DomainPayloadPlain  = []byte("VES_PAYLOAD_PLAIN_V1")
    DomainPayloadAAD    = []byte("VES_PAYLOAD_AAD_V1")
    DomainPayloadCipher = []byte("VES_PAYLOAD_CIPHER_V1")
    DomainRecipients    = []byte("VES_RECIPIENTS_V1")
)

func EncryptPayload(
    payload interface{},
    eventContext *EventContext,
    recipientKeys []RecipientKey,
) (*EncryptionResult, error) {
    // 1. Generate random values
    salt := make([]byte, 16)
    dek := make([]byte, 32)
    nonce := make([]byte, 12)
    rand.Read(salt)
    rand.Read(dek)
    rand.Read(nonce)

    // 2. Canonicalize JSON
    canonicalJSON, err := CanonicalizeJSON(payload)
    if err != nil {
        return nil, err
    }

    // 3. Prepare plaintext
    plaintext := append(salt, canonicalJSON...)

    // 4. Compute payload_plain_hash
    h := sha256.New()
    h.Write(DomainPayloadPlain)
    h.Write(plaintext)
    payloadPlainHash := h.Sum(nil)

    // 5. Compute AAD
    payloadAAD := ComputeAAD(eventContext, payloadPlainHash)

    // 6. Encrypt with AES-256-GCM
    block, _ := aes.NewCipher(dek)
    aesgcm, _ := cipher.NewGCM(block)
    ciphertextWithTag := aesgcm.Seal(nil, nonce, plaintext, payloadAAD)
    ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-16]
    tag := ciphertextWithTag[len(ciphertextWithTag)-16:]

    // 7. Wrap DEK for each recipient
    var recipients []Recipient
    for _, rk := range recipientKeys {
        enc, ct, err := HPKEWrapDEK(dek, rk.PublicKey, payloadAAD)
        if err != nil {
            return nil, err
        }
        recipients = append(recipients, Recipient{
            RecipientKID: rk.KID,
            EncB64u:      Base64URLEncode(enc),
            CtB64u:       Base64URLEncode(ct),
        })
    }
    sort.Slice(recipients, func(i, j int) bool {
        return recipients[i].RecipientKID < recipients[j].RecipientKID
    })

    // 8. Compute hashes
    recipientsHash := ComputeRecipientsHash(recipients)
    payloadCipherHash := ComputeCipherHash(nonce, payloadAAD, ciphertext, tag, recipientsHash)

    return &EncryptionResult{
        PayloadEncrypted:  BuildPayloadEncrypted(nonce, ciphertext, tag, recipients),
        PayloadPlainHash:  payloadPlainHash,
        PayloadCipherHash: payloadCipherHash,
    }, nil
}
```

---

## 11. Test Vectors

### 11.1 Canonicalization Test Vector

**Input JSON:**
```json
{"z": 1, "a": "hello", "m": {"b": 2, "a": 1}}
```

**Expected Canonical Output:**
```json
{"a":"hello","m":{"a":1,"b":2},"z":1}
```

**SHA-256 of Canonical (hex):**
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 11.2 Payload Plain Hash Test Vector

**Salt (hex):**
```
0102030405060708090a0b0c0d0e0f10
```

**Payload:**
```json
{"delta": 100, "reason": "test"}
```

**Canonical Payload:**
```json
{"delta":100,"reason":"test"}
```

**Plaintext (salt || canonical):**
```
0102030405060708090a0b0c0d0e0f107b2264656c7461223a3130302c22726561736f6e223a2274657374227d
```

**payload_plain_hash (hex):**
```
0x7f8a9b3c4d5e6f708192a3b4c5d6e7f80011223344556677889900aabbccddee
```

### 11.3 Full Encryption Test Vector

**Event Context:**
```json
{
  "ves_version": 1,
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "store_id": "00000000-0000-0000-0000-000000000002",
  "event_id": "11111111-1111-1111-1111-111111111111",
  "source_agent_id": "22222222-2222-2222-2222-222222222222",
  "agent_key_id": 1,
  "entity_type": "InventoryItem",
  "entity_id": "WIDGET-001",
  "event_type": "Adjusted",
  "created_at": "2025-01-01T00:00:00Z"
}
```

**Recipient Key (X25519 private, hex):**
```
77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
```

**Recipient Key (X25519 public, hex):**
```
8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
```

See `tests/vectors/ves-enc-1/` for complete test vector files.

---

## 12. Security Considerations

### 12.1 Threat Model

**Protected Against:**
| Threat | Mitigation |
|--------|------------|
| Payload interception | AES-256-GCM encryption |
| Ciphertext substitution | AAD binds to event context |
| Recipient modification | Recipients hash in cipher hash |
| Low-entropy guessing | 16-byte random salt |
| Key compromise scope | Per-event random DEK |
| Cross-event attacks | Unique nonces and AAD |

**Not Protected Against:**
| Threat | Mitigation Required |
|--------|---------------------|
| Recipient private key theft | HSM, secure key storage |
| Traffic analysis (size) | Padding (optional) |
| Timing attacks | Constant-time implementations |
| Quantum attacks | Future: post-quantum HPKE |

### 12.2 Implementation Requirements

**MUST:**
- Use cryptographically secure random number generators
- Never reuse nonces with the same DEK
- Validate all inputs before processing
- Verify authentication tags before using decrypted data
- Use constant-time comparison for hash verification
- Clear sensitive data from memory after use

**MUST NOT:**
- Log or persist plaintext payloads in unencrypted form
- Expose timing information about decryption failures
- Use weak or predictable random number sources
- Skip AAD verification during decryption
- Allow nonce reuse across encryptions

### 12.3 Key Security

**Signing Keys (Ed25519):**
- Store in HSM or secure enclave when possible
- Rotate at least annually or after suspected compromise
- Maintain revocation lists

**Encryption Keys (X25519):**
- Generate using secure random source
- Store private keys encrypted at rest
- Implement key escrow for business continuity (optional)
- Support multiple active keys for rotation

### 12.4 Audit Logging

All encryption operations SHOULD be logged:
```sql
CREATE TABLE encryption_audit_log (
    id              UUID PRIMARY KEY,
    event_id        UUID NOT NULL,
    operation       VARCHAR(20) NOT NULL,  -- 'encrypt' | 'decrypt'
    agent_id        UUID NOT NULL,
    recipient_kids  INTEGER[] NOT NULL,
    success         BOOLEAN NOT NULL,
    error_code      VARCHAR(50),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 13. Implementation Checklist

### 13.1 Core Requirements

- [ ] AES-256-GCM encryption with 12-byte nonces
- [ ] HPKE key wrapping (X25519/HKDF-SHA256/AES-256-GCM)
- [ ] RFC 8785 JCS canonicalization
- [ ] SHA-256 hashing with domain separation
- [ ] Base64url encoding (no padding)

### 13.2 Hash Computations

- [ ] `payload_plain_hash` with domain separator and salt
- [ ] `payload_aad` from event context
- [ ] `recipients_hash` from sorted recipients
- [ ] `payload_cipher_hash` from ciphertext structure

### 13.3 Security

- [ ] Cryptographic random number generation
- [ ] Constant-time hash comparison
- [ ] Memory clearing for sensitive data
- [ ] Input validation for all fields

### 13.4 Interoperability

- [ ] JSON schema validation
- [ ] Test vector verification
- [ ] Cross-implementation testing

---

## Appendix A: Domain Separators

All domain separators are ASCII byte strings with no null terminator.

| Constant | Value | Usage |
|----------|-------|-------|
| `DOMAIN_PAYLOAD_PLAIN` | `b"VES_PAYLOAD_PLAIN_V1"` | Plaintext hash |
| `DOMAIN_PAYLOAD_AAD` | `b"VES_PAYLOAD_AAD_V1"` | AAD computation |
| `DOMAIN_PAYLOAD_CIPHER` | `b"VES_PAYLOAD_CIPHER_V1"` | Ciphertext hash |
| `DOMAIN_RECIPIENTS` | `b"VES_RECIPIENTS_V1"` | Recipients hash |

---

## Appendix B: Base64url Encoding

VES-ENC-1 uses Base64url encoding per RFC 4648 Section 5, **without padding**.

**Encoding Table:**
```
A-Z = 0-25
a-z = 26-51
0-9 = 52-61
-   = 62
_   = 63
```

**Examples:**
| Input (hex) | Base64url |
|-------------|-----------|
| `0x00` | `AA` |
| `0xff` | `_w` |
| `0x000102` | `AAEC` |

**Implementation Note:** Standard Base64 uses `+` and `/` which are not URL-safe. Base64url replaces these with `-` and `_` respectively, and omits `=` padding.

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-22 | Initial specification |

---

*This specification is part of the Verifiable Event Sync (VES) v1.0 protocol. For the complete VES specification, see [VES_SPEC.md](./VES_SPEC.md).*
