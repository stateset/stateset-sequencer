# VES-SIG-1: Agent Signatures Specification

**Version:** 1.0
**Status:** Stable
**Last Updated:** 2025-12-22
**Parent Specification:** VES v1.0 Sections 4, 6, 8, 9

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Principles](#2-design-principles)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Data Structures](#4-data-structures)
5. [Event Signing Hash](#5-event-signing-hash)
6. [Signature Generation](#6-signature-generation)
7. [Signature Verification](#7-signature-verification)
8. [Agent Key Registry](#8-agent-key-registry)
9. [Key Lifecycle Management](#9-key-lifecycle-management)
10. [JSON Schemas](#10-json-schemas)
11. [Code Examples](#11-code-examples)
12. [Test Vectors](#12-test-vectors)
13. [Security Considerations](#13-security-considerations)
14. [Implementation Checklist](#14-implementation-checklist)
15. [Appendix A: Domain Separators](#appendix-a-domain-separators)
16. [Appendix B: Encoding Primitives](#appendix-b-encoding-primitives)

---

## 1. Overview

VES-SIG-1 defines the agent signature scheme for the Verifiable Event Sync (VES) protocol. Every event in the VES system is cryptographically signed by the originating agent, providing:

- **Non-repudiation**: Agents cannot deny having created events
- **Integrity**: Any modification to signed data is detectable
- **Attribution**: Events are cryptographically bound to specific agents
- **Verifiability**: Third parties can independently verify signatures

### 1.1 Key Features

| Feature | Description |
|---------|-------------|
| **Deterministic Signatures** | Ed25519 produces identical signatures for identical inputs |
| **Key Rotation** | Agents can rotate keys while maintaining signature chain |
| **Dual-Hash Binding** | Signatures cover both plaintext and ciphertext hashes |
| **Merkle Integration** | Signatures are included in Merkle leaf computation |
| **Offline Signing** | Agents can sign events without network connectivity |

### 1.2 Algorithm Summary

| Component | Algorithm | Size |
|-----------|-----------|------|
| Signature Scheme | Ed25519 (EdDSA over Curve25519) | 64 bytes |
| Public Key | Ed25519 | 32 bytes |
| Private Key | Ed25519 | 32 bytes |
| Hash Function | SHA-256 | 32 bytes |

---

## 2. Design Principles

### 2.1 Cryptographic Non-Repudiation

Every VES event contains an agent signature that cryptographically binds:
- The agent's identity (`source_agent_id`)
- The specific key used (`agent_key_id`)
- All event metadata and payload hashes

This creates an unforgeable audit trail where agents cannot deny creating events.

### 2.2 Deterministic Hash-then-Sign

VES-SIG-1 uses a hash-then-sign approach:

```
event_signing_hash = SHA256(structured_preimage)
agent_signature = Ed25519.Sign(private_key, event_signing_hash)
```

Benefits:
- Fixed-size input to signature algorithm (32 bytes)
- Deterministic across implementations
- Enables offline signature verification

### 2.3 Domain Separation

All hash computations include unique domain prefixes to prevent cross-protocol attacks:

```
eventsig_preimage = b"VES_EVENTSIG_V1" || ...
```

This ensures hashes computed for different purposes cannot collide.

### 2.4 Dual-Hash Commitment

Agents sign over both payload hashes:
- `payload_plain_hash`: Commits to plaintext content
- `payload_cipher_hash`: Commits to encrypted structure (or zeros for plaintext)

This allows:
- Recipients to verify decrypted content matches agent intent
- Sequencers to verify encrypted structure without decryption

---

## 3. Cryptographic Primitives

### 3.1 Ed25519 Signature Scheme

**Standard:** RFC 8032 (Edwards-Curve Digital Signature Algorithm)

| Property | Value |
|----------|-------|
| Curve | Curve25519 (Edwards form: Ed25519) |
| Security Level | ~128-bit |
| Private Key | 32 bytes (256 bits) |
| Public Key | 32 bytes (256 bits) |
| Signature | 64 bytes (512 bits) |
| Hash Function | SHA-512 (internal) |

**Properties:**
- **Deterministic**: Same key + message always produces same signature
- **Fast**: Single-pass algorithm, no random values needed
- **Compact**: Small keys and signatures
- **Secure**: No known practical attacks

### 3.2 SHA-256 Hashing

**Standard:** FIPS 180-4

| Property | Value |
|----------|-------|
| Output Size | 256 bits (32 bytes) |
| Block Size | 512 bits |
| Security | 128-bit collision resistance |

**Usage in VES-SIG-1:**
- Compute `event_signing_hash` from structured preimage
- Compute `payload_plain_hash` from canonical JSON
- All hashes include domain separation prefixes

### 3.3 RFC 8785 JCS (Canonicalization)

**Purpose:** Ensure deterministic JSON serialization for payload hashing.

**Rules:**
- Object keys sorted lexicographically by UTF-16 code units
- Numbers normalized (no trailing zeros, no leading zeros)
- Strings with minimal escaping
- No whitespace between tokens
- UTF-8 encoding

---

## 4. Data Structures

### 4.1 AgentSigningKey

The private key used for signing events:

```rust
pub struct AgentSigningKey {
    signing_key: Ed25519SigningKey,  // 32 bytes
}

impl AgentSigningKey {
    fn generate() -> Self;                           // Random key generation
    fn from_bytes(bytes: &[u8; 32]) -> Result<Self>; // From raw bytes
    fn to_bytes(&self) -> [u8; 32];                  // Export raw bytes
    fn public_key(&self) -> AgentVerifyingKey;       // Derive public key
    fn sign(&self, hash: &[u8; 32]) -> [u8; 64];     // Sign hash
    fn sign_event(&self, params: &EventSigningParams) -> [u8; 64];
}
```

### 4.2 AgentVerifyingKey

The public key used for signature verification:

```rust
pub struct AgentVerifyingKey {
    verifying_key: Ed25519VerifyingKey,  // 32 bytes
}

impl AgentVerifyingKey {
    fn from_bytes(bytes: &[u8; 32]) -> Result<Self>;
    fn to_bytes(&self) -> [u8; 32];
    fn verify(&self, hash: &[u8; 32], signature: &[u8; 64]) -> Result<()>;
    fn verify_event(&self, params: &EventSigningParams, signature: &[u8; 64]) -> Result<()>;
}
```

### 4.3 EventSigningParams

Parameters for computing the event signing hash:

```rust
pub struct EventSigningParams<'a> {
    pub ves_version: u32,                    // Protocol version (1)
    pub tenant_id: &'a Uuid,                 // Tenant identifier
    pub store_id: &'a Uuid,                  // Store identifier
    pub event_id: &'a Uuid,                  // Unique event ID
    pub source_agent_id: &'a Uuid,           // Agent creating event
    pub agent_key_id: u32,                   // Which key was used
    pub entity_type: &'a str,                // Entity type string
    pub entity_id: &'a str,                  // Entity identifier
    pub event_type: &'a str,                 // Event type string
    pub created_at: &'a str,                 // RFC 3339 timestamp
    pub payload_kind: u32,                   // 0=plaintext, 1=encrypted
    pub payload_plain_hash: &'a [u8; 32],    // Plaintext hash
    pub payload_cipher_hash: &'a [u8; 32],   // Ciphertext hash (or zeros)
}
```

### 4.4 Type Aliases

```rust
/// Ed25519 signature (64 bytes)
pub type Signature64 = [u8; 64];

/// Ed25519 public key (32 bytes)
pub type PublicKey32 = [u8; 32];

/// Ed25519 secret key (32 bytes)
pub type SecretKey32 = [u8; 32];

/// SHA-256 hash (32 bytes)
pub type Hash256 = [u8; 32];
```

---

## 5. Event Signing Hash

### 5.1 Preimage Structure

The event signing hash is computed from a structured binary preimage:

```
eventsig_preimage =
  b"VES_EVENTSIG_V1"        ||    // Domain separator (15 bytes)
  U32_BE(ves_version)       ||    // Version (4 bytes)
  UUID(tenant_id)           ||    // Tenant ID (16 bytes)
  UUID(store_id)            ||    // Store ID (16 bytes)
  UUID(event_id)            ||    // Event ID (16 bytes)
  UUID(source_agent_id)     ||    // Agent ID (16 bytes)
  U32_BE(agent_key_id)      ||    // Key ID (4 bytes)
  ENC_STR(entity_type)      ||    // Entity type (4 + len bytes)
  ENC_STR(entity_id)        ||    // Entity ID (4 + len bytes)
  ENC_STR(event_type)       ||    // Event type (4 + len bytes)
  ENC_STR(created_at)       ||    // Timestamp (4 + len bytes)
  U32_BE(payload_kind)      ||    // Payload kind (4 bytes)
  payload_plain_hash        ||    // Plaintext hash (32 bytes)
  payload_cipher_hash             // Ciphertext hash (32 bytes)
```

### 5.2 Hash Computation

```
event_signing_hash = SHA256(eventsig_preimage)
```

### 5.3 Field Details

| Field | Encoding | Size | Description |
|-------|----------|------|-------------|
| Domain | ASCII bytes | 15 | `VES_EVENTSIG_V1` |
| ves_version | U32_BE | 4 | Protocol version (must be 1) |
| tenant_id | UUID bytes | 16 | Network byte order |
| store_id | UUID bytes | 16 | Network byte order |
| event_id | UUID bytes | 16 | Network byte order |
| source_agent_id | UUID bytes | 16 | Network byte order |
| agent_key_id | U32_BE | 4 | Key identifier for rotation |
| entity_type | ENC_STR | 4+len | Length-prefixed UTF-8 |
| entity_id | ENC_STR | 4+len | Length-prefixed UTF-8 |
| event_type | ENC_STR | 4+len | Length-prefixed UTF-8 |
| created_at | ENC_STR | 4+len | RFC 3339 timestamp |
| payload_kind | U32_BE | 4 | 0=plaintext, 1=encrypted |
| payload_plain_hash | bytes | 32 | SHA-256 hash |
| payload_cipher_hash | bytes | 32 | SHA-256 hash or zeros |

### 5.4 Minimum Preimage Size

```
Fixed: 15 + 4 + 16 + 16 + 16 + 16 + 4 + 4 + 4 + 4 + 4 + 4 + 32 + 32 = 167 bytes
Variable: entity_type + entity_id + event_type + created_at
Total: 167 + (4 * 4) + string_lengths = 183+ bytes
```

### 5.5 Preimage Flowchart

```
┌─────────────────────────────────────────────────────────────┐
│                    Event Signing Preimage                    │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ b"VES_EVENTSIG_V1"                        [15 bytes]    │ │
│ └─────────────────────────────────────────────────────────┘ │
│ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────────┐ │
│ │ves_version│ │ tenant_id │ │ store_id  │ │   event_id    │ │
│ │  [4 B]    │ │  [16 B]   │ │  [16 B]   │ │   [16 B]      │ │
│ └───────────┘ └───────────┘ └───────────┘ └───────────────┘ │
│ ┌───────────────────┐ ┌───────────────────────────────────┐ │
│ │  source_agent_id  │ │        agent_key_id               │ │
│ │      [16 B]       │ │           [4 B]                   │ │
│ └───────────────────┘ └───────────────────────────────────┘ │
│ ┌───────────────────────────────────────────────────────┐   │
│ │ ENC_STR(entity_type) || ENC_STR(entity_id)           │   │
│ │ ENC_STR(event_type)  || ENC_STR(created_at)          │   │
│ └───────────────────────────────────────────────────────┘   │
│ ┌───────────┐ ┌─────────────────┐ ┌─────────────────────┐   │
│ │payload_kind│ │payload_plain_hash│ │payload_cipher_hash│   │
│ │   [4 B]   │ │     [32 B]      │ │      [32 B]        │   │
│ └───────────┘ └─────────────────┘ └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │    SHA-256      │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │event_signing_hash│
                    │    (32 bytes)   │
                    └─────────────────┘
```

---

## 6. Signature Generation

### 6.1 Algorithm

```
SIGN_EVENT(signing_key, event_params):

1. COMPUTE PAYLOAD HASHES
   IF payload_kind == 0 (plaintext):
     payload_plain_hash ← SHA256(b"VES_PAYLOAD_PLAIN_V1" || JCS(payload))
     payload_cipher_hash ← [0; 32]  // 32 zero bytes
   ELSE (encrypted):
     // payload_plain_hash and payload_cipher_hash from encryption
     // (computed during VES-ENC-1 encryption)

2. BUILD EVENT SIGNING PARAMS
   params ← EventSigningParams {
     ves_version: 1,
     tenant_id, store_id, event_id,
     source_agent_id, agent_key_id,
     entity_type, entity_id, event_type,
     created_at,
     payload_kind,
     payload_plain_hash,
     payload_cipher_hash
   }

3. COMPUTE EVENT SIGNING HASH
   event_signing_hash ← compute_event_signing_hash(params)

4. SIGN
   agent_signature ← Ed25519.Sign(signing_key, event_signing_hash)

5. RETURN agent_signature (64 bytes)
```

### 6.2 Signature Flow

```
┌───────────────┐     ┌───────────────┐
│    Payload    │     │ Event Context │
│    (JSON)     │     │  (metadata)   │
└───────┬───────┘     └───────┬───────┘
        │                     │
        ▼                     │
┌───────────────┐             │
│     JCS       │             │
│ Canonicalize  │             │
└───────┬───────┘             │
        │                     │
        ▼                     │
┌───────────────┐             │
│payload_plain_ │             │
│     hash      │             │
└───────┬───────┘             │
        │                     │
        └─────────┬───────────┘
                  │
                  ▼
        ┌─────────────────┐
        │ EventSigningParams│
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Build Preimage  │
        │ (structured)    │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │    SHA-256      │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │event_signing_hash│
        │   (32 bytes)    │
        └────────┬────────┘
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
┌───────────────┐  ┌─────────────┐
│  Private Key  │  │  Ed25519    │
│  (32 bytes)   │  │    Sign     │
└───────────────┘  └──────┬──────┘
                          │
                          ▼
                   ┌─────────────┐
                   │agent_signature│
                   │  (64 bytes) │
                   └─────────────┘
```

---

## 7. Signature Verification

### 7.1 Algorithm

```
VERIFY_EVENT(public_key, event, agent_signature):

1. RECONSTRUCT EVENT SIGNING PARAMS
   params ← EventSigningParams {
     ves_version: event.ves_version,
     tenant_id: event.tenant_id,
     store_id: event.store_id,
     event_id: event.event_id,
     source_agent_id: event.source_agent_id,
     agent_key_id: event.agent_key_id,
     entity_type: event.entity_type,
     entity_id: event.entity_id,
     event_type: event.event_type,
     created_at: event.created_at,
     payload_kind: event.payload_kind,
     payload_plain_hash: event.payload_plain_hash,
     payload_cipher_hash: event.payload_cipher_hash
   }

2. RECOMPUTE EVENT SIGNING HASH
   computed_hash ← compute_event_signing_hash(params)

3. VERIFY SIGNATURE
   valid ← Ed25519.Verify(public_key, computed_hash, agent_signature)

4. RETURN valid
```

### 7.2 Sequencer Validation

The sequencer MUST perform these validations on every incoming event:

```
VALIDATE_EVENT(event):

1. VALIDATE STRUCTURE
   - All required fields present
   - Field types correct
   - UUIDs valid format
   - created_at is valid RFC 3339

2. LOOKUP AGENT KEY
   lookup ← AgentKeyLookup {
     tenant_id: event.tenant_id,
     agent_id: event.source_agent_id,
     key_id: event.agent_key_id
   }
   key_entry ← registry.get_valid_key_at(lookup, NOW())
   IF key_entry IS ERROR:
     REJECT "Unknown or invalid agent key"

3. VERIFY PAYLOAD HASH
   IF event.payload_kind == 0:
     computed_plain_hash ← payload_plain_hash(event.payload)
     IF computed_plain_hash != event.payload_plain_hash:
       REJECT "Payload hash mismatch"
     IF event.payload_cipher_hash != [0; 32]:
       REJECT "Plaintext event must have zero cipher hash"
   ELSE:
     // Verify cipher hash matches encrypted structure
     // (cannot verify plain hash without decryption)

4. VERIFY SIGNATURE
   IF NOT verify_event(key_entry.public_key, event, event.agent_signature):
     REJECT "Invalid signature"

5. CHECK IDEMPOTENCY
   IF exists(event.event_id) WITH SAME CONTENT:
     RETURN existing_sequence_number
   IF exists(event.event_id) WITH DIFFERENT CONTENT:
     REJECT "Duplicate event_id with different content"

6. ACCEPT EVENT
   RETURN assigned_sequence_number
```

---

## 8. Agent Key Registry

### 8.1 Registry Interface

```rust
#[async_trait]
pub trait AgentKeyRegistry: Send + Sync {
    /// Get key entry by lookup
    async fn get_key(&self, lookup: &AgentKeyLookup)
        -> Result<AgentKeyEntry, AgentKeyError>;

    /// Get key valid at specific time
    async fn get_valid_key_at(&self, lookup: &AgentKeyLookup, at: DateTime<Utc>)
        -> Result<AgentKeyEntry, AgentKeyError>;

    /// Register a new key
    async fn register_key(&self, lookup: &AgentKeyLookup, entry: AgentKeyEntry)
        -> Result<(), AgentKeyError>;

    /// Revoke a key
    async fn revoke_key(&self, lookup: &AgentKeyLookup)
        -> Result<(), AgentKeyError>;

    /// List all keys for an agent
    async fn list_agent_keys(&self, tenant_id: &Uuid, agent_id: &Uuid)
        -> Result<Vec<(u32, AgentKeyEntry)>, AgentKeyError>;
}
```

### 8.2 Key Lookup

Keys are identified by a composite lookup:

```rust
pub struct AgentKeyLookup {
    pub tenant_id: Uuid,      // Tenant scope
    pub agent_id: Uuid,       // Agent identifier
    pub key_id: u32,          // Key version number
}
```

### 8.3 Key Entry

```rust
pub struct AgentKeyEntry {
    pub public_key: [u8; 32],                  // Ed25519 public key
    pub status: KeyStatus,                      // active, revoked, expired
    pub valid_from: Option<DateTime<Utc>>,     // Start of validity
    pub valid_to: Option<DateTime<Utc>>,       // End of validity
    pub revoked_at: Option<DateTime<Utc>>,     // Revocation timestamp
    pub metadata: Option<String>,               // Optional metadata
    pub created_at: DateTime<Utc>,             // When registered
}
```

### 8.4 Key Status

```rust
pub enum KeyStatus {
    Active,       // Key can be used for signing and verification
    Revoked,      // Key has been explicitly revoked
    Expired,      // Key has passed valid_to
    NotYetValid,  // Key hasn't reached valid_from
}
```

### 8.5 Database Schema

```sql
CREATE TABLE agent_signing_keys (
    tenant_id     UUID NOT NULL,
    agent_id      UUID NOT NULL,
    key_id        INTEGER NOT NULL,
    public_key    BYTEA NOT NULL CHECK (length(public_key) = 32),
    status        VARCHAR(16) NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'revoked', 'expired')),
    valid_from    TIMESTAMPTZ,
    valid_to      TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    grace_until   TIMESTAMPTZ,
    rotation_reason VARCHAR(50),
    metadata      TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, agent_id, key_id),

    CONSTRAINT chk_revoked_consistent CHECK (
        (revoked_at IS NULL AND status != 'revoked') OR
        (revoked_at IS NOT NULL AND status = 'revoked')
    ),
    CONSTRAINT chk_validity_window CHECK (
        valid_from IS NULL OR valid_to IS NULL OR valid_from <= valid_to
    ),
    CONSTRAINT chk_grace_after_expiry CHECK (
        grace_until IS NULL OR expires_at IS NULL OR grace_until >= expires_at
    )
);

-- Index for active key lookups
CREATE INDEX idx_agent_keys_active
    ON agent_signing_keys(tenant_id, agent_id, key_id)
    WHERE status = 'active';

-- Index for expiring keys
CREATE INDEX idx_agent_keys_expiring
    ON agent_signing_keys(expires_at)
    WHERE expires_at IS NOT NULL AND status = 'active';
```

---

## 9. Key Lifecycle Management

### 9.1 Key States

```
┌──────────────┐
│   Generated  │
└──────┬───────┘
       │ register_key()
       ▼
┌──────────────┐     revoke_key()     ┌──────────────┐
│    Active    │─────────────────────►│   Revoked    │
└──────┬───────┘                      └──────────────┘
       │
       │ expires_at reached
       ▼
┌──────────────┐     grace_until      ┌──────────────┐
│   Expired    │─────────────────────►│  Fully       │
│ (grace period)│    reached          │  Expired     │
└──────────────┘                      └──────────────┘
```

### 9.2 Key Rotation

```sql
-- Rotation tracking table
CREATE TABLE scheduled_key_rotations (
    id               UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    agent_id         UUID NOT NULL,
    key_type         VARCHAR(20) NOT NULL,
    current_key_id   INTEGER NOT NULL,
    scheduled_at     TIMESTAMPTZ NOT NULL,
    reason           VARCHAR(50) NOT NULL,  -- 'age_limit', 'usage_limit', etc.
    status           VARCHAR(20) NOT NULL DEFAULT 'pending',
    completed_at     TIMESTAMPTZ,
    new_key_id       INTEGER,
    error_message    TEXT
);

-- Get next key_id for rotation
CREATE FUNCTION get_next_agent_key_id(
    p_tenant_id UUID,
    p_agent_id UUID
) RETURNS INTEGER AS $$
    SELECT COALESCE(MAX(key_id), 0) + 1
    FROM agent_signing_keys
    WHERE tenant_id = p_tenant_id AND agent_id = p_agent_id;
$$ LANGUAGE SQL;
```

### 9.3 Rotation Policies

```sql
CREATE TABLE key_rotation_policies (
    id                      UUID PRIMARY KEY,
    tenant_id               UUID NOT NULL,
    agent_id                UUID,              -- NULL = tenant-wide default
    key_type                VARCHAR(20) NOT NULL,
    max_age_hours           INTEGER,           -- Time-based rotation
    max_usage_count         BIGINT,            -- Usage-based rotation
    warning_threshold_hours INTEGER DEFAULT 24,
    grace_period_hours      INTEGER DEFAULT 72,
    enforce_expiry          BOOLEAN DEFAULT true,
    auto_rotate             BOOLEAN DEFAULT false,

    UNIQUE (tenant_id, agent_id, key_type)
);
```

### 9.4 Usage Tracking

```sql
CREATE TABLE key_usage_counters (
    tenant_id      UUID NOT NULL,
    agent_id       UUID NOT NULL,
    key_id         INTEGER NOT NULL,
    key_type       VARCHAR(20) NOT NULL,
    usage_count    BIGINT NOT NULL DEFAULT 0,
    last_used_at   TIMESTAMPTZ,
    first_used_at  TIMESTAMPTZ,

    PRIMARY KEY (tenant_id, agent_id, key_id, key_type)
);

-- Atomic increment function
CREATE FUNCTION increment_key_usage(
    p_tenant_id UUID,
    p_agent_id UUID,
    p_key_id INTEGER,
    p_key_type VARCHAR
) RETURNS BIGINT AS $$
DECLARE
    v_count BIGINT;
BEGIN
    INSERT INTO key_usage_counters (tenant_id, agent_id, key_id, key_type, usage_count, last_used_at, first_used_at)
    VALUES (p_tenant_id, p_agent_id, p_key_id, p_key_type, 1, NOW(), NOW())
    ON CONFLICT (tenant_id, agent_id, key_id, key_type)
    DO UPDATE SET
        usage_count = key_usage_counters.usage_count + 1,
        last_used_at = NOW()
    RETURNING usage_count INTO v_count;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;
```

### 9.5 Audit Logging

```sql
CREATE TABLE key_rotation_audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    agent_id    UUID NOT NULL,
    key_type    VARCHAR(20) NOT NULL,
    action      VARCHAR(50) NOT NULL,    -- 'key_generated', 'key_rotated', etc.
    old_key_id  INTEGER,
    new_key_id  INTEGER,
    actor_type  VARCHAR(20) NOT NULL,    -- 'system', 'agent', 'admin', 'api'
    actor_id    UUID,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for audit queries
CREATE INDEX idx_key_audit_tenant
    ON key_rotation_audit_log(tenant_id, created_at DESC);
```

---

## 10. JSON Schemas

### 10.1 Agent Signing Key Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://stateset.com/schemas/ves-sig-1/agent-key.json",
  "title": "VES-SIG-1 Agent Signing Key",
  "type": "object",
  "required": ["tenant_id", "agent_id", "key_id", "public_key", "status"],
  "properties": {
    "tenant_id": {
      "type": "string",
      "format": "uuid"
    },
    "agent_id": {
      "type": "string",
      "format": "uuid"
    },
    "key_id": {
      "type": "integer",
      "minimum": 0
    },
    "public_key": {
      "type": "string",
      "pattern": "^0x[a-f0-9]{64}$",
      "description": "32-byte Ed25519 public key, hex encoded"
    },
    "status": {
      "type": "string",
      "enum": ["active", "revoked", "expired"]
    },
    "valid_from": {
      "type": "string",
      "format": "date-time"
    },
    "valid_to": {
      "type": "string",
      "format": "date-time"
    },
    "revoked_at": {
      "type": "string",
      "format": "date-time"
    }
  }
}
```

### 10.2 Signed Event Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://stateset.com/schemas/ves-sig-1/signed-event.json",
  "title": "VES-SIG-1 Signed Event",
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
    "payload_plain_hash",
    "payload_cipher_hash",
    "agent_signature"
  ],
  "properties": {
    "ves_version": {
      "type": "integer",
      "const": 1
    },
    "event_id": {
      "type": "string",
      "format": "uuid"
    },
    "tenant_id": {
      "type": "string",
      "format": "uuid"
    },
    "store_id": {
      "type": "string",
      "format": "uuid"
    },
    "source_agent_id": {
      "type": "string",
      "format": "uuid"
    },
    "agent_key_id": {
      "type": "integer",
      "minimum": 0
    },
    "entity_type": {
      "type": "string",
      "minLength": 1
    },
    "entity_id": {
      "type": "string",
      "minLength": 1
    },
    "event_type": {
      "type": "string",
      "minLength": 1
    },
    "created_at": {
      "type": "string",
      "format": "date-time"
    },
    "payload_kind": {
      "type": "integer",
      "enum": [0, 1]
    },
    "payload_plain_hash": {
      "type": "string",
      "pattern": "^0x[a-f0-9]{64}$"
    },
    "payload_cipher_hash": {
      "type": "string",
      "pattern": "^0x[a-f0-9]{64}$"
    },
    "agent_signature": {
      "type": "string",
      "pattern": "^0x[a-f0-9]{128}$",
      "description": "64-byte Ed25519 signature, hex encoded"
    }
  }
}
```

---

## 11. Code Examples

### 11.1 Rust Implementation

```rust
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use sha2::{Sha256, Digest};
use uuid::Uuid;

const DOMAIN_EVENTSIG: &[u8] = b"VES_EVENTSIG_V1";

/// Compute event signing hash
pub fn compute_event_signing_hash(params: &EventSigningParams) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain prefix
    hasher.update(DOMAIN_EVENTSIG);

    // Fixed fields
    hasher.update(params.ves_version.to_be_bytes());
    hasher.update(params.tenant_id.as_bytes());
    hasher.update(params.store_id.as_bytes());
    hasher.update(params.event_id.as_bytes());
    hasher.update(params.source_agent_id.as_bytes());
    hasher.update(params.agent_key_id.to_be_bytes());

    // Length-prefixed strings
    hasher.update(&encode_string(params.entity_type));
    hasher.update(&encode_string(params.entity_id));
    hasher.update(&encode_string(params.event_type));
    hasher.update(&encode_string(params.created_at));

    // Payload fields
    hasher.update(params.payload_kind.to_be_bytes());
    hasher.update(params.payload_plain_hash);
    hasher.update(params.payload_cipher_hash);

    hasher.finalize().into()
}

/// Sign an event
pub fn sign_event(signing_key: &SigningKey, params: &EventSigningParams) -> [u8; 64] {
    let hash = compute_event_signing_hash(params);
    let signature = signing_key.sign(&hash);
    signature.to_bytes()
}

/// Verify an event signature
pub fn verify_event(
    verifying_key: &VerifyingKey,
    params: &EventSigningParams,
    signature: &[u8; 64]
) -> bool {
    let hash = compute_event_signing_hash(params);
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(&hash, &sig).is_ok()
}

/// Encode string as length-prefixed UTF-8
fn encode_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(4 + bytes.len());
    result.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(bytes);
    result
}
```

### 11.2 TypeScript Implementation

```typescript
import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';

const DOMAIN_EVENTSIG = new TextEncoder().encode('VES_EVENTSIG_V1');

interface EventSigningParams {
  vesVersion: number;
  tenantId: string;
  storeId: string;
  eventId: string;
  sourceAgentId: string;
  agentKeyId: number;
  entityType: string;
  entityId: string;
  eventType: string;
  createdAt: string;
  payloadKind: number;
  payloadPlainHash: Uint8Array;
  payloadCipherHash: Uint8Array;
}

function computeEventSigningHash(params: EventSigningParams): Uint8Array {
  const parts: Uint8Array[] = [
    // Domain prefix
    DOMAIN_EVENTSIG,

    // Fixed fields
    u32be(params.vesVersion),
    uuidBytes(params.tenantId),
    uuidBytes(params.storeId),
    uuidBytes(params.eventId),
    uuidBytes(params.sourceAgentId),
    u32be(params.agentKeyId),

    // Length-prefixed strings
    encStr(params.entityType),
    encStr(params.entityId),
    encStr(params.eventType),
    encStr(params.createdAt),

    // Payload fields
    u32be(params.payloadKind),
    params.payloadPlainHash,
    params.payloadCipherHash,
  ];

  return sha256(concat(...parts));
}

async function signEvent(
  privateKey: Uint8Array,
  params: EventSigningParams
): Promise<Uint8Array> {
  const hash = computeEventSigningHash(params);
  return ed25519.sign(hash, privateKey);
}

async function verifyEvent(
  publicKey: Uint8Array,
  params: EventSigningParams,
  signature: Uint8Array
): Promise<boolean> {
  const hash = computeEventSigningHash(params);
  return ed25519.verify(signature, hash, publicKey);
}

// Helper functions
function u32be(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, n, false);
  return buf;
}

function encStr(s: string): Uint8Array {
  const bytes = new TextEncoder().encode(s);
  return concat(u32be(bytes.length), bytes);
}

function uuidBytes(uuid: string): Uint8Array {
  return new Uint8Array(
    uuid.replace(/-/g, '').match(/.{2}/g)!.map(b => parseInt(b, 16))
  );
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
```

### 11.3 Python Implementation

```python
import hashlib
import struct
import uuid
from typing import NamedTuple
from nacl.signing import SigningKey, VerifyKey

DOMAIN_EVENTSIG = b"VES_EVENTSIG_V1"

class EventSigningParams(NamedTuple):
    ves_version: int
    tenant_id: uuid.UUID
    store_id: uuid.UUID
    event_id: uuid.UUID
    source_agent_id: uuid.UUID
    agent_key_id: int
    entity_type: str
    entity_id: str
    event_type: str
    created_at: str
    payload_kind: int
    payload_plain_hash: bytes
    payload_cipher_hash: bytes

def compute_event_signing_hash(params: EventSigningParams) -> bytes:
    """Compute event signing hash per VES-SIG-1."""
    preimage = bytearray()

    # Domain prefix
    preimage.extend(DOMAIN_EVENTSIG)

    # Fixed fields (big-endian)
    preimage.extend(struct.pack('>I', params.ves_version))
    preimage.extend(params.tenant_id.bytes)
    preimage.extend(params.store_id.bytes)
    preimage.extend(params.event_id.bytes)
    preimage.extend(params.source_agent_id.bytes)
    preimage.extend(struct.pack('>I', params.agent_key_id))

    # Length-prefixed strings
    for s in [params.entity_type, params.entity_id,
              params.event_type, params.created_at]:
        encoded = s.encode('utf-8')
        preimage.extend(struct.pack('>I', len(encoded)))
        preimage.extend(encoded)

    # Payload fields
    preimage.extend(struct.pack('>I', params.payload_kind))
    preimage.extend(params.payload_plain_hash)
    preimage.extend(params.payload_cipher_hash)

    return hashlib.sha256(bytes(preimage)).digest()

def sign_event(signing_key: SigningKey, params: EventSigningParams) -> bytes:
    """Sign an event with Ed25519."""
    hash_bytes = compute_event_signing_hash(params)
    signed = signing_key.sign(hash_bytes)
    return signed.signature

def verify_event(
    verify_key: VerifyKey,
    params: EventSigningParams,
    signature: bytes
) -> bool:
    """Verify an event signature."""
    hash_bytes = compute_event_signing_hash(params)
    try:
        verify_key.verify(hash_bytes, signature)
        return True
    except Exception:
        return False

# Example usage
def example():
    # Generate key pair
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    # Create event params
    params = EventSigningParams(
        ves_version=1,
        tenant_id=uuid.UUID('00000000-0000-0000-0000-000000000001'),
        store_id=uuid.UUID('00000000-0000-0000-0000-000000000002'),
        event_id=uuid.uuid4(),
        source_agent_id=uuid.uuid4(),
        agent_key_id=1,
        entity_type='InventoryItem',
        entity_id='WIDGET-001',
        event_type='Adjusted',
        created_at='2025-01-01T00:00:00Z',
        payload_kind=0,
        payload_plain_hash=b'\x00' * 32,
        payload_cipher_hash=b'\x00' * 32,
    )

    # Sign
    signature = sign_event(signing_key, params)
    print(f"Signature: {signature.hex()}")

    # Verify
    valid = verify_event(verify_key, params, signature)
    print(f"Valid: {valid}")
```

### 11.4 Go Implementation

```go
package vessig

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/binary"

    "github.com/google/uuid"
)

var DomainEventsig = []byte("VES_EVENTSIG_V1")

type EventSigningParams struct {
    VesVersion       uint32
    TenantID         uuid.UUID
    StoreID          uuid.UUID
    EventID          uuid.UUID
    SourceAgentID    uuid.UUID
    AgentKeyID       uint32
    EntityType       string
    EntityID         string
    EventType        string
    CreatedAt        string
    PayloadKind      uint32
    PayloadPlainHash [32]byte
    PayloadCipherHash [32]byte
}

func ComputeEventSigningHash(params *EventSigningParams) [32]byte {
    h := sha256.New()

    // Domain prefix
    h.Write(DomainEventsig)

    // Fixed fields
    binary.Write(h, binary.BigEndian, params.VesVersion)
    h.Write(params.TenantID[:])
    h.Write(params.StoreID[:])
    h.Write(params.EventID[:])
    h.Write(params.SourceAgentID[:])
    binary.Write(h, binary.BigEndian, params.AgentKeyID)

    // Length-prefixed strings
    writeString(h, params.EntityType)
    writeString(h, params.EntityID)
    writeString(h, params.EventType)
    writeString(h, params.CreatedAt)

    // Payload fields
    binary.Write(h, binary.BigEndian, params.PayloadKind)
    h.Write(params.PayloadPlainHash[:])
    h.Write(params.PayloadCipherHash[:])

    var result [32]byte
    copy(result[:], h.Sum(nil))
    return result
}

func SignEvent(privateKey ed25519.PrivateKey, params *EventSigningParams) []byte {
    hash := ComputeEventSigningHash(params)
    return ed25519.Sign(privateKey, hash[:])
}

func VerifyEvent(
    publicKey ed25519.PublicKey,
    params *EventSigningParams,
    signature []byte,
) bool {
    hash := ComputeEventSigningHash(params)
    return ed25519.Verify(publicKey, hash[:], signature)
}

func writeString(h hash.Hash, s string) {
    bytes := []byte(s)
    binary.Write(h, binary.BigEndian, uint32(len(bytes)))
    h.Write(bytes)
}
```

---

## 12. Test Vectors

### 12.1 Key Generation Test Vector

```json
{
  "seed_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "private_key_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
}
```

### 12.2 Event Signing Test Vector

```json
{
  "description": "Complete event signing test vector",
  "params": {
    "ves_version": 1,
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "store_id": "00000000-0000-0000-0000-000000000002",
    "event_id": "11111111-1111-1111-1111-111111111111",
    "source_agent_id": "22222222-2222-2222-2222-222222222222",
    "agent_key_id": 1,
    "entity_type": "InventoryItem",
    "entity_id": "WIDGET-001",
    "event_type": "Adjusted",
    "created_at": "2025-01-01T00:00:00Z",
    "payload_kind": 0,
    "payload_plain_hash_hex": "0000000000000000000000000000000000000000000000000000000000000000",
    "payload_cipher_hash_hex": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "private_key_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "expected_event_signing_hash_hex": "IMPLEMENTATION_SPECIFIC",
  "expected_signature_hex": "IMPLEMENTATION_SPECIFIC",
  "note": "Hash and signature depend on exact preimage encoding"
}
```

### 12.3 Domain Separator Test Vectors

```json
{
  "domain_separators": {
    "VES_EVENTSIG_V1": {
      "ascii": "VES_EVENTSIG_V1",
      "hex": "5645535f4556454e545349475f5631",
      "length": 15
    },
    "VES_PAYLOAD_PLAIN_V1": {
      "ascii": "VES_PAYLOAD_PLAIN_V1",
      "hex": "5645535f5041594c4f41445f504c41494e5f5631",
      "length": 20
    },
    "VES_LEAF_V1": {
      "ascii": "VES_LEAF_V1",
      "hex": "5645535f4c4541465f5631",
      "length": 11
    }
  }
}
```

### 12.4 Deterministic Signature Test

```json
{
  "description": "Ed25519 signatures are deterministic",
  "test": {
    "message_hex": "48656c6c6f2c20576f726c6421",
    "private_key_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "expected_behavior": "Same key + message always produces identical signature"
  }
}
```

---

## 13. Security Considerations

### 13.1 Key Security

**Private Key Protection:**
- Store private keys in HSM or secure enclave when possible
- Never log or transmit private keys
- Use hardware-backed key generation in production
- Implement key backup with encryption

**Key Rotation:**
- Rotate keys at least every 90 days
- Implement automatic rotation based on usage thresholds
- Maintain audit trail of all key operations
- Support grace periods for smooth transitions

**Revocation:**
- Implement immediate revocation capability
- Evaluate events against `sequenced_at` (not `created_at`) for revocation
- Maintain revocation lists with timestamps
- Alert on signatures from revoked keys

### 13.2 Signature Security

**Verification Requirements:**
- ALWAYS verify signatures before processing events
- Use constant-time comparison for signature bytes
- Verify key validity at event time, not current time
- Reject events with invalid or missing signatures

**Replay Protection:**
- Enforce `event_id` uniqueness per stream
- Return existing sequence number for duplicate submissions
- Reject same `event_id` with different content

### 13.3 Hash Security

**Preimage Resistance:**
- SHA-256 provides 128-bit preimage resistance
- Domain separation prevents cross-protocol attacks
- Deterministic encoding ensures reproducibility

**Collision Resistance:**
- SHA-256 provides 128-bit collision resistance
- Unique domain prefixes per hash type
- No known practical attacks

### 13.4 Threat Model

| Threat | Mitigation |
|--------|------------|
| Key theft | HSM storage, rotation, monitoring |
| Signature forgery | Ed25519 security (128-bit) |
| Event tampering | Signature verification |
| Replay attacks | Event ID uniqueness |
| Key misuse | Time-based validity windows |
| Backdating | Verify against `sequenced_at` |

---

## 14. Implementation Checklist

### 14.1 Core Cryptography

- [ ] Ed25519 key generation with secure RNG
- [ ] Ed25519 signing implementation
- [ ] Ed25519 verification implementation
- [ ] SHA-256 hashing with domain separation

### 14.2 Event Signing Hash

- [ ] Correct preimage structure
- [ ] Big-endian integer encoding
- [ ] Length-prefixed string encoding
- [ ] UUID network byte order
- [ ] Domain prefix `VES_EVENTSIG_V1`

### 14.3 Key Registry

- [ ] Key lookup by (tenant, agent, key_id)
- [ ] Key status tracking (active/revoked/expired)
- [ ] Validity window enforcement
- [ ] Key registration and revocation

### 14.4 Verification

- [ ] Signature verification before processing
- [ ] Payload hash verification
- [ ] Key validity at event time
- [ ] Idempotency handling

### 14.5 Key Management

- [ ] Key rotation support
- [ ] Usage tracking
- [ ] Audit logging
- [ ] Grace period handling

---

## Appendix A: Domain Separators

| Constant | Value | Length | Usage |
|----------|-------|--------|-------|
| `DOMAIN_EVENTSIG` | `VES_EVENTSIG_V1` | 15 | Event signing preimage |
| `DOMAIN_PAYLOAD_PLAIN` | `VES_PAYLOAD_PLAIN_V1` | 20 | Plaintext payload hash |
| `DOMAIN_PAYLOAD_CIPHER` | `VES_PAYLOAD_CIPHER_V1` | 22 | Ciphertext hash |
| `DOMAIN_LEAF` | `VES_LEAF_V1` | 11 | Merkle leaf hash |
| `DOMAIN_NODE` | `VES_NODE_V1` | 11 | Merkle node hash |
| `DOMAIN_RECEIPT` | `VES_RECEIPT_V1` | 14 | Sequencer receipt |

---

## Appendix B: Encoding Primitives

### B.1 Integer Encoding

```
U32_BE(n) = 4-byte big-endian unsigned integer
U64_BE(n) = 8-byte big-endian unsigned integer
```

### B.2 String Encoding

```
ENC_STR(s) = U32_BE(len(UTF8(s))) || UTF8(s)
```

### B.3 UUID Encoding

```
UUID(u) = 16 bytes in network byte order (RFC 4122)
```

### B.4 Hash Encoding (JSON)

```
HASH_HEX(h) = "0x" || lowercase_hex(h)

Example: 0x7f8a9b3c4d5e6f708192a3b4c5d6e7f80011223344556677889900aabbccddee
```

### B.5 Signature Encoding (JSON)

```
SIG_HEX(s) = "0x" || lowercase_hex(s)

Example: 0x3f8a... (128 hex chars = 64 bytes)
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-22 | Initial specification |

---

*This specification is part of the Verifiable Event Sync (VES) v1.0 protocol. For the complete VES specification, see [VES_SPEC.md](./VES_SPEC.md). For encryption, see [VES_ENC_1_SPECIFICATION.md](./VES_ENC_1_SPECIFICATION.md).*
