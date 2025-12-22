Yes — here is the **complete updated VES specification** (production-ready) with:

* **Encrypted payloads (VES-ENC-1)** using AES-256-GCM + HPKE (X25519)
* **Agent signatures** (Ed25519) with a frozen signing preimage
* **Unambiguous leaf encoding** with domain separation + fixed binary encodings
* **Commitment chaining** on-chain via `prev_events_root` to prevent anchored forks
* Clear **clock drift / ordering semantics** (`sequence_number` is canonical; `created_at` is informational)

You can share this directly with engineering:

[Download VES-SPEC-v1.0.md](sandbox:/mnt/data/VES-SPEC-v1.0.md)

---

## VES Specification v1.0 (Updated)

Below is the full text (same as the file):

---

# Verifiable Event Sync (VES) Specification v1.0

**Status:** Draft (production-oriented, audit-ready)
**Audience:** Engineering, security, auditors, enterprise buyers
**Last updated:** 2025-12-20
**Scope:** This specification defines how VES events are authored, signed, (optionally) end-to-end encrypted, sequenced, committed in Merkle batches, anchored on-chain with anti-equivocation chaining, and verified independently.

---

## Table of contents

1. [Conformance language](#1-conformance-language)
2. [System model](#2-system-model)
3. [Data types and canonical encodings](#3-data-types-and-canonical-encodings)
4. [Cryptographic primitives](#4-cryptographic-primitives)
5. [Canonical JSON and plaintext payload hashing](#5-canonical-json-and-plaintext-payload-hashing)
6. [Encrypted payloads (VES-ENC-1)](#6-encrypted-payloads-ves-enc-1)
7. [Event envelope](#7-event-envelope)
8. [Agent signatures (non-repudiation)](#8-agent-signatures-non-repudiation)
9. [Sequencer validation and idempotency](#9-sequencer-validation-and-idempotency)
10. [Ordering semantics and clock drift](#10-ordering-semantics-and-clock-drift)
11. [Merkle batching and leaf encoding](#11-merkle-batching-and-leaf-encoding)
12. [Inclusion proofs](#12-inclusion-proofs)
13. [On-chain anchoring and commitment chaining (anti-equivocation)](#13-on-chain-anchoring-and-commitment-chaining-anti-equivocation)
14. [Transport/API semantics (recommended)](#14-transportapi-semantics-recommended)
15. [Security considerations](#15-security-considerations)
16. [Versioning and compatibility](#16-versioning-and-compatibility)
    A. [Auditor verification checklist](#appendix-a-auditor-verification-checklist)
    B. [Reference JSON examples](#appendix-b-reference-json-examples)

---

## 1. Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119 / RFC 8174.

---

## 2. System model

### 2.1 Roles

* **Agent**: a writer that creates events while offline and later syncs them.
* **Sequencer**: validates events, assigns canonical sequence numbers, persists an append-only log, and produces Merkle batch commitments.
* **Anchor chain**: blockchain used to store commitments (e.g., Set Chain + SetRegistry contract).
* **Verifier**: any third party that checks signatures, recomputes Merkle roots, and compares them to on-chain commitments.

### 2.2 Streams

Events are sequenced and anchored per **stream**:

* `tenant_id` (UUID)
* `store_id` (UUID)

All ordering, batching, and commitment chaining are defined **per (tenant_id, store_id)**.

### 2.3 Threat model overview (non-normative)

VES v1 aims to provide:

* **Authenticity / non-repudiation:** events cannot be forged “as if” from an agent.
* **Integrity:** events cannot be modified without detection.
* **Canonical order:** all parties can replay the same history.
* **Verifiable anchoring:** third parties can verify inclusion from on-chain roots.
* **Anti-equivocation (anchored):** the sequencer cannot anchor conflicting histories for the same stream without detection.
* **Confidentiality (optional):** payloads may be encrypted such that the sequencer stores ciphertext only.

---

## 3. Data types and canonical encodings

### 3.1 UUID

* JSON representation: canonical UUID string (RFC 4122), e.g. `"20f4a1ae-f3a2-4d29-9bc9-ab9715b81be6"`.
* Binary representation: 16 bytes per RFC 4122 (network byte order).

Notation used in this spec:

* `UUID(x)` means the 16-byte representation of UUID `x`.

### 3.2 Integers

* `U32_BE(n)`: 4-byte unsigned integer, big-endian.
* `U64_BE(n)`: 8-byte unsigned integer, big-endian.

### 3.3 Strings

Binary encoding of a string `s`:

```
ENC_STR(s) = U32_BE(len(UTF8(s))) || UTF8(s)
```

### 3.4 Hex encoding for fixed-size cryptographic values

The following values MUST be JSON-encoded as lowercase hex with a `0x` prefix:

* SHA-256 hashes (32 bytes) → `"0x" + 64 hex chars`
* Merkle roots (32 bytes)
* Ed25519 public keys (32 bytes)
* Ed25519 signatures (64 bytes)

### 3.5 Base64url for variable-size binary blobs

Binary blobs that may be large (ciphertext, nonces, tags, HPKE outputs) MUST be encoded as **base64url without padding** (RFC 4648 §5). We denote this encoding as `b64u`.

Fields using `b64u` MUST be decoded to bytes before hashing/verification.

---

## 4. Cryptographic primitives

### 4.1 Hash function

VES v1 uses **SHA-256** for:

* payload hashing
* signing preimages (hashed then signed)
* leaf hashes
* Merkle internal nodes
* stream IDs

### 4.2 Signature scheme

VES v1 requires:

* **Ed25519** for agent signatures.

### 4.3 Payload encryption

VES-ENC-1 requires:

* **AES-256-GCM** as the content AEAD
* **HPKE base mode** using:

  * KEM: X25519 + HKDF-SHA256
  * KDF: HKDF-SHA256
  * AEAD: AES-256-GCM

### 4.4 Domain separation constants

All hashed structured preimages MUST begin with an ASCII domain prefix.

The following domain bytes are used:

* `b"VES_PAYLOAD_PLAIN_V1"`
* `b"VES_PAYLOAD_AAD_V1"`
* `b"VES_PAYLOAD_CIPHER_V1"`
* `b"VES_RECIPIENTS_V1"`
* `b"VES_EVENTSIG_V1"`
* `b"VES_LEAF_V1"`
* `b"VES_PAD_LEAF_V1"`
* `b"VES_NODE_V1"`
* `b"VES_STREAM_V1"`
* `b"VES_RECEIPT_V1"` (optional, if receipts are implemented)

Implementations MUST match these prefixes exactly (ASCII bytes, no null terminator).

---

## 5. Canonical JSON and plaintext payload hashing

### 5.1 Canonical JSON

The plaintext payload MUST be canonicalized using **RFC 8785 JSON Canonicalization Scheme (JCS)**.

* Canonical form MUST be UTF-8 encoded bytes.
* Implementations MUST reject non-JSON values (NaN/Infinity).
* For cross-language safety, payloads SHOULD avoid floating-point numbers; represent amounts as integers (minor units) or strings.

### 5.2 Plaintext payload hash (payload_plain_hash)

Let:

* `payload_c14n = JCS(payload)` as UTF-8 bytes.

For **plaintext** payload events (`payload_kind = 0`):

```
payload_plain_hash = SHA256( b"VES_PAYLOAD_PLAIN_V1" || payload_c14n )
```

For **encrypted** payload events (`payload_kind = 1`), the plaintext is salted to reduce guessability:

* Generate `payload_salt` = 16 bytes cryptographically random.
* Define `payload_plaintext_bytes = payload_salt || payload_c14n`.

Then:

```
payload_plain_hash = SHA256( b"VES_PAYLOAD_PLAIN_V1" || payload_plaintext_bytes )
```

**Important:** For encrypted payloads, `payload_salt` MUST NOT be transmitted in plaintext; it MUST be contained only inside the encrypted plaintext (see Section 6.3).

---

## 6. Encrypted payloads (VES-ENC-1)

Encrypted payloads provide confidentiality: the sequencer can validate signatures, order events, and commit/anchor ciphertexts without reading business data.

### 6.1 Payload kind

`payload_kind` MUST be one of:

* `0` = plaintext payload (`payload` present; `payload_encrypted` absent)
* `1` = encrypted payload (`payload` omitted or null; `payload_encrypted` present)

### 6.2 Content encryption: AES-256-GCM

For `payload_kind = 1`:

* Generate a random **DEK** (data encryption key): `dek` = 32 random bytes.
* Generate a random nonce: `nonce` = 12 random bytes.

Plaintext to encrypt:

* `payload_plaintext_bytes = payload_salt(16 bytes) || JCS(payload)`.

Associated data (AAD):

AAD binds ciphertext to the event context to prevent ciphertext substitution across events.

Define:

```
payload_aad_preimage =
  b"VES_PAYLOAD_AAD_V1" ||
  UUID(tenant_id) ||
  UUID(store_id) ||
  UUID(event_id) ||
  UUID(source_agent_id) ||
  U32_BE(agent_key_id) ||
  ENC_STR(entity_type) ||
  ENC_STR(entity_id) ||
  ENC_STR(event_type) ||
  ENC_STR(created_at) ||
  payload_plain_hash(32)
```

Then:

```
payload_aad = SHA256(payload_aad_preimage)   // 32 bytes
```

Encrypt:

* `(ciphertext, tag) = AES-256-GCM.Encrypt(key=dek, nonce=nonce, aad=payload_aad, plaintext=payload_plaintext_bytes)`

Where:

* `ciphertext` is the encrypted bytes (same length as plaintext)
* `tag` is 16 bytes

### 6.3 Key wrapping to recipients: HPKE base mode

Each encrypted event MUST include a list of **recipients** whose public keys can unwrap the DEK.

Each recipient entry:

* references a public key by `recipient_kid` (u32) in a Recipient Key Registry
* contains HPKE outputs `enc` and `ct`

HPKE parameters are fixed for VES-ENC-1:

* mode: base
* KEM: X25519 + HKDF-SHA256
* KDF: HKDF-SHA256
* AEAD: AES-256-GCM

HPKE context `info` MUST be derived deterministically:

```
hpke_info = SHA256(
  b"VES_PAYLOAD_CIPHER_V1" ||
  UUID(tenant_id) ||
  UUID(store_id) ||
  UUID(event_id) ||
  payload_aad
)
```

For each recipient public key `pk_i`, compute:

* `(enc_i, ct_i) = HPKE.Seal(pk_i, info=hpke_info, aad=payload_aad, plaintext=dek)`

The `recipients` list MUST contain at least one recipient.

### 6.4 Recipient list canonicalization and recipients_hash

To ensure all verifiers compute identical hashes, the recipients list MUST be canonicalized:

* Sort recipients ascending by `recipient_kid` (numeric).
* No duplicate `recipient_kid` entries are allowed.

Define each canonical recipient entry encoding:

```
RECIP_ENTRY(i) =
  U32_BE(recipient_kid_i) ||
  U32_BE(len(enc_i)) || enc_i ||
  U32_BE(len(ct_i))  || ct_i
```

Then:

```
recipients_hash = SHA256( b"VES_RECIPIENTS_V1" || RECIP_ENTRY(0) || ... || RECIP_ENTRY(n-1) )
```

### 6.5 Ciphertext bundle hash (payload_cipher_hash)

For `payload_kind = 1`, define:

```
cipher_preimage =
  b"VES_PAYLOAD_CIPHER_V1" ||
  U32_BE(1) ||                      // enc_version = 1
  nonce(12) ||
  payload_aad(32) ||
  U32_BE(len(ciphertext)) || ciphertext ||
  tag(16) ||
  recipients_hash(32)
```

Then:

```
payload_cipher_hash = SHA256(cipher_preimage)
```

For `payload_kind = 0` (plaintext):

* `payload_cipher_hash` MUST be 32 bytes of zero (`0x0000...0000` in JSON).

### 6.6 What the sequencer can validate for encrypted payloads

For `payload_kind = 1`, the sequencer:

* CAN verify `payload_cipher_hash` matches the provided `payload_encrypted` fields.
* CANNOT verify that decrypting ciphertext yields a plaintext consistent with `payload_plain_hash` unless the sequencer is also a recipient (not required and generally discouraged).

However:

* Because `payload_plain_hash` and `payload_cipher_hash` are signed by the agent (Section 8), any mismatch is attributable to the agent and detectable by any authorized decryptor.

---

## 7. Event envelope

### 7.1 Required event fields

All events MUST include:

* `ves_version` (u32) — MUST be `1`
* `event_id` (UUID)
* `tenant_id` (UUID)
* `store_id` (UUID)
* `source_agent_id` (UUID)
* `agent_key_id` (u32) — identifies agent signing key
* `entity_type` (string)
* `entity_id` (string)
* `event_type` (string)
* `created_at` (RFC 3339 string)
* `payload_kind` (u32): 0 plaintext, 1 encrypted
* `payload_plain_hash` (32-byte hex string)
* `payload_cipher_hash` (32-byte hex string)
* `agent_signature` (Ed25519 signature hex string, 64 bytes)

Plus either:

#### Plaintext payload form (`payload_kind = 0`)

* `payload` (JSON value) — REQUIRED
* `payload_encrypted` — MUST be absent

#### Encrypted payload form (`payload_kind = 1`)

* `payload` — SHOULD be absent or null
* `payload_encrypted` — REQUIRED (see Section 7.2)

### 7.2 payload_encrypted object (when payload_kind = 1)

`payload_encrypted` MUST include:

* `enc_version` (u32) — MUST be `1`
* `aead` (string) — MUST be `"AES-256-GCM"`
* `nonce_b64u` (string) — 12-byte nonce encoded in base64url
* `ciphertext_b64u` (string) — ciphertext bytes base64url
* `tag_b64u` (string) — 16-byte tag base64url
* `hpke` (object) — algorithm identifiers (strings; fixed for v1)
* `recipients` (array) — recipient entries

Recipient entry:

* `recipient_kid` (u32)
* `enc_b64u` (string) — HPKE `enc` bytes base64url
* `ct_b64u` (string) — HPKE `ct` bytes base64url

The recipients list MUST be sorted by `recipient_kid` ascending.

---

## 8. Agent signatures (non-repudiation)

### 8.1 Agent signing keys and registry

Each agent has an Ed25519 keypair. A deployment MUST provide a registry mapping:

* `(tenant_id, source_agent_id, agent_key_id) -> agent_signing_public_key + status + metadata`

Key rotation:

* Agents MAY rotate keys by incrementing `agent_key_id`.
* The registry MUST define revocation policy (see Section 15).

### 8.2 Canonical signing preimage and signing hash

Define the event signing preimage:

```
eventsig_preimage =
  b"VES_EVENTSIG_V1" ||
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
  U32_BE(payload_kind) ||
  payload_plain_hash(32) ||
  payload_cipher_hash(32)
```

Then:

```
event_signing_hash = SHA256(eventsig_preimage)
```

### 8.3 Signature

The agent MUST compute:

* `agent_signature = Ed25519.Sign(agent_sk, event_signing_hash)`

The event MUST include `agent_signature` as a 64-byte hex string.

### 8.4 Optional: sequencer receipt (recommended)

To let an agent prove the sequencer accepted an event (even if later censored), the sequencer MAY provide a receipt.

Receipt preimage:

```
receipt_preimage =
  b"VES_RECEIPT_V1" ||
  UUID(tenant_id) ||
  UUID(store_id) ||
  UUID(event_id) ||
  U64_BE(sequence_number) ||
  event_signing_hash(32)
```

Receipt hash:

* `receipt_hash = SHA256(receipt_preimage)`

Sequencer signs `receipt_hash` with a published sequencer key.
Receipt format is deployment-defined but MUST include the above fields.

---

## 9. Sequencer validation and idempotency

### 9.1 Validation steps (MUST)

Upon receiving an event, the sequencer MUST:

1. Validate basic schema and types.
2. Validate `ves_version == 1`.
3. If `payload_kind == 0`:

   * Recompute `payload_plain_hash` from `payload` per Section 5.2.
   * Ensure `payload_cipher_hash` is all-zero.
4. If `payload_kind == 1`:

   * Parse `payload_encrypted` and recompute `payload_cipher_hash` per Section 6.5.
   * The sequencer SHOULD recompute and validate recipient sorting/uniqueness.
   * The sequencer MUST NOT require decryption.
5. Lookup agent public key via `(tenant_id, source_agent_id, agent_key_id)`.
6. Recompute `event_signing_hash` per Section 8.2.
7. Verify `agent_signature` over `event_signing_hash` using the registry public key.
8. Enforce authorization policy (tenant/store access, agent permissions).
9. Assign `sequence_number` in the canonical stream order (Section 10) and persist the event append-only.

### 9.2 Idempotency and uniqueness (MUST)

* `event_id` MUST be unique within a stream `(tenant_id, store_id)`.
* If the sequencer receives the same `event_id` again:

  * If the signed content is identical (same `event_signing_hash`), the sequencer MUST return the previously assigned `sequence_number` (idempotent accept).
  * If the signed content differs, the sequencer MUST reject.

---

## 10. Ordering semantics and clock drift

### 10.1 Canonical ordering primitive

**The only canonical ordering primitive is `sequence_number`.**

All replay, projections, and consistency guarantees MUST order events by increasing `sequence_number` within the stream.

### 10.2 created_at semantics

* `created_at` is an **agent-authored timestamp**, signed by the agent.
* `created_at` MAY be incorrect due to clock drift.
* Systems MUST NOT use `created_at` to define global event order across agents.

### 10.3 sequenced_at semantics (optional but recommended)

Sequencers SHOULD record `sequenced_at` (RFC 3339) when accepting events.
`sequenced_at` is informational and helps debugging latency and drift.

---

## 11. Merkle batching and leaf encoding

This section defines the batch Merkle root used for anchoring.

### 11.1 Batch definition

A batch commitment covers a contiguous sequence range:

* `sequence_start` (u64, inclusive)
* `sequence_end` (u64, inclusive)
* `event_count = sequence_end - sequence_start + 1`

The ordered event list in the batch MUST be:

* `E[i]` is the event with `sequence_number = sequence_start + i`.

### 11.2 Leaf hash (unambiguous encoding)

For each event `E[i]` in the batch, define leaf preimage:

```
leaf_preimage =
  b"VES_LEAF_V1" ||
  UUID(tenant_id) ||
  UUID(store_id) ||
  U64_BE(sequence_number) ||
  event_signing_hash(32) ||
  agent_signature(64)
```

Leaf hash:

```
leaf_hash[i] = SHA256(leaf_preimage)
```

This commits to:

* the stream identity
* the event’s canonical position
* the exact signed event content (via event_signing_hash)
* and the signature bytes

### 11.3 Padding rule

Let `n = event_count`, `m = next_power_of_two(n)`.

Define:

```
PAD_LEAF = SHA256( b"VES_PAD_LEAF_V1" )
```

For indices:

* For `0 <= i < n`, use computed `leaf_hash[i]`.
* For `n <= i < m`, set `leaf_hash[i] = PAD_LEAF`.

### 11.4 Internal node hash

For any node with children `(L, R)`:

```
node_hash = SHA256( b"VES_NODE_V1" || L(32) || R(32) )
```

The **events_root** is the top hash of the Merkle tree.

### 11.5 Leaf index

For sequence number `s` in the batch:

* `leaf_index = s - sequence_start`

---

## 12. Inclusion proofs

### 12.1 Proof format

A proof for a specific event includes:

* `events_root` (32 bytes hex)
* `sequence_start` (u64)
* `sequence_number` (u64)
* `leaf_index` (u64)
* `leaf_hash` (32 bytes hex)
* `proof_path` (array of sibling hashes hex, bottom-up)

### 12.2 Direction derivation

No explicit left/right markers are required if the verifier derives direction from `leaf_index`.

At depth `d` (starting at 0):

* If `(leaf_index >> d) & 1 == 0`, sibling is on the **right**.
* If `(leaf_index >> d) & 1 == 1`, sibling is on the **left**.

### 12.3 Proof verification algorithm

Given `leaf_hash`, `leaf_index`, `proof_path`:

```
current = leaf_hash
for d in 0..len(proof_path)-1:
  sibling = proof_path[d]
  if ((leaf_index >> d) & 1) == 0:
     current = SHA256(b"VES_NODE_V1" || current || sibling)
  else:
     current = SHA256(b"VES_NODE_V1" || sibling || current)

valid iff current == events_root
```

---

## 13. On-chain anchoring and commitment chaining (anti-equivocation)

### 13.1 Stream ID

To anchor per stream, define:

```
stream_id = SHA256( b"VES_STREAM_V1" || UUID(tenant_id) || UUID(store_id) )
```

### 13.2 On-chain batch commitment record

A conforming SetRegistry-like contract MUST store or emit:

* `stream_id` (bytes32)
* `sequence_start` (u64)
* `sequence_end` (u64)
* `event_count` (u32)
* `events_root` (bytes32)
* `prev_events_root` (bytes32)
* `timestamp` (block timestamp)
* `submitter` (address)

### 13.3 Commitment chaining rules (MUST)

For each `stream_id`, the contract MUST maintain a single canonical **head**:

* `head_events_root`
* `head_sequence_end`

A new commitment is valid only if:

1. `prev_events_root == head_events_root`
2. `sequence_start == head_sequence_end + 1`
3. `event_count == sequence_end - sequence_start + 1`
4. `event_count > 0`

Genesis rule:

* If no head exists for `stream_id`:

  * `prev_events_root` MUST be all-zero (`0x00...00`)
  * `sequence_start` MUST be `0`

These rules prevent anchoring multiple conflicting histories for the same stream.

---

## 14. Transport/API semantics (recommended)

This section is non-normative but RECOMMENDED for consistent behavior across implementations.

### 14.1 Push: agent → sequencer

* Endpoint accepts an event (agent-authored fields + payload info).
* Response returns assigned `sequence_number` and optional receipt.

Idempotency:

* repeated pushes of the same signed event MUST return the same sequence number.

### 14.2 Pull: agent ← sequencer

* Pull by `(tenant_id, store_id, after_sequence, limit)`.
* Return events strictly increasing by `sequence_number`.

### 14.3 Create commitment

* Request: `(tenant_id, store_id, sequence_start, sequence_end)`
* Response: `{ events_root, event_count, ... }`

### 14.4 Anchor commitment

* Request: `batch_id` (or equivalent commitment identifier)
* Sequencer submits to chain and returns tx hash.

### 14.5 Proof endpoint

Given `sequence_number`, return:

* leaf_hash, leaf_index, proof_path, events_root, batch metadata

---

## 15. Security considerations

### 15.1 What is proven without decryption keys

A verifier without decryption keys can still prove:

* The event was signed by the agent (signature verifies)
* The signed event was included in an anchored batch (Merkle proof)
* The batch was chained correctly on-chain (anti-equivocation per stream)

They cannot verify plaintext business data for encrypted payload events.

### 15.2 What is proven with decryption keys

An authorized decryptor can additionally:

* Decrypt payload ciphertext
* Extract `payload_salt`
* Recompute `payload_plain_hash` and confirm it matches the signed hash
* Confirm ciphertext corresponds to the signed plaintext commitment

### 15.3 Censorship / withholding (not fully solved)

A sequencer can refuse to accept events or delay anchoring. Mitigations include:

* frequent anchoring cadence
* publishing sequencer receipts
* mirrored event stores
* multiple sequencers / failover

### 15.4 Key compromise and rotation

* Compromised agent signing keys allow forged events as that agent until revoked.
* Registries SHOULD support revocation and rotation.
* A deployment MUST define whether revocation is evaluated against `created_at` or `sequenced_at`.

  * RECOMMENDED: enforce against `sequenced_at` to prevent “backdating” signed events after revocation.

### 15.5 Metadata leakage in encrypted payload events

Even with encrypted payloads, some metadata remains visible:

* tenant/store IDs
* entity_type / entity_id / event_type
* created_at
* payload hashes (plaintext hash is salted; ciphertext hash is visible)

If entity identifiers are sensitive, deployments SHOULD consider:

* encrypting entity_id (requires a different indexing approach)
* or using opaque identifiers

---

## 16. Versioning and compatibility

### 16.1 Version fields

* `ves_version` MUST be `1`.
* `payload_encrypted.enc_version` MUST be `1` for encrypted payloads.

Any change to:

* signing preimages
* domain prefixes
* leaf encoding
* Merkle hashing rules
* encryption formats / recipients hashing
  MUST increment the relevant version.

### 16.2 Mixed-version batches

A batch MUST NOT mix multiple `ves_version` values.

---

## Appendix A. Auditor verification checklist

Given a claimed anchored batch:

1. Read commitment from chain: `(stream_id, sequence_start, sequence_end, events_root, prev_events_root)`.
2. Fetch events for `[sequence_start..sequence_end]` from sequencer or any mirror.
3. For each event:

   * Verify signature (agent registry + Section 8).
   * If plaintext payload: recompute `payload_plain_hash` from `payload`.
   * If encrypted payload: recompute `payload_cipher_hash` from `payload_encrypted`.
4. Recompute each `leaf_hash` (Section 11.2).
5. Recompute Merkle `events_root` (Sections 11.3–11.4).
6. Compare computed `events_root` to on-chain `events_root`.
7. Verify chaining: confirm `prev_events_root` matches the previous anchored root for that stream.

If decrypt keys are available and payload is encrypted:
8. Decrypt, extract salt, recompute `payload_plain_hash`, compare to signed hash.

---

## Appendix B. Reference JSON examples

### B.1 Plaintext payload event (payload_kind = 0)

```json
{
  "ves_version": 1,
  "event_id": "d64f4c59-0c2f-4c18-8bf5-9af90a6c6d5e",
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "store_id": "00000000-0000-0000-0000-000000000001",
  "source_agent_id": "11111111-1111-1111-1111-111111111111",
  "agent_key_id": 1,
  "entity_type": "InventoryItem",
  "entity_id": "WIDGET-001",
  "event_type": "InventoryAdjusted",
  "created_at": "2025-12-20T18:31:22.123Z",
  "payload_kind": 0,
  "payload": { "delta": 100, "reason": "shipment_receive" },
  "payload_plain_hash": "0x…",
  "payload_cipher_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "agent_signature": "0x…"
}
```

### B.2 Encrypted payload event (payload_kind = 1)

```json
{
  "ves_version": 1,
  "event_id": "0a9fd2d7-8c3b-4d13-9e24-0f42f9d3c2aa",
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "store_id": "00000000-0000-0000-0000-000000000001",
  "source_agent_id": "11111111-1111-1111-1111-111111111111",
  "agent_key_id": 2,
  "entity_type": "Order",
  "entity_id": "ORD-123",
  "event_type": "OrderPacked",
  "created_at": "2025-12-20T18:45:10.001Z",
  "payload_kind": 1,
  "payload_plain_hash": "0x…",
  "payload_cipher_hash": "0x…",
  "payload_encrypted": {
    "enc_version": 1,
    "aead": "AES-256-GCM",
    "nonce_b64u": "…",
    "ciphertext_b64u": "…",
    "tag_b64u": "…",
    "hpke": {
      "mode": "base",
      "kem": "X25519-HKDF-SHA256",
      "kdf": "HKDF-SHA256",
      "aead": "AES-256-GCM"
    },
    "recipients": [
      { "recipient_kid": 10, "enc_b64u": "…", "ct_b64u": "…" },
      { "recipient_kid": 11, "enc_b64u": "…", "ct_b64u": "…" }
    ]
  },
  "agent_signature": "0x…"
}
```