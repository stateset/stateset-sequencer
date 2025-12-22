# Verifiable Event Sync (VES) Specification v1.0

**Status:** Draft (intended to be audit-ready)
**Last updated:** 2025-12-20
**Scope:** This spec defines the cryptographic, encoding, sequencing, commitment, proof, and anchoring rules for VES so that an independent verifier can reproduce (a) event hashes, (b) Merkle roots, (c) inclusion proofs, and (d) anti-equivocation guarantees from publicly available inputs.

This spec focuses on the items you prioritized for seed/early enterprise diligence:

* **Agent signatures** (cryptographic attribution / non-repudiation)
* **Unambiguous leaf encoding** (reproducible proofs)
* **Commitment chaining** (anti-fork / anti-equivocation)
* Plus: **ordering semantics**, **Merkle padding**, and a **canonical JSON standard** (JCS) to remove verification debates.

---

## 1. Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119 / RFC 8174.

---

## 2. System model

### 2.1 Actors

* **Agent**: an offline-capable writer that creates events and later syncs them.
* **Sequencer**: a service that validates events, assigns **canonical sequence numbers**, and stores an append-only log.
* **Verifier**: any third party (auditor, counterparty, regulator) who recomputes roots/proofs from data and compares to on-chain commitments.
* **Anchor chain**: a blockchain storing batch commitments (e.g., Set Chain + SetRegistry).

### 2.2 Streams

Events belong to a **stream** identified by:

* `tenant_id` (UUID)
* `store_id` (UUID)

All sequencing, batching, and commitment chaining are defined **per stream**.

---

## 3. Data types and encoding primitives

### 3.1 UUID

* JSON representation: canonical UUID string (RFC 4122), e.g. `"20f4a1ae-f3a2-4d29-9bc9-ab9715b81be6"`.
* Binary encoding: **16 bytes** per RFC 4122 in network byte order (the standard 16-byte UUID value).

### 3.2 Integers

* `u32`: 4-byte unsigned integer, **big-endian**
* `u64`: 8-byte unsigned integer, **big-endian**

### 3.3 Strings

Binary encoding of a string `s`:

```
ENC_STR(s) = U32_BE(len(UTF8(s))) || UTF8(s)
```

### 3.4 Hash bytes and hex strings

* Hash function outputs are **raw bytes** internally.
* In JSON, all hashes/signatures/keys MUST be encoded as **lowercase hex** with a `"0x"` prefix.

Lengths:

* SHA-256 hash: 32 bytes → `"0x"` + 64 hex chars
* Ed25519 public key: 32 bytes → `"0x"` + 64 hex chars
* Ed25519 signature: 64 bytes → `"0x"` + 128 hex chars

---

## 4. Cryptographic primitives

### 4.1 Hash function

VES v1 uses:

* **SHA-256** for all hashing in this spec.

### 4.2 Signature scheme

VES v1 requires:

* **Ed25519** for agent signatures.

Rationale: fast, deterministic, widely supported, strong audit story. (On-chain verification of Ed25519 is out of scope; signatures are verified off-chain by the sequencer and by any verifier.)

### 4.3 Domain separation

All hashes built from structured data MUST include an ASCII domain prefix as the first bytes of the preimage to prevent cross-protocol collisions.

Domains used in this spec:

* `b"VES_PAYLOAD_PLAIN_V1"` — plaintext payload hash
* `b"VES_PAYLOAD_AAD_V1"` — encrypted payload AAD
* `b"VES_PAYLOAD_CIPHER_V1"` — ciphertext hash
* `b"VES_RECIPIENTS_V1"` — recipients list hash
* `b"VES_EVENTSIG_V1"` — event signing preimage
* `b"VES_LEAF_V1"` — Merkle leaf
* `b"VES_NODE_V1"` — Merkle internal node
* `b"VES_PAD_LEAF_V1"` — padding leaf
* `b"VES_STREAM_V1"` — stream identifier
* `b"VES_RECEIPT_V1"` — sequencer receipt

Domain prefixes are ASCII bytes exactly as shown (no null terminator).

---

## 5. Payload kinds and hashing

VES v1.0 supports two payload kinds:

* **Plaintext (`payload_kind = 0`)**: JSON payload visible to sequencer
* **Encrypted (`payload_kind = 1`)**: Payload encrypted per VES-ENC-1 (Section 5A)

### 5.1 Canonical JSON

`payload` MUST be canonicalized using **RFC 8785 JSON Canonicalization Scheme (JCS)**.

* Canonical form MUST be encoded as UTF-8 bytes.
* Implementations MUST reject non-JSON values (NaN/Infinity), and MUST follow JCS number normalization rules.

**Practical guidance (non-normative, enterprise-friendly):**

* Monetary/decimal quantities SHOULD be represented as **strings** (e.g. `"12.34"`) or as integers in smallest units (e.g. cents) to avoid floating representation issues across languages.

### 5.2 Plaintext payload hash (`payload_plain_hash`)

For plaintext payloads, define:

```
payload_c14n_bytes = JCS(payload)  // UTF-8 bytes
payload_plain_hash = SHA256( b"VES_PAYLOAD_PLAIN_V1" || payload_c14n_bytes )
```

For encrypted payloads with a salt (see Section 5A):

```
payload_c14n_bytes = JCS(payload)  // UTF-8 bytes (plaintext before encryption)
payload_plain_hash = SHA256( b"VES_PAYLOAD_PLAIN_V1" || salt(16) || payload_c14n_bytes )
```

The 16-byte salt prevents guessability of low-entropy payloads in encrypted events.

### 5.3 Ciphertext hash (`payload_cipher_hash`)

For plaintext events (`payload_kind = 0`):

```
payload_cipher_hash = 0x0000...0000  (32 zero bytes)
```

For encrypted events (`payload_kind = 1`):

```
payload_cipher_hash = SHA256(
  b"VES_PAYLOAD_CIPHER_V1" ||
  nonce(12) ||
  payload_aad(32) ||
  ciphertext_bytes ||
  tag(16) ||
  recipients_hash(32)
)
```

Both `payload_plain_hash` and `payload_cipher_hash` are included in the event signing preimage (Section 6.2).

**Sequencer rule:** The sequencer MUST verify both hashes:
* For plaintext: recompute `payload_plain_hash` and verify `payload_cipher_hash` is zero
* For encrypted: verify `payload_cipher_hash` against the encrypted structure (sequencer cannot verify `payload_plain_hash` without decrypting)

---

## 5A. VES-ENC-1: Encrypted Payloads

This section defines the encrypted payload format for VES v1.0, enabling end-to-end encryption where the sequencer can sequence and commit events without accessing plaintext data.

### 5A.1 Overview

VES-ENC-1 uses:

* **Content encryption**: AES-256-GCM
* **Key encapsulation**: HPKE (RFC 9180) with:
  - Mode: Base (0x00)
  - KEM: DHKEM(X25519, HKDF-SHA256) - 0x0020
  - KDF: HKDF-SHA256 - 0x0001
  - AEAD: AES-256-GCM - 0x0002

### 5A.2 Encryption process

1. **Generate random values**:
   - `dek` (32 bytes): Data Encryption Key
   - `nonce` (12 bytes): AES-GCM nonce
   - `salt` (16 bytes): Payload salt for plaintext hash

2. **Prepare plaintext**:
   ```
   plaintext = salt(16) || JCS(payload)
   ```

3. **Compute payload_plain_hash**:
   ```
   payload_plain_hash = SHA256( b"VES_PAYLOAD_PLAIN_V1" || plaintext )
   ```

4. **Compute payload AAD** (binds ciphertext to event context):
   ```
   payload_aad = SHA256(
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
     payload_plain_hash(32)
   )
   ```

5. **Encrypt**:
   ```
   (ciphertext, tag) = AES-256-GCM.Encrypt(dek, nonce, plaintext, aad=payload_aad)
   ```

6. **Wrap DEK for each recipient** using HPKE:
   ```
   For each recipient (kid, public_key):
     (enc, ct) = HPKE.Seal(dek, recipient_public_key, info=payload_aad)
   ```

7. **Compute recipients_hash**:
   ```
   recipients_json = JCS(sorted_recipients_array)
   recipients_hash = SHA256( b"VES_RECIPIENTS_V1" || recipients_json )
   ```

8. **Compute payload_cipher_hash** (Section 5.3)

### 5A.3 Encrypted payload structure

The `payload_encrypted` field contains:

```json
{
  "enc_version": 1,
  "aead": "AES-256-GCM",
  "nonce_b64u": "<base64url>",
  "ciphertext_b64u": "<base64url>",
  "tag_b64u": "<base64url>",
  "hpke": {
    "mode": "base",
    "kem": "X25519-HKDF-SHA256",
    "kdf": "HKDF-SHA256",
    "aead": "AES-256-GCM"
  },
  "recipients": [
    {
      "recipient_kid": 1,
      "enc_b64u": "<base64url>",
      "ct_b64u": "<base64url>"
    }
  ]
}
```

Where:
* `nonce_b64u`: 12-byte nonce (base64url, no padding)
* `ciphertext_b64u`: Encrypted `salt || JCS(payload)`
* `tag_b64u`: 16-byte AES-GCM authentication tag
* `recipients`: Array sorted by `recipient_kid`
* `enc_b64u`: HPKE encapsulated key (32 bytes for X25519)
* `ct_b64u`: Wrapped DEK ciphertext

### 5A.4 Decryption process

1. Find recipient entry by `recipient_kid`
2. Unwrap DEK using HPKE:
   ```
   dek = HPKE.Open(enc, ct, recipient_private_key, info=payload_aad)
   ```
3. Decrypt content:
   ```
   plaintext = AES-256-GCM.Decrypt(dek, nonce, ciphertext || tag, aad=payload_aad)
   ```
4. Extract salt and payload:
   ```
   salt = plaintext[0:16]
   payload = JSON.parse(plaintext[16:])
   ```
5. Verify `payload_plain_hash`:
   ```
   computed = SHA256( b"VES_PAYLOAD_PLAIN_V1" || plaintext )
   assert computed == payload_plain_hash
   ```

### 5A.5 Security properties

* **Confidentiality**: Only designated recipients with private keys can decrypt
* **Context binding**: AAD prevents ciphertext substitution between events
* **Salt protection**: Prevents guessing low-entropy payloads via hash comparison
* **Sequencer-blind**: Sequencer can verify structural integrity and commit without seeing plaintext
* **Forward secrecy**: Per-event random DEK limits exposure from key compromise

### 5A.6 Recipient key management

Recipient public keys are managed separately from agent signing keys:

* Recipient keys use X25519 (ECDH) for HPKE
* Agent keys use Ed25519 (signatures)

Deployments SHOULD define a recipient key registry analogous to the agent key registry (Section 9).

---

## 6. Event envelope

### 6.1 Event fields

#### 6.1.1 Agent-authored fields (signed)

The following fields are authored by the agent and covered by the agent signature:

* `ves_version` (integer) — MUST be `1` for this spec
* `event_id` (UUID)
* `tenant_id` (UUID)
* `store_id` (UUID)
* `source_agent_id` (UUID)
* `agent_key_id` (u32) — identifies which public key in the agent key registry was used
* `entity_type` (string)
* `entity_id` (string)
* `event_type` (string)
* `created_at` (string) — RFC 3339 timestamp
* `payload_kind` (u32) — `0` for plaintext, `1` for encrypted
* `payload` (JSON object/value, OPTIONAL) — present when `payload_kind = 0`
* `payload_encrypted` (object, OPTIONAL) — present when `payload_kind = 1`, per Section 5A
* `payload_plain_hash` (hex string) — per Section 5.2
* `payload_cipher_hash` (hex string) — per Section 5.3
* `agent_signature` (hex string) — per Section 6.3

**created_at requirements:**

* MUST be a valid RFC 3339 timestamp string.
* SHOULD be UTC with `Z`.
* MUST be treated as **informational** for global ordering (see Section 7).

#### 6.1.2 Sequencer-assigned fields (not agent-signed)

These fields are assigned by the sequencer after validation:

* `sequence_number` (u64) — canonical ordering primitive
* `sequenced_at` (string) — RFC 3339 timestamp set by sequencer at acceptance time
* `sequencer_receipt` (object, OPTIONAL but RECOMMENDED) — Section 6.4

### 6.2 Canonical event signing preimage

The agent MUST compute an event signing hash from a fixed binary encoding.

Define the binary preimage:

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

> Note: Both `payload_plain_hash` and `payload_cipher_hash` are committed in the signature.
> For plaintext events, `payload_cipher_hash` is 32 zero bytes.
> For encrypted events, both hashes bind the agent signature to the complete cryptographic structure.

### 6.3 Agent signature

The agent MUST sign `event_signing_hash` using Ed25519:

```
agent_signature = Ed25519.Sign(agent_private_key, event_signing_hash)
```

The event MUST include `agent_signature` as a hex string (64 bytes).

### 6.4 Sequencer receipt (recommended)

To make “sequencer accepted this event” independently provable (even if the sequencer later censors or misbehaves), the sequencer SHOULD return a signed receipt.

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

```
receipt_hash = SHA256(receipt_preimage)
```

Sequencer signs `receipt_hash` with a published sequencer key (scheme MAY be Ed25519 or secp256k1; specify in deployment metadata).

Receipt object:

```json
"sequencer_receipt": {
  "sequencer_id": "uuid",
  "sequence_number": 27,
  "sequenced_at": "2025-12-20T18:35:10.456Z",
  "receipt_hash": "0x…32bytes…",
  "signature_alg": "ed25519",
  "sequencer_signature": "0x…"
}
```

---

## 7. Ordering semantics and clock drift

### 7.1 Canonical order

**The only canonical ordering primitive is `sequence_number`.**

* All state reconstruction, projections, and consistency guarantees MUST use ascending `sequence_number`.
* `created_at` MUST NOT be used to reorder events across agents.

### 7.2 created_at vs sequenced_at

* `created_at` is an **agent claim**, signed by the agent.
* `sequenced_at` is a **sequencer observation**, set when the sequencer accepts and sequences the event.

Clock drift scenarios (expected behavior):

* If Agent A’s clock is ahead, its `created_at` may be “in the future” relative to other events; this MUST NOT affect canonical replay.
* UIs MAY display both times and MAY show warnings for excessive skew, but MUST keep ordering by `sequence_number`.

### 7.3 Sequence assignment

For each stream `(tenant_id, store_id)`, the sequencer MUST assign `sequence_number` values that:

* Are strictly increasing by 1 with no gaps (unless explicitly documented as a checkpointing mode; see Section 10.4).
* Define a total order over accepted events in that stream.

---

## 8. Sequencer validation rules (accept/reject)

For each incoming event (agent-authored fields):

The sequencer MUST:

1. Validate required fields and types.
2. Recompute `payload_hash` per Section 5.2 and compare to provided `payload_hash`.
3. Lookup the agent public key using `(tenant_id, source_agent_id, agent_key_id)` in the **Agent Key Registry** (Section 9).
4. Recompute `event_signing_hash` per Section 6.2.
5. Verify `agent_signature` over `event_signing_hash`.
6. Enforce idempotency:

   * `event_id` MUST be unique per stream.
   * If the same `event_id` is re-submitted with identical signed content, the sequencer MUST return the previously assigned `sequence_number`.
   * If the same `event_id` is re-submitted with different content/signature, the sequencer MUST reject.

The sequencer MUST reject events if:

* Signature invalid
* Key unknown/revoked (per registry policy)
* Hash mismatch
* Unauthorized tenant/store access (authorization is deployment-specific but MUST exist)

---

## 9. Agent Key Registry

### 9.1 Registry responsibilities

A conforming deployment MUST provide a registry mapping:

```
(tenant_id, source_agent_id, agent_key_id) -> public_key + status + validity window
```

### 9.2 Key lifecycle

* Keys MAY be rotated by incrementing `agent_key_id`.
* Registry SHOULD support:

  * `valid_from`, `valid_to` (or equivalent)
  * `revoked_at` (optional but recommended)

Sequencer behavior:

* MUST reject events signed by revoked keys if `created_at` (or sequenced time) is after revocation policy threshold.
* MUST define and document whether revocation is evaluated against `created_at` or `sequenced_at`. (Enterprise-friendly default: evaluate against `sequenced_at` to prevent backdating.)

### 9.3 On-chain vs off-chain registry

* The registry MAY be on-chain (strongest auditability) or off-chain (faster iteration).
* If off-chain, registry updates SHOULD themselves be anchored (out of scope for v1, but recommended).

---

## 10. Merkle tree construction and leaf encoding

This section is the “make proofs independently reproducible” core.

### 10.1 Batch definition

A batch commitment covers a contiguous sequence range:

* `sequence_start` (u64, inclusive)
* `sequence_end` (u64, inclusive)
* `event_count = sequence_end - sequence_start + 1`

The ordered event list for the batch MUST be:

```
E[0] = event with sequence_number = sequence_start
E[i] = event with sequence_number = sequence_start + i
...
E[event_count-1] = event with sequence_number = sequence_end
```

### 10.2 Leaf hash

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

* stream identity (tenant/store)
* canonical position (sequence_number)
* the exact signed event content (via event_signing_hash)
* the exact agent signature bytes

### 10.3 Padding rule

Let `n = event_count`. Let `m = next_power_of_two(n)`.

Define:

```
PAD_LEAF = SHA256( b"VES_PAD_LEAF_V1" )
```

For indices:

* For `0 <= i < n`, use `leaf_hash[i]` from Section 10.2
* For `n <= i < m`, define `leaf_hash[i] = PAD_LEAF`

### 10.4 Internal node hash

For each level, pairwise hash left/right:

```
node_hash = SHA256( b"VES_NODE_V1" || left_child(32) || right_child(32) )
```

The Merkle **events root** is the single 32-byte hash at the top.

### 10.5 Leaf index

For a sequence number `s` in a batch:

* `leaf_index = s - sequence_start`

---

## 11. Inclusion proofs

### 11.1 Proof format

A proof for event at `leaf_index` consists of:

* `events_root` (32 bytes)
* `leaf_hash` (32 bytes)
* `leaf_index` (integer)
* `proof_path` (array of sibling hashes, bottom-up)

**Direction rule (no explicit left/right needed):**
At depth `d` (starting at 0 at the leaf level):

* If `(leaf_index >> d) & 1 == 0`, the sibling is on the **right**
* If `(leaf_index >> d) & 1 == 1`, the sibling is on the **left**

### 11.2 Verification algorithm

Given `leaf_hash`, `leaf_index`, `proof_path`, compute:

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

## 12. Commitment chaining and anti-equivocation

### 12.1 Goal

Prevent a sequencer from anchoring two conflicting histories (“forks”) for the same stream without detection.

### 12.2 Stream identifier

Define a `stream_id` (bytes32):

```
stream_id = SHA256( b"VES_STREAM_V1" || UUID(tenant_id) || UUID(store_id) )
```

### 12.3 On-chain commitment record

Each on-chain commitment for a stream MUST store:

* `stream_id` (bytes32)
* `sequence_start` (u64)
* `sequence_end` (u64)
* `event_count` (u32)
* `events_root` (bytes32)
* `prev_events_root` (bytes32)
* `timestamp` (chain timestamp)
* `submitter` (address)

### 12.4 Chaining rules

For each `stream_id`, the anchor contract MUST maintain a single canonical head with:

* `head_events_root`
* `head_sequence_end`

A new commitment is valid only if:

1. `prev_events_root == head_events_root`
2. `sequence_start == head_sequence_end + 1`
3. `event_count == sequence_end - sequence_start + 1`
4. `event_count > 0`

Genesis rule:

* If no head exists for `stream_id`, then:

  * `prev_events_root` MUST be `0x000…000` (32 bytes zero)
  * `sequence_start` MUST be `0`

This ensures a single append-only chain per stream and prevents anchored forks.

### 12.5 Checkpoint mode (optional extension)

Some deployments may want to begin anchoring mid-stream.

If supported, it MUST be explicit (e.g., `is_checkpoint=true` stored on-chain) and verifiers MUST treat checkpointed streams as **not proving** pre-checkpoint completeness.

(Recommendation for enterprise messaging: default to strict genesis chaining; only offer checkpoint mode with clear caveats.)

---

## 13. Anchoring interface (SetRegistry requirements)

A conforming SetRegistry-like contract MUST expose a method logically equivalent to:

```
commitBatch(
  bytes32 streamId,
  uint64 sequenceStart,
  uint64 sequenceEnd,
  uint32 eventCount,
  bytes32 eventsRoot,
  bytes32 prevEventsRoot
) returns (…)
```

The contract MUST:

* Enforce chaining rules (Section 12.4)
* Emit an event containing at least those fields

The contract MAY additionally store `prevStateRoot/newStateRoot` for application-specific state continuity; that is outside the generic VES v1 definition.

---

## 14. Sync protocol requirements (API-level, transport-agnostic)

This section is intentionally “HTTP shaped” but applies to any transport.

### 14.1 Push (agent → sequencer)

Agent submits event with all agent-authored fields, including signature.

Sequencer response MUST include:

* assigned `sequence_number`
* `sequenced_at`
* OPTIONAL `sequencer_receipt`

Idempotency:

* Re-pushing the same `event_id` + same signed content MUST return the same `sequence_number`.

### 14.2 Pull (agent ← sequencer)

Agent fetches canonical events for `(tenant_id, store_id)` by sequence range:

* `after_sequence` (exclusive)
* `limit`

Sequencer MUST return events strictly increasing by `sequence_number`.

### 14.3 Commitment creation (sequencer internal or public endpoint)

A commitment request for `[sequence_start, sequence_end]` MUST only succeed if:

* all events in the range exist
* the range is contiguous
* `events_root` is computed per Sections 10–11

### 14.4 Proof endpoint

Given `(stream, batch, sequence_number)`, sequencer SHOULD return:

* leaf_index
* leaf_hash
* proof_path
* events_root
  …and any metadata needed to locate the on-chain commitment.

---

## 15. Security considerations (threat model highlights)

### 15.1 Threats addressed by this spec

* **Event forgery “from another agent”**: prevented by agent signatures + key registry.
* **Event mutation after acceptance**: detectable because mutation breaks payload hash, signature, leaf hash, and Merkle root.
* **Anchored fork/equivocation**: prevented on-chain by commitment chaining rules.
* **Replay / duplicate submission**: prevented by `event_id` uniqueness + idempotent semantics.

### 15.2 Threats not fully solved (must be documented in sales/security reviews)

* **Censorship/withholding**: a sequencer can refuse to accept or serve events. Mitigations: sequencer receipts, multi-homing to multiple sequencers, and/or public mirroring.
* **Pre-anchoring trust window**: before a batch is anchored, the sequencer could misbehave. Mitigations: frequent anchoring cadence; receipts; monitoring.
* **Key compromise**: if an agent key is stolen, attacker can sign. Mitigations: HSM/secure enclave, rotation, revocation, anomaly detection.

---

## 16. Compatibility and versioning

### 16.1 Version field

All events MUST include `ves_version`.

* v1 events MUST use this spec’s signing/hash/leaf rules.
* Any future changes to leaf encoding, hash domains, canonicalization, or signature schemes MUST increment `ves_version`.

### 16.2 Mixed-version batches

A batch MUST NOT mix multiple `ves_version` values.

---

## Appendix A. Reference JSON event (examples)

### A.1 Plaintext event

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
  "payload": {
    "delta": 100,
    "reason": "shipment_receive",
    "location_bin": "A-12"
  },
  "payload_plain_hash": "0x7a4b9c…32bytes…",
  "payload_cipher_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "agent_signature": "0x3f8a…64bytes…",

  "sequence_number": 27,
  "sequenced_at": "2025-12-20T18:35:10.456Z",
  "sequencer_receipt": {
    "sequencer_id": "22222222-2222-2222-2222-222222222222",
    "sequence_number": 27,
    "sequenced_at": "2025-12-20T18:35:10.456Z",
    "receipt_hash": "0x…",
    "signature_alg": "ed25519",
    "sequencer_signature": "0x…"
  }
}
```

### A.2 Encrypted event

```json
{
  "ves_version": 1,
  "event_id": "e75f5d60-1d3f-5d29-9cf6-ba0826c92e7f",
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "store_id": "00000000-0000-0000-0000-000000000001",
  "source_agent_id": "11111111-1111-1111-1111-111111111111",
  "agent_key_id": 1,
  "entity_type": "InventoryItem",
  "entity_id": "WIDGET-001",
  "event_type": "InventoryAdjusted",
  "created_at": "2025-12-20T18:31:22.123Z",
  "payload_kind": 1,
  "payload_encrypted": {
    "enc_version": 1,
    "aead": "AES-256-GCM",
    "nonce_b64u": "dGVzdG5vbmNl",
    "ciphertext_b64u": "Y2lwaGVydGV4dA",
    "tag_b64u": "YXV0aHRhZw",
    "hpke": {
      "mode": "base",
      "kem": "X25519-HKDF-SHA256",
      "kdf": "HKDF-SHA256",
      "aead": "AES-256-GCM"
    },
    "recipients": [
      {
        "recipient_kid": 1,
        "enc_b64u": "ZW5jYXBzdWxhdGVk",
        "ct_b64u": "d3JhcHBlZGRlaw"
      }
    ]
  },
  "payload_plain_hash": "0x8b5c0d…32bytes…",
  "payload_cipher_hash": "0x9e6f1a…32bytes…",
  "agent_signature": "0x4c9b…64bytes…",

  "sequence_number": 28,
  "sequenced_at": "2025-12-20T18:35:11.789Z"
}
```

---

## Appendix B. What an auditor can verify “without trust” (checklist)

For a given on-chain batch commitment:

1. Read `(stream_id, sequence_start, sequence_end, events_root, prev_events_root)` from chain.
2. Fetch the event list for `[sequence_start..sequence_end]` (from sequencer or any mirror).
3. For each event:

   * Canonicalize `payload` with JCS and recompute `payload_hash`.
   * Recompute `event_signing_hash` and verify `agent_signature` against the registry key.
   * Recompute `leaf_hash` (Section 10.2).
4. Recompute `events_root` (Sections 10.3–10.4).
5. Compare to on-chain `events_root`.
6. Verify chain continuity by checking `prev_events_root` matches the previous batch root for the same stream.

---

## Appendix C. Implementation notes you’ll want in the repo (recommended)

To reduce diligence friction, publish alongside this spec:

* **Test vectors**:

  * payload → JCS bytes → payload_hash
  * event fields → event_signing_hash → signature (with a known private key)
  * leaf hashes for a 10-event batch + computed events_root + an inclusion proof
* A small verifier CLI:

  * `ves verify-batch --rpc ... --batch ...`
  * `ves verify-proof --events-root ... --leaf ... --path ... --index ...`

---

If you want, I can also turn this into a clean, versioned `VES-SPEC-v1.md` and a PDF “audit pack” format (spec + test vector templates + verification checklist) so you can drop it straight into a seed diligence data room.
