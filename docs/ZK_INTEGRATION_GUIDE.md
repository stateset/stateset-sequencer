# Zero-Knowledge Compliance Proof Integration (stateset-stark + sequencer)

Integrate **stateset-stark** STARK compliance proofs with the **StateSet sequencer** VES pipeline so anyone can verify compliance claims without seeing the sensitive payload.

## Architecture (High Level)

```
VES Event (signed, optionally encrypted)
        |
        v
Sequencer orders + stores event
        |
        |  POST /ves/compliance/:event_id/inputs  (canonical public inputs)
        v
External Prover (stateset-stark)
        |
        |  STARK proof bytes + witness commitment (Rescue hash output)
        v
Sequencer proof registry (encrypted-at-rest)
        |
        |  GET /ves/compliance/proofs/:proof_id/verify
        v
Cryptographic verification (in sequencer for STARK proofs)
```

## What This Adds

- Payload privacy: your business/regulated fields can stay encrypted or off-chain.
- Public verifiability: the sequencer can cryptographically verify STARK proofs and expose a verification endpoint.
- Post-quantum-friendly: STARKs avoid trusted setup.

## Quickstart (Recommended)

This runs the full flow end-to-end:
- registers an agent key
- ingests a spec-compliant VES event
- fetches canonical compliance public inputs
- generates a real STARK proof via `ves-stark`
- submits the proof + witness commitment
- verifies the proof (including cryptographic STARK verification)

```bash
cd /home/dom/icommerce-app/stateset-sequencer

# Optional (if auth is enabled):
# export SEQUENCER_API_KEY="ss_..."
# export SEQUENCER_URL="http://localhost:8080"

./scripts/run_zk_demo.sh
```

If you want to see the full code for signing/hashing, read:
- `scripts/zk_compliance_demo.mjs`
- `src/crypto/hash.rs` (VES hashing, domain separators, binary encodings)
- `src/domain/ves_event.rs` (VES envelope shape)

## Core API Workflow (Manual)

### 1) Fetch Canonical Compliance Public Inputs

```http
POST /api/v1/ves/compliance/:event_id/inputs
```

Request:
```json
{
  "policyId": "aml.threshold",
  "policyParams": { "threshold": 10000 }
}
```

Response (shape):
```json
{
  "event_id": "uuid",
  "public_inputs": { "...": "..." },
  "public_inputs_hash": "hex-32-bytes"
}
```

The `public_inputs` object is the *canonical* public input set for proving; clients must not mutate it.

### 2) Generate a STARK Proof (stateset-stark)

Use the canonical `public_inputs` JSON as the prover inputs.

```bash
cd /home/dom/icommerce-app/stateset-stark

# Save the `public_inputs` JSON from the sequencer as /tmp/public_inputs.json
# Then:
cargo run -q -p ves-stark-cli -- \\
  prove \\
  --policy aml.threshold \\
  --amount 5000 \\
  --limit 10000 \\
  --inputs /tmp/public_inputs.json \\
  --json > /tmp/proof.json
```

`/tmp/proof.json` contains (relevant fields):
- `proof_b64`: base64-encoded proof bytes
- `witness_commitment_hex`: 64-char lowercase hex string (32 bytes)

Tip: for a tighter integration, `ves-stark` also has an end-to-end command that fetches inputs,
generates the proof, submits it, and optionally verifies it:

```bash
cd /home/dom/icommerce-app/stateset-stark

cargo run -q -p ves-stark-cli -- \\
  prove-submit \\
  --sequencer-url "http://localhost:8080" \\
  --event-id "$EVENT_ID" \\
  --amount 5000 \\
  --limit 10000 \\
  --policy aml.threshold \\
  --verify
```

### 3) Submit the Proof to the Sequencer

```http
POST /api/v1/ves/compliance/:event_id/proofs
```

Request (STARK):
```json
{
  "proofType": "stark",
  "proofVersion": 2,
  "policyId": "aml.threshold",
  "policyParams": { "threshold": 10000 },
  "proofB64": "base64",
  "witnessCommitment": "64-lowercase-hex-chars"
}
```

Notes:
- `proofVersion` must match `ves_stark_verifier::PROOF_VERSION` (currently `2`).
- `witnessCommitment` is required for STARK proofs and is stored alongside the proof.
- The sequencer verifies the STARK proof at submission time by default.
  - Disable with `VES_STARK_VERIFY_ON_SUBMIT=false` (not recommended for production).

### 4) Verify a Stored Proof

```http
GET /api/v1/ves/compliance/proofs/:proof_id/verify
```

For STARK proofs, this endpoint returns:
- hash/inputs consistency checks
- cryptographic STARK verification fields: `stark_valid`, `stark_error`, `stark_verification_time_ms`

## Storage (Postgres)

Compliance proofs are stored encrypted-at-rest in `ves_compliance_proofs`.

Key fields:
- `(event_id, proof_type, proof_version, policy_hash)` is the idempotency key
- `witness_commitment` (BYTEA, 32 bytes) stores the STARK witness commitment (required for STARK verification)

Migration:
- `migrations/postgres/012_ves_compliance_proofs_witness_commitment.sql`

## Operational Knobs (Sequencer)

- `VES_STARK_VERIFY_ON_SUBMIT`:
  - default: `true`
  - when `false`, the sequencer stores STARK proofs without cryptographic verification at submission time.
- `VES_STARK_VERIFY_CONCURRENCY`:
  - default: `min(4, available_parallelism)`
  - caps concurrent STARK verifications to reduce CPU exhaustion risk.

## Next Improvements (High Impact)

1. Bind the private witness to the event payload hashes (prove correct parsing/decryption or a commitment-to-plaintext scheme).
2. Anchor proof hashes (or proof summaries) into commitments to make proofs part of the anchored audit trail.
3. Add more policies and policy versioning conventions (`policyId` namespacing, upgrade strategy).
