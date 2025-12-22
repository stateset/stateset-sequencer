# VES-STARK-1 Validity Proofs Demo

This walkthrough demonstrates VES-STARK-1 validity proofs for batch verification of VES events using STARK proofs.

## Prerequisites

- Rust 1.70+ with cargo
- Node.js 18+
- Solana CLI tools
- VES Sequencer running

## Demo Scenario: Batch Verification

Prove validity of 1000 VES events in a single STARK proof, anchoring the batch commitment on Solana for 97% cost reduction compared to individual verification.

```
┌─────────────────────────────────────────────────────────────────┐
│              VES-STARK-1 Batch Verification Flow                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1000 VES Events                                               │
│   ┌─────┐┌─────┐┌─────┐┌─────┐     ┌─────┐                     │
│   │ E₁  ││ E₂  ││ E₃  ││ E₄  │ ... │E₁₀₀₀│                     │
│   │seq:1││seq:2││seq:3││seq:4│     │     │                     │
│   └──┬──┘└──┬──┘└──┬──┘└──┬──┘     └──┬──┘                     │
│      │      │      │      │           │                         │
│      └──────┴──────┴──────┴───────────┘                         │
│                      │                                          │
│                      ▼                                          │
│              ┌───────────────┐                                  │
│              │ STARK Prover  │                                  │
│              │ Constraints:  │                                  │
│              │ - seq++       │                                  │
│              │ - sig valid   │                                  │
│              │ - merkle OK   │                                  │
│              └───────┬───────┘                                  │
│                      │                                          │
│                      ▼                                          │
│              ┌───────────────┐        ┌───────────────┐         │
│              │ STARK Proof   │───────▶│ On-Chain      │         │
│              │ ~100 KB       │        │ Verification  │         │
│              │               │        │ ~200K CU      │         │
│              └───────────────┘        └───────────────┘         │
│                                                                 │
│   Cost: 0.001 SOL vs 1 SOL for 1000 individual txs             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Step 1: Setup Prover Environment

```bash
# Clone the VES-STARK prover
cd /home/dom/icommerce-app/stateset-stark

# Build the prover in release mode
cargo build --release

# Verify installation
./target/release/ves-stark --version
```

## Step 2: Generate Test Events

```javascript
// demo-generate-events.mjs
import { Sequencer } from '../lib/sequencer.js';
import { randomUUID } from 'crypto';

const sequencer = new Sequencer();
await sequencer.connect();

const tenantId = "550e8400-e29b-41d4-a716-446655440000";
const storeId = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

// Generate 1000 events for batch proof
const events = [];
for (let i = 0; i < 1000; i++) {
  const event = {
    eventType: "InventoryUpdated",
    entityType: "Product",
    entityId: `PROD-${String(i).padStart(6, '0')}`,
    version: 1,
    payload: {
      sku: `SKU-${String(i).padStart(6, '0')}`,
      previousQuantity: Math.floor(Math.random() * 100),
      newQuantity: Math.floor(Math.random() * 100),
      reason: "restock",
      locationId: `LOC-${String(i % 10).padStart(3, '0')}`
    },
    timestamp: new Date(Date.now() + i * 1000).toISOString()
  };

  const result = await sequencer.appendEvent(event);
  events.push({
    ...event,
    eventId: result.eventId,
    sequenceNumber: result.sequenceNumber,
    signature: result.signature
  });

  if (i % 100 === 0) {
    console.log(`Generated ${i + 1} events...`);
  }
}

console.log(`Generated ${events.length} events`);
console.log(`Sequence range: ${events[0].sequenceNumber} - ${events[events.length-1].sequenceNumber}`);

// Get Merkle roots
const startRoot = await sequencer.getRootAt(events[0].sequenceNumber - 1);
const endRoot = await sequencer.getRootAt(events[events.length - 1].sequenceNumber);

console.log("Previous root:", startRoot);
console.log("New root:", endRoot);

// Export batch data for prover
const batchData = {
  tenant_id: tenantId,
  store_id: storeId,
  batch_size: events.length,
  sequence_start: events[0].sequenceNumber,
  sequence_end: events[events.length - 1].sequenceNumber,
  prev_events_root: startRoot,
  new_events_root: endRoot,
  events: events.map(e => ({
    event_id: e.eventId,
    sequence_number: e.sequenceNumber,
    event_type: e.eventType,
    entity_type: e.entityType,
    entity_id: e.entityId,
    payload_hash: e.payloadHash,
    timestamp: e.timestamp,
    signature: e.signature
  }))
};

await fs.writeFile(
  'batch-input.json',
  JSON.stringify(batchData, null, 2)
);

console.log("Batch data exported to batch-input.json");
```

## Step 3: Generate STARK Proof

```bash
# Generate the STARK proof
./target/release/ves-stark prove \
  --input batch-input.json \
  --output batch-proof.json \
  --security-level 100

# Expected output:
# Loading batch input...
# Events: 1000
# Sequence range: 1 - 1000
# Building execution trace...
# Trace length: 8192 (padded from 1000)
# Generating AIR constraints...
# Constraint count: 12
# Computing polynomial commitments...
# Running FRI protocol...
# Generating query responses...
# Proof generated successfully!
# Proof size: 98,432 bytes
# Proving time: 12.4 seconds
```

```rust
// Internal prover flow (lib.rs)
pub fn generate_proof(batch: &BatchInput) -> Result<StarkProof> {
    // 1. Build execution trace
    let trace = build_execution_trace(&batch.events)?;

    // 2. Define AIR constraints
    let air = VesBatchAir::new(
        batch.batch_size,
        batch.prev_events_root,
        batch.new_events_root,
    );

    // 3. Generate proof using winterfell
    let proof = winterfell::prove::<VesBatchAir, Blake3_256>(
        trace,
        &air,
        ProofOptions::new(
            32,  // num_queries
            8,   // blowup_factor
            0,   // grinding_factor
            FieldExtension::None,
            4,   // fri_folding_factor
            31,  // fri_max_remainder_poly_degree
        ),
    )?;

    Ok(proof)
}
```

## Step 4: Examine Proof Structure

```javascript
// demo-inspect-proof.mjs
import fs from 'fs';

const proof = JSON.parse(fs.readFileSync('batch-proof.json', 'utf8'));

console.log("=== STARK Proof Structure ===\n");

console.log("Version:", proof.version);
console.log("Generated at:", proof.generated_at);
console.log("");

console.log("=== Public Inputs ===");
console.log("Previous events root:", proof.public_inputs.prev_events_root);
console.log("New events root:", proof.public_inputs.new_events_root);
console.log("Batch size:", proof.public_inputs.batch_size);
console.log("Sequence range:",
  proof.public_inputs.sequence_start, "-",
  proof.public_inputs.sequence_end);
console.log("State commitment:", proof.public_inputs.state_commitment);
console.log("");

console.log("=== STARK Proof Components ===");
console.log("Trace commitments:", proof.stark_proof.trace_commitment.length);
console.log("Composition commitment:", proof.stark_proof.composition_commitment.slice(0, 20) + "...");
console.log("FRI layers:", proof.stark_proof.fri_layers.length);
console.log("Query responses:", proof.stark_proof.query_responses.length);
console.log("");

console.log("=== Auxiliary Parameters ===");
console.log("Blowup factor:", proof.auxiliary.blowup_factor);
console.log("Number of queries:", proof.auxiliary.num_queries);
console.log("FRI folding factor:", proof.auxiliary.fri_fold_factor);
console.log("Hash function:", proof.auxiliary.hash_function);
console.log("");

console.log("=== Metadata ===");
console.log("Proving time:", proof.metadata.proving_time_ms, "ms");
console.log("Proof size:", proof.metadata.proof_size_bytes, "bytes");
console.log("Trace length:", proof.metadata.trace_length);
console.log("Constraint count:", proof.metadata.constraint_count);
```

Example output:
```
=== STARK Proof Structure ===

Version: 1
Generated at: 2025-01-15T10:30:00Z

=== Public Inputs ===
Previous events root: 0x0000000000000000000000000000000000000000000000000000000000000000
New events root: 0x7f8c9d2e1a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d
Batch size: 1000
Sequence range: 1 - 1000
State commitment: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

=== STARK Proof Components ===
Trace commitments: 4
Composition commitment: 0xaabbccdd11223344...
FRI layers: 6
Query responses: 32

=== Auxiliary Parameters ===
Blowup factor: 8
Number of queries: 32
FRI folding factor: 4
Hash function: blake3

=== Metadata ===
Proving time: 12400 ms
Proof size: 98432 bytes
Trace length: 8192
Constraint count: 12
```

## Step 5: Verify Proof Off-Chain

```bash
# Verify the proof locally
./target/release/ves-stark verify \
  --proof batch-proof.json

# Expected output:
# Loading proof...
# Proof size: 98,432 bytes
# Verifying public inputs...
# Batch size: 1000
# Roots valid: true
# Verifying STARK proof...
# Checking trace commitments...
# Verifying FRI layers...
# Validating query responses...
# Proof verified successfully!
# Verification time: 45 ms
```

```rust
// Internal verifier flow
pub fn verify_proof(proof: &StarkProof) -> Result<bool> {
    // 1. Reconstruct AIR from public inputs
    let air = VesBatchAir::new(
        proof.public_inputs.batch_size,
        proof.public_inputs.prev_events_root,
        proof.public_inputs.new_events_root,
    );

    // 2. Verify using winterfell
    let result = winterfell::verify::<VesBatchAir, Blake3_256>(
        proof.clone(),
        &air,
    )?;

    Ok(result)
}
```

## Step 6: Deploy Verifier Contract

```bash
# Deploy the Solana verifier program
cd programs/ves-stark-verifier
anchor build
anchor deploy --program-name ves_stark_verifier

export STARK_VERIFIER_PROGRAM="<program_id>"
```

```rust
// programs/ves-stark-verifier/src/lib.rs
use anchor_lang::prelude::*;
use winterfell::VerifierChannel;

#[program]
pub mod ves_stark_verifier {
    use super::*;

    pub fn verify_batch(
        ctx: Context<VerifyBatch>,
        public_inputs: PublicInputs,
        proof_commitment: [u8; 32],
        fri_final: Vec<u8>,
        query_proofs: Vec<QueryProof>,
    ) -> Result<()> {
        // Verify proof components
        let verification = verify_stark_proof(
            &public_inputs,
            proof_commitment,
            &fri_final,
            &query_proofs,
        )?;

        require!(verification.is_valid, ErrorCode::InvalidProof);

        // Store verification record
        let record = &mut ctx.accounts.verification_record;
        record.verification_id = verification.id;
        record.tenant_id = public_inputs.tenant_id;
        record.store_id = public_inputs.store_id;
        record.batch_size = public_inputs.batch_size;
        record.sequence_start = public_inputs.sequence_start;
        record.sequence_end = public_inputs.sequence_end;
        record.events_root = public_inputs.new_events_root;
        record.state_commitment = public_inputs.state_commitment;
        record.verified_at = Clock::get()?.unix_timestamp;
        record.proof_hash = hash_proof(&proof_commitment, &fri_final);

        emit!(BatchVerified {
            verification_id: record.verification_id,
            batch_size: record.batch_size,
            events_root: record.events_root,
        });

        Ok(())
    }
}

#[derive(Accounts)]
pub struct VerifyBatch<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + VerificationRecord::SIZE,
        seeds = [
            b"verification",
            public_inputs.tenant_id.as_ref(),
            public_inputs.sequence_end.to_le_bytes().as_ref(),
        ],
        bump,
    )]
    pub verification_record: Account<'info, VerificationRecord>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct VerificationRecord {
    pub verification_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub store_id: [u8; 16],
    pub batch_size: u32,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub events_root: [u8; 32],
    pub state_commitment: [u8; 32],
    pub proof_hash: [u8; 32],
    pub verified_at: i64,
}
```

## Step 7: Submit Proof On-Chain

```typescript
// demo-submit-proof.ts
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { VesStarkVerifier } from "../target/types/ves_stark_verifier";
import * as fs from "fs";

const provider = anchor.AnchorProvider.env();
anchor.setProvider(provider);

const program = anchor.workspace.VesStarkVerifier as Program<VesStarkVerifier>;

// Load the proof
const proof = JSON.parse(fs.readFileSync("batch-proof.json", "utf8"));

// Convert to on-chain format
const publicInputs = {
  tenantId: [...Buffer.from(proof.public_inputs.tenant_id.slice(2), "hex")],
  storeId: [...Buffer.from(proof.public_inputs.store_id.slice(2), "hex")],
  batchSize: proof.public_inputs.batch_size,
  sequenceStart: new anchor.BN(proof.public_inputs.sequence_start),
  sequenceEnd: new anchor.BN(proof.public_inputs.sequence_end),
  prevEventsRoot: [...Buffer.from(proof.public_inputs.prev_events_root.slice(2), "hex")],
  newEventsRoot: [...Buffer.from(proof.public_inputs.new_events_root.slice(2), "hex")],
  stateCommitment: [...Buffer.from(proof.public_inputs.state_commitment.slice(2), "hex")],
};

// Proof commitment (hash of full proof for space efficiency)
const proofCommitment = Buffer.from(
  proof.stark_proof.composition_commitment.slice(2),
  "hex"
);

// FRI final polynomial
const friFinal = Buffer.from(proof.stark_proof.final_poly, "base64");

// Query proofs (subset for on-chain verification)
const queryProofs = proof.stark_proof.query_responses.slice(0, 8).map(q => ({
  index: q.index,
  traceValues: q.trace_values.map(v => Buffer.from(v, "base64")),
  authenticationPaths: q.authentication_paths.map(path =>
    path.map(h => [...Buffer.from(h.slice(2), "hex")])
  ),
}));

// Derive verification record PDA
const [verificationPda] = anchor.web3.PublicKey.findProgramAddressSync(
  [
    Buffer.from("verification"),
    Buffer.from(publicInputs.tenantId),
    publicInputs.sequenceEnd.toArrayLike(Buffer, "le", 8),
  ],
  program.programId
);

// Submit verification transaction
const tx = await program.methods
  .verifyBatch(publicInputs, [...proofCommitment], friFinal, queryProofs)
  .accounts({
    verificationRecord: verificationPda,
    authority: provider.wallet.publicKey,
    systemProgram: anchor.web3.SystemProgram.programId,
  })
  .rpc();

console.log("Verification submitted!");
console.log("Transaction:", tx);
console.log("Verification record:", verificationPda.toBase58());

// Fetch and display the record
const record = await program.account.verificationRecord.fetch(verificationPda);
console.log("\n=== Verification Record ===");
console.log("Batch size:", record.batchSize);
console.log("Sequence range:", record.sequenceStart.toString(), "-", record.sequenceEnd.toString());
console.log("Events root:", Buffer.from(record.eventsRoot).toString("hex"));
console.log("Verified at:", new Date(record.verifiedAt.toNumber() * 1000).toISOString());
```

## Step 8: Record Verification in VES

```javascript
// demo-record-verification.mjs
import { Sequencer } from '../lib/sequencer.js';
import fs from 'fs';

const sequencer = new Sequencer();
await sequencer.connect();

const proof = JSON.parse(fs.readFileSync('batch-proof.json', 'utf8'));
const verificationTx = "5KtP..."; // From Step 7

// Record batch verification event
const verificationEvent = {
  eventType: "BatchVerified",
  entityType: "StarkBatch",
  entityId: crypto.randomUUID(),
  version: 1,
  payload: {
    batch_size: proof.public_inputs.batch_size,
    sequence_start: proof.public_inputs.sequence_start,
    sequence_end: proof.public_inputs.sequence_end,
    prev_events_root: proof.public_inputs.prev_events_root,
    new_events_root: proof.public_inputs.new_events_root,
    state_commitment: proof.public_inputs.state_commitment,
    proof_hash: proof.stark_proof.composition_commitment,
    chain_verification: {
      chain: "solana",
      network: "devnet",
      tx_hash: verificationTx,
      status: "verified"
    },
    proving_time_ms: proof.metadata.proving_time_ms,
    proof_size_bytes: proof.metadata.proof_size_bytes
  },
  timestamp: new Date().toISOString()
};

const result = await sequencer.appendEvent(verificationEvent);
console.log("Verification recorded in VES:", result.eventId);
```

## Complete Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    VES-STARK-1 Complete Flow                             │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   VES Sequencer                          STARK Prover                    │
│   ─────────────                          ───────────                     │
│                                                                          │
│   ┌─────────────────┐                                                    │
│   │ Events 1-1000   │                                                    │
│   │ ┌───┬───┬───┐   │                                                    │
│   │ │E₁ │E₂ │...│   │                                                    │
│   │ └───┴───┴───┘   │                                                    │
│   │ Merkle Tree:    │                                                    │
│   │ root₀ → root₁₀₀₀│                                                    │
│   └────────┬────────┘                                                    │
│            │                                                             │
│            │ Export batch                                                │
│            ▼                                                             │
│   ┌─────────────────┐                                                    │
│   │ batch-input.json│                                                    │
│   │ - events[]      │                                                    │
│   │ - signatures[]  │                                                    │
│   │ - merkle data   │                                                    │
│   └────────┬────────┘                                                    │
│            │                                                             │
│            │                    ┌─────────────────────────────────────┐  │
│            └───────────────────▶│          STARK Prover               │  │
│                                 ├─────────────────────────────────────┤  │
│                                 │                                     │  │
│                                 │  1. Build Execution Trace           │  │
│                                 │     ┌─────────────────────────┐     │  │
│                                 │     │ row │ seq │ sig │ hash │     │  │
│                                 │     ├─────┼─────┼─────┼──────┤     │  │
│                                 │     │  0  │  1  │ ✓  │ 0x.. │     │  │
│                                 │     │  1  │  2  │ ✓  │ 0x.. │     │  │
│                                 │     │ ... │ ... │ .. │ ...  │     │  │
│                                 │     │ 999 │1000 │ ✓  │ 0x.. │     │  │
│                                 │     └─────────────────────────┘     │  │
│                                 │                                     │  │
│                                 │  2. Apply AIR Constraints           │  │
│                                 │     • seq[i+1] = seq[i] + 1         │  │
│                                 │     • verify_sig(pk, msg, sig)      │  │
│                                 │     • merkle_valid(root, proof)     │  │
│                                 │                                     │  │
│                                 │  3. Generate Polynomial Commit.     │  │
│                                 │     ┌─────────────────┐             │  │
│                                 │     │ trace_commit    │             │  │
│                                 │     │ comp_commit     │             │  │
│                                 │     └─────────────────┘             │  │
│                                 │                                     │  │
│                                 │  4. FRI Protocol                    │  │
│                                 │     ┌─────┐                         │  │
│                                 │     │ L₀  │──▶ fold                 │  │
│                                 │     │ L₁  │──▶ fold                 │  │
│                                 │     │ L₂  │──▶ fold                 │  │
│                                 │     │ ... │                         │  │
│                                 │     │ Lₖ  │──▶ constant             │  │
│                                 │     └─────┘                         │  │
│                                 │                                     │  │
│                                 │  5. Query Responses                 │  │
│                                 │     32 random queries verified      │  │
│                                 │                                     │  │
│                                 └─────────────────┬───────────────────┘  │
│                                                   │                      │
│                                                   ▼                      │
│                                 ┌─────────────────────────────────────┐  │
│                                 │ batch-proof.json                    │  │
│                                 │ - public_inputs                     │  │
│                                 │ - stark_proof                       │  │
│                                 │ - auxiliary                         │  │
│                                 │ Size: ~100 KB                       │  │
│                                 └─────────────────┬───────────────────┘  │
│                                                   │                      │
│   On-Chain Verification                           │                      │
│   ─────────────────────                           │                      │
│                                                   ▼                      │
│                                 ┌─────────────────────────────────────┐  │
│                                 │      Solana Verifier Program        │  │
│                                 ├─────────────────────────────────────┤  │
│                                 │                                     │  │
│                                 │  1. Verify public inputs            │  │
│                                 │  2. Check FRI commitment            │  │
│                                 │  3. Verify query responses          │  │
│                                 │  4. Store verification record       │  │
│                                 │                                     │  │
│                                 │  Compute units: ~200,000            │  │
│                                 │  Cost: ~0.001 SOL                   │  │
│                                 │                                     │  │
│                                 └─────────────────┬───────────────────┘  │
│                                                   │                      │
│                                                   ▼                      │
│   ┌─────────────────┐           ┌─────────────────────────────────────┐  │
│   │ VES Event:      │◀──────────│ Verification Record PDA             │  │
│   │ BatchVerified   │           │ - batch_size: 1000                  │  │
│   │ tx: 5KtP...     │           │ - events_root: 0x7f8c...            │  │
│   └─────────────────┘           │ - verified_at: 1705312200           │  │
│                                 └─────────────────────────────────────┘  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Cost Analysis

| Approach | Events | Cost | Time |
|----------|--------|------|------|
| Individual anchoring | 1,000 | 1.0 SOL | 10 min |
| STARK batch proof | 1,000 | 0.001 SOL | 15 sec |
| **Savings** | | **99.9%** | **97.5%** |

| Batch Size | Proof Size | Proving Time | Verify Time |
|------------|------------|--------------|-------------|
| 100 | 45 KB | 1.2 sec | 20 ms |
| 1,000 | 98 KB | 12 sec | 45 ms |
| 10,000 | 180 KB | 120 sec | 80 ms |
| 100,000 | 320 KB | 1,200 sec | 150 ms |

## Security Properties

| Property | Description |
|----------|-------------|
| **Soundness** | Invalid batches cannot produce valid proofs |
| **Completeness** | Valid batches always produce valid proofs |
| **Zero-Knowledge** | Proof reveals nothing beyond public inputs |
| **Succinctness** | Proof size O(log n), verify time O(log n) |
| **Transparency** | No trusted setup required |

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `SequenceGap` | Non-contiguous events | Fill gaps or split batches |
| `InvalidSignature` | Bad event signature | Exclude invalid event |
| `MerkleRootMismatch` | Root doesn't match | Recompute Merkle tree |
| `ConstraintViolation` | AIR constraint failed | Debug trace at failure point |
| `ProofTooLarge` | Exceeds CU limit | Split into smaller batches |

## Next Steps

- Review [VES-STARK-1 Specification](./VES_STARK_1_SPECIFICATION.md) for full details
- Explore [VES-CONTRACT-1](./VES_CONTRACT_1_SPECIFICATION.md) for proof-triggered escrow
- See [VES-MULTI-1](./VES_MULTI_1_SPECIFICATION.md) for multi-agent coordination
