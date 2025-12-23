# Verifiable Event Sync (VES) System Overview

A complete zero-knowledge commerce infrastructure enabling AI agents to interact with cryptographic verification, STARK proofs, and on-chain anchoring.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              AI Agent Commerce Platform                              │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │  AI Agent   │    │  AI Agent   │    │  AI Agent   │    │  AI Agent   │         │
│  │  (Orders)   │    │ (Inventory) │    │  (Payments) │    │  (Returns)  │         │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘         │
│         │                  │                  │                  │                 │
│         └──────────────────┴────────┬─────────┴──────────────────┘                 │
│                                     │                                              │
│                                     ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                        StateSet CLI (MCP Server)                            │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │  │
│  │  │   Outbox    │  │  Ed25519    │  │    HPKE     │  │   Event Capture     │ │  │
│  │  │  (SQLite)   │  │   Signing   │  │  Encryption │  │   & Serialization   │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │  │
│  └────────────────────────────────────┬────────────────────────────────────────┘  │
│                                       │                                            │
└───────────────────────────────────────┼────────────────────────────────────────────┘
                                        │ VES Protocol v1.0
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                            stateset-sequencer (Rust)                                │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐  │
│  │  Event Ingest   │  │   Sequencing    │  │  Merkle Trees   │  │  Commitments  │  │
│  │  (REST/gRPC)    │  │  (Deterministic)│  │  (rs_merkle)    │  │   (Batches)   │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  └───────┬───────┘  │
│           │                    │                    │                   │          │
│           └────────────────────┴────────────────────┴───────────────────┘          │
│                                         │                                          │
│  ┌──────────────────────────────────────┴──────────────────────────────────────┐   │
│  │                          Event Store (PostgreSQL/SQLite)                    │   │
│  └──────────────────────────────────────────────────────────────────────────────┘  │
│                                         │                                          │
└─────────────────────────────────────────┼──────────────────────────────────────────┘
                                          │ Batch Events
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                             stateset-stark (Rust)                                   │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                              STARK Prover                                    │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │   │
│  │  │  Witness    │  │   Trace     │  │   AIR       │  │   Winterfell        │ │   │
│  │  │  Builder    │  │  Generator  │  │ Constraints │  │   Prover            │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                            Supported Policies                                │   │
│  │  • aml.threshold    - Proves amount < threshold (AML compliance)            │   │
│  │  • order_total.cap  - Proves amount <= cap (Order limits)                   │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                         │                                          │
│                                         │ STARK Proofs                             │
│                                         ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                              STARK Verifier                                  │   │
│  │  • Proof verification in ~600µs                                              │   │
│  │  • Public inputs validation                                                  │   │
│  │  • Policy compliance checking                                                │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                         │                                          │
└─────────────────────────────────────────┼──────────────────────────────────────────┘
                                          │ Verified Proofs
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              set/anchor (Rust)                                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                     │
│  │  Sequencer      │  │   Registry      │  │   Health        │                     │
│  │  API Client     │  │   Client        │  │   Monitoring    │                     │
│  └────────┬────────┘  └────────┬────────┘  └─────────────────┘                     │
│           │                    │                                                    │
│           └────────────────────┴─────────────────────────┐                         │
│                                                          │                         │
└──────────────────────────────────────────────────────────┼─────────────────────────┘
                                                           │ On-chain TX
                                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           Set L2 (EVM-Compatible Chain)                             │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────────┐   │
│  │                          SetRegistry.sol                                     │   │
│  │                                                                              │   │
│  │  struct BatchCommitment {                                                    │   │
│  │      bytes32 eventsRoot;      // Merkle root of events                      │   │
│  │      bytes32 prevStateRoot;   // Previous state                             │   │
│  │      bytes32 newStateRoot;    // New state after batch                      │   │
│  │      uint64 sequenceStart;    // First sequence number                      │   │
│  │      uint64 sequenceEnd;      // Last sequence number                       │   │
│  │      uint32 eventCount;       // Events in batch                            │   │
│  │  }                                                                          │   │
│  │                                                                              │   │
│  │  struct StarkProofCommitment {                                              │   │
│  │      bytes32 proofHash;       // Hash of STARK proof                        │   │
│  │      bytes32 policyHash;      // Policy used                                │   │
│  │      bool allCompliant;       // Compliance status                          │   │
│  │  }                                                                          │   │
│  │                                                                              │   │
│  │  Functions:                                                                  │   │
│  │  • commitBatch()      - Anchor batch commitment                             │   │
│  │  • commitStarkProof() - Anchor STARK proof                                  │   │
│  │  • verifyInclusion()  - Verify event in batch                               │   │
│  │                                                                              │   │
│  └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

### Step 1: AI Agent Creates Event

```javascript
// AI Agent creates a commerce event through the CLI
const event = {
  entityType: 'order',
  entityId: 'order-001',
  eventType: 'OrderCreated',
  payload: {
    orderId: 'order-001',
    customerId: 'customer-001',
    items: [{ sku: 'WIDGET-001', quantity: 2, price: 29.99 }],
    total: 59.98
  }
};

// CLI captures, signs, and encrypts the event
outbox.append(event);
```

### Step 2: Event Signing & Encryption (CLI)

The CLI performs VES v1.0 protocol operations:

1. **Payload Hash**: `SHA-256(domain_prefix || canonical_json(payload))`
2. **Ed25519 Signature**: Signs event envelope with agent's private key
3. **HPKE Encryption**: Encrypts payload for authorized recipients
4. **Cipher Hash**: `SHA-256(domain_prefix || ciphertext)`

```
Event Envelope:
├── eventId: UUID
├── vesVersion: 1
├── payloadKind: 1 (encrypted)
├── payloadPlainHash: "0x..."
├── payloadCipherHash: "0x..."
├── agentKeyId: 1
├── agentSignature: "0x..."
└── payloadEncrypted: { ... }
```

### Step 3: Sequencing (stateset-sequencer)

The sequencer:
1. Validates agent signature
2. Assigns deterministic sequence number
3. Adds event to Merkle tree
4. Creates batch when threshold reached

```
Sequenced Event:
├── envelope: { ... }
├── sequenceNumber: 42
├── sequencedAt: "2024-12-22T20:15:00Z"
└── receiptHash: "0x..."
```

### Step 4: STARK Proof Generation (stateset-stark)

For each batch, generate a STARK proof:

```bash
# Prove compliance: amount < 10000 (AML threshold)
ves-stark prove \
  --amount 5000 \
  --limit 10000 \
  --policy aml.threshold \
  --inputs public_inputs.json \
  --output proof.json
```

**Proof Characteristics:**
- Proof Size: ~36KB (individual), ~53KB (batch)
- Proving Time: ~20-25ms
- Verification Time: ~600µs
- Security Level: 128-bit

### Step 5: On-Chain Anchoring (set/anchor → SetRegistry)

The anchor service submits to Set L2:

```solidity
// SetRegistry.commitBatch()
commitBatch(
    batchId,           // Unique batch identifier
    tenantId,          // Tenant UUID as bytes32
    storeId,           // Store UUID as bytes32
    eventsRoot,        // Merkle root of events
    prevStateRoot,     // State before batch
    newStateRoot,      // State after batch
    sequenceStart,     // 0
    sequenceEnd,       // 7
    eventCount         // 8
);

// SetRegistry.commitStarkProof()
commitStarkProof(
    batchId,
    proofHash,         // SHA-256 of STARK proof
    policyHash,        // Policy identifier hash
    policyLimit,       // 10000
    allCompliant,      // true
    proofSize,         // 53074
    provingTimeMs      // 25
);
```

### Step 6: Verification by Other Agents

Any AI agent can verify:

1. **Event Inclusion**: Merkle proof against on-chain root
2. **Compliance**: STARK proof verification
3. **State Transition**: Verify prev_state → new_state

```bash
# Verify a STARK proof
ves-stark verify \
  --proof proof.json \
  --inputs public_inputs.json \
  --limit 10000 \
  --policy aml.threshold

# Output: Proof VALID (verified in 622.133µs)
```

## Repository Structure

| Repository | Path | Description |
|------------|------|-------------|
| **stateset-sequencer** | `/home/dom/icommerce-app/stateset-sequencer` | VES protocol sequencer |
| **stateset-stark** | `/home/dom/icommerce-app/stateset-stark` | STARK prover/verifier |
| **set** | `/home/dom/icommerce-app/set` | L2 chain & anchor service |
| **CLI** | `/home/dom/stateset-icommerce/cli` | AI agent MCP server |

## Crate Structure (stateset-stark)

```
stateset-stark/crates/
├── ves-stark-primitives/   # Field arithmetic, Rescue hash
├── ves-stark-air/          # AIR constraints for policies
├── ves-stark-prover/       # Witness & proof generation
├── ves-stark-verifier/     # Proof verification
├── ves-stark-batch/        # zkRollup batch proofs
├── ves-stark-cli/          # Command-line interface
└── ves-stark-client/       # HTTP client for sequencer
```

## CLI Commands

### STARK Prover CLI

```bash
# Generate public inputs
ves-stark gen-inputs --limit 10000 --policy aml.threshold -o inputs.json

# Generate compliance proof
ves-stark prove --amount 5000 --limit 10000 --policy aml.threshold \
  --inputs inputs.json --output proof.json --json

# Verify proof
ves-stark verify --proof proof.json --inputs inputs.json \
  --limit 10000 --policy aml.threshold

# Inspect proof metadata
ves-stark inspect --proof proof.json

# Run benchmark
ves-stark benchmark -n 10 --max-amount 10000 --limit 10000

# Generate batch proof (zkRollup style)
ves-stark batch-prove -n 8 --limit 10000 --output batch_proof.json

# Run sequencer simulation
ves-stark sequencer -n 16 --batch-size 8 --limit 10000 \
  --output-dir ./proofs
```

### Sync CLI

```bash
# Initialize sync configuration
stateset-sync init

# Generate agent keys
stateset-sync keys:generate

# Push events to sequencer
stateset-sync push

# Pull events from sequencer
stateset-sync pull

# Show sync status
stateset-sync status
```

## Performance Metrics

| Operation | Time | Size |
|-----------|------|------|
| Individual Proof Generation | ~20ms | ~36KB |
| Batch Proof (8 events) | ~25ms | ~53KB |
| Proof Verification | ~600µs | - |
| Merkle Proof Verification | <1ms | ~1KB |

## Security Properties

1. **Privacy**: Event payloads encrypted with HPKE
2. **Authenticity**: Ed25519 signatures on all events
3. **Ordering**: Deterministic sequencing prevents reordering
4. **Compliance**: Zero-knowledge proofs for policy enforcement
5. **Finality**: On-chain anchoring provides immutability
6. **Verifiability**: Anyone can verify proofs without trusted setup

## Running the Demo

```bash
# Run the complete demonstration
./run-ves-demo.sh
```

See `run-ves-demo.sh` for the full demonstration script.
