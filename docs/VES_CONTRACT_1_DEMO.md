# VES-CONTRACT-1 Smart Contract Integration Demo

This walkthrough demonstrates VES-CONTRACT-1 smart contract integration for trustless escrow and on-chain VES proof verification.

## Prerequisites

- Solana CLI tools installed
- Anchor framework 0.29+
- Node.js 18+
- Running local validator or devnet access

## Demo Scenario: E-Commerce Escrow

Alice (buyer) purchases a product from Bob (seller) with funds held in escrow until delivery is confirmed via VES events.

```
┌─────────────────────────────────────────────────────────────────┐
│                    E-Commerce Escrow Flow                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Order Created        2. Payment Escrowed                    │
│  ┌─────────────┐         ┌─────────────────────┐               │
│  │ VES Event:  │         │ Solana Program:     │               │
│  │ OrderCreated│────────▶│ create_escrow()     │               │
│  │ ORD-001234  │         │ 100 USDC locked     │               │
│  └─────────────┘         └─────────────────────┘               │
│                                    │                            │
│  3. Order Shipped                  │                            │
│  ┌─────────────┐                   │                            │
│  │ VES Event:  │                   │                            │
│  │ OrderShipped│                   │                            │
│  │ Tracking:   │                   │                            │
│  │ 1Z999AA1... │                   │                            │
│  └─────────────┘                   │                            │
│                                    │                            │
│  4. Delivery Confirmed             ▼                            │
│  ┌─────────────┐         ┌─────────────────────┐               │
│  │ VES Event:  │         │ Merkle Proof        │               │
│  │ Delivery    │────────▶│ Generated           │               │
│  │ Confirmed   │         │ for DeliveryConf.   │               │
│  └─────────────┘         └─────────────────────┘               │
│                                    │                            │
│                                    ▼                            │
│  5. Escrow Released      ┌─────────────────────┐               │
│  ┌─────────────┐         │ Solana Program:     │               │
│  │ Bob receives│◀────────│ release_escrow()    │               │
│  │ 100 USDC    │         │ Proof verified!     │               │
│  └─────────────┘         └─────────────────────┘               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Step 1: Setup Environment

```bash
# Clone the VES contracts
cd /home/dom/icommerce-app/stateset-sequencer

# Start local Solana validator
solana-test-validator --reset &

# Configure for localhost
solana config set --url localhost
```

## Step 2: Deploy VES Contracts

```bash
# Build the Anchor programs
cd programs/ves-anchor
anchor build

# Deploy VES Anchor program (root commitment storage)
anchor deploy --program-name ves_anchor

# Deploy VES Escrow program
anchor deploy --program-name ves_escrow

# Note the program IDs
export VES_ANCHOR_PROGRAM="<program_id_1>"
export VES_ESCROW_PROGRAM="<program_id_2>"
```

## Step 3: Initialize VES Anchor State

```typescript
// demo-contract-init.ts
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { VesAnchor } from "../target/types/ves_anchor";

const provider = anchor.AnchorProvider.env();
anchor.setProvider(provider);

const program = anchor.workspace.VesAnchor as Program<VesAnchor>;

// Initialize tenant state
const tenantId = "550e8400-e29b-41d4-a716-446655440000";
const storeId = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

const [tenantPda] = anchor.web3.PublicKey.findProgramAddressSync(
  [
    Buffer.from("ves-tenant"),
    Buffer.from(tenantId.replace(/-/g, ""), "hex"),
  ],
  program.programId
);

// Initialize with genesis root
const genesisRoot = Buffer.alloc(32);
await program.methods
  .initializeTenant(
    [...Buffer.from(tenantId.replace(/-/g, ""), "hex")],
    [...Buffer.from(storeId.replace(/-/g, ""), "hex")],
    [...genesisRoot]
  )
  .accounts({
    tenant: tenantPda,
    authority: provider.wallet.publicKey,
    systemProgram: anchor.web3.SystemProgram.programId,
  })
  .rpc();

console.log("Tenant initialized:", tenantPda.toBase58());
```

## Step 4: Create VES Events for Order

```javascript
// demo-create-order.mjs
import { Sequencer } from '../lib/sequencer.js';
import { createHash } from 'crypto';

const sequencer = new Sequencer();
await sequencer.connect();

// Create order event
const orderEvent = {
  eventType: "OrderCreated",
  entityType: "Order",
  entityId: "ORD-2025-001234",
  version: 1,
  payload: {
    buyer: "Alice123",
    buyerWallet: "AaL1ceWa11etAddress111111111111111111111111",
    seller: "Bob456",
    sellerWallet: "B0bSe11erWa11etAddress11111111111111111111",
    items: [
      {
        sku: "WIDGET-001",
        name: "Premium Widget",
        quantity: 1,
        unitPrice: "100.00",
        currency: "USD"
      }
    ],
    totalAmount: "100.00",
    currency: "USD",
    shippingAddress: {
      street: "123 Main St",
      city: "San Francisco",
      state: "CA",
      zip: "94102",
      country: "US"
    }
  },
  timestamp: new Date().toISOString()
};

const result = await sequencer.appendEvent(orderEvent);
console.log("Order event created:", {
  eventId: result.eventId,
  sequenceNumber: result.sequenceNumber,
  merkleRoot: result.merkleRoot
});
```

## Step 5: Create Escrow on Solana

```typescript
// demo-create-escrow.ts
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { VesEscrow } from "../target/types/ves_escrow";
import {
  createMint,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

const provider = anchor.AnchorProvider.env();
anchor.setProvider(provider);

const program = anchor.workspace.VesEscrow as Program<VesEscrow>;

// Setup token accounts (using USDC-like token for demo)
const usdcMint = await createMint(
  provider.connection,
  provider.wallet.payer,
  provider.wallet.publicKey,
  null,
  6 // 6 decimals like USDC
);

// Mint tokens to buyer
const buyerTokenAccount = await getOrCreateAssociatedTokenAccount(
  provider.connection,
  provider.wallet.payer,
  usdcMint,
  provider.wallet.publicKey // buyer is demo wallet
);

await mintTo(
  provider.connection,
  provider.wallet.payer,
  usdcMint,
  buyerTokenAccount.address,
  provider.wallet.publicKey,
  100_000_000 // 100 USDC
);

// Create escrow
const escrowId = Buffer.alloc(32);
escrowId.write("ORD-2025-001234", 0, "utf8");
const escrowIdHash = createHash('sha256').update(escrowId).digest();

const [escrowPda] = anchor.web3.PublicKey.findProgramAddressSync(
  [Buffer.from("escrow"), escrowIdHash],
  program.programId
);

const [escrowVaultPda] = anchor.web3.PublicKey.findProgramAddressSync(
  [Buffer.from("escrow-vault"), escrowIdHash],
  program.programId
);

// Seller's wallet
const sellerWallet = new anchor.web3.PublicKey(
  "B0bSe11erWa11etAddress11111111111111111111"
);

await program.methods
  .createEscrow(
    [...escrowIdHash],
    new anchor.BN(100_000_000), // 100 USDC
    "DeliveryConfirmed",        // Release event type
    "Order",                     // Entity type
    "ORD-2025-001234",          // Entity ID
    new anchor.BN(7 * 24 * 3600) // 7 day timeout
  )
  .accounts({
    escrow: escrowPda,
    escrowVault: escrowVaultPda,
    buyer: provider.wallet.publicKey,
    seller: sellerWallet,
    tokenMint: usdcMint,
    buyerTokenAccount: buyerTokenAccount.address,
    tokenProgram: TOKEN_PROGRAM_ID,
    systemProgram: anchor.web3.SystemProgram.programId,
  })
  .rpc();

console.log("Escrow created:", escrowPda.toBase58());
console.log("Amount locked: 100 USDC");
console.log("Release condition: DeliveryConfirmed for ORD-2025-001234");
```

## Step 6: Simulate Order Fulfillment Events

```javascript
// demo-fulfill-order.mjs
import { Sequencer } from '../lib/sequencer.js';

const sequencer = new Sequencer();
await sequencer.connect();

// Seller ships the order
const shippedEvent = {
  eventType: "OrderShipped",
  entityType: "Order",
  entityId: "ORD-2025-001234",
  version: 2,
  payload: {
    carrier: "UPS",
    trackingNumber: "1Z999AA10123456784",
    shippedAt: new Date().toISOString(),
    estimatedDelivery: new Date(Date.now() + 3*24*60*60*1000).toISOString()
  },
  timestamp: new Date().toISOString()
};

const shipResult = await sequencer.appendEvent(shippedEvent);
console.log("Order shipped:", shipResult.eventId);

// Simulate delivery after delay
await new Promise(resolve => setTimeout(resolve, 2000));

// Buyer confirms delivery
const deliveredEvent = {
  eventType: "DeliveryConfirmed",
  entityType: "Order",
  entityId: "ORD-2025-001234",
  version: 3,
  payload: {
    confirmedBy: "buyer",
    confirmedAt: new Date().toISOString(),
    signedBy: "Alice Smith",
    condition: "good"
  },
  timestamp: new Date().toISOString()
};

const deliverResult = await sequencer.appendEvent(deliveredEvent);
console.log("Delivery confirmed:", deliverResult.eventId);
console.log("New Merkle root:", deliverResult.merkleRoot);

// Get the event index for proof generation
console.log("Event sequence number:", deliverResult.sequenceNumber);
```

## Step 7: Generate Merkle Proof

```javascript
// demo-generate-proof.mjs
import { MerkleTree } from '../lib/merkle.js';
import { Sequencer } from '../lib/sequencer.js';

const sequencer = new Sequencer();
await sequencer.connect();

// Get the DeliveryConfirmed event
const event = await sequencer.getEvent("DeliveryConfirmed", "Order", "ORD-2025-001234");

// Generate Merkle proof
const proof = await sequencer.generateMerkleProof(event.eventId);

console.log("VES Proof generated:");
console.log(JSON.stringify({
  event_hash: proof.eventHash,
  merkle_root: proof.merkleRoot,
  proof_path: proof.path,
  event: {
    event_id: event.eventId,
    event_type: event.eventType,
    entity_type: event.entityType,
    entity_id: event.entityId,
    payload_hash: proof.payloadHash,
    timestamp: event.timestamp
  }
}, null, 2));

// Save proof for escrow release
await fs.writeFile(
  'delivery-proof.json',
  JSON.stringify(proof, null, 2)
);
```

Example proof output:

```json
{
  "event_hash": "0x7f8c9d2e1a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d",
  "merkle_root": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "proof_path": [
    {
      "position": "right",
      "hash": "0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
    },
    {
      "position": "left",
      "hash": "0x5566778899aabbcc5566778899aabbcc5566778899aabbcc5566778899aabbcc"
    },
    {
      "position": "right",
      "hash": "0xddeeff0011223344ddeeff0011223344ddeeff0011223344ddeeff0011223344"
    }
  ],
  "event": {
    "event_id": "evt_delivery_001",
    "event_type": "DeliveryConfirmed",
    "entity_type": "Order",
    "entity_id": "ORD-2025-001234",
    "payload_hash": "0x9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0",
    "timestamp": "2025-01-15T14:30:00Z"
  }
}
```

## Step 8: Release Escrow with Proof

```typescript
// demo-release-escrow.ts
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { VesEscrow } from "../target/types/ves_escrow";
import * as fs from "fs";

const provider = anchor.AnchorProvider.env();
anchor.setProvider(provider);

const program = anchor.workspace.VesEscrow as Program<VesEscrow>;

// Load the proof
const proof = JSON.parse(fs.readFileSync("delivery-proof.json", "utf8"));

// Reconstruct escrow PDA
const escrowId = Buffer.alloc(32);
escrowId.write("ORD-2025-001234", 0, "utf8");
const escrowIdHash = createHash('sha256').update(escrowId).digest();

const [escrowPda] = anchor.web3.PublicKey.findProgramAddressSync(
  [Buffer.from("escrow"), escrowIdHash],
  program.programId
);

const [escrowVaultPda] = anchor.web3.PublicKey.findProgramAddressSync(
  [Buffer.from("escrow-vault"), escrowIdHash],
  program.programId
);

// Get VES anchor PDA for root verification
const tenantId = "550e8400-e29b-41d4-a716-446655440000";
const [tenantPda] = anchor.web3.PublicKey.findProgramAddressSync(
  [
    Buffer.from("ves-tenant"),
    Buffer.from(tenantId.replace(/-/g, ""), "hex"),
  ],
  vesAnchorProgram.programId
);

// Convert proof to on-chain format
const vesProof = {
  eventHash: [...Buffer.from(proof.event_hash.slice(2), "hex")],
  eventType: proof.event.event_type,
  entityType: proof.event.entity_type,
  entityId: proof.event.entity_id,
  payloadHash: [...Buffer.from(proof.event.payload_hash.slice(2), "hex")],
  timestamp: new anchor.BN(new Date(proof.event.timestamp).getTime() / 1000),
  merkleProof: proof.proof_path.map(step => ({
    position: step.position === "left" ? { left: {} } : { right: {} },
    hash: [...Buffer.from(step.hash.slice(2), "hex")],
  })),
};

// Release escrow
const tx = await program.methods
  .releaseEscrow(vesProof)
  .accounts({
    escrow: escrowPda,
    escrowVault: escrowVaultPda,
    seller: sellerWallet,
    sellerTokenAccount: sellerTokenAccount.address,
    vesTenant: tenantPda,
    vesAnchorProgram: vesAnchorProgram.programId,
    tokenProgram: TOKEN_PROGRAM_ID,
  })
  .rpc();

console.log("Escrow released!");
console.log("Transaction:", tx);
console.log("Seller received 100 USDC");
```

## Step 9: Verify on Chain

```bash
# Check escrow account state
solana account <escrow_pda> --output json

# Check transaction logs
solana confirm -v <tx_signature>
```

Expected output:
```
Transaction executed successfully
Log Messages:
  Program <escrow_program> invoke [1]
  Program log: Instruction: ReleaseEscrow
  Program log: Verifying VES proof...
  Program log: Event type matches: DeliveryConfirmed
  Program log: Entity matches: Order/ORD-2025-001234
  Program log: Merkle proof valid
  Program log: Root verified against VES Anchor
  Program log: Releasing 100000000 tokens to seller
  Program <token_program> invoke [2]
  Program <token_program> success
  Program log: Escrow released successfully
  Program <escrow_program> success
```

## Complete Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    VES-CONTRACT-1 Complete Flow                          │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Off-Chain (VES)                        On-Chain (Solana)               │
│   ──────────────                         ────────────────                │
│                                                                          │
│   ┌─────────────────┐                                                    │
│   │  OrderCreated   │─────────────────────┐                              │
│   │  seq: 100       │                     │                              │
│   └─────────────────┘                     │                              │
│          │                                │                              │
│          │ append                         │                              │
│          ▼                                ▼                              │
│   ┌─────────────────┐              ┌─────────────────┐                   │
│   │  Merkle Tree    │              │  create_escrow  │                   │
│   │  Updated        │              │  100 USDC       │                   │
│   │  root: 0xabc... │              │  locked         │                   │
│   └─────────────────┘              └─────────────────┘                   │
│          │                                │                              │
│          │                                │                              │
│   ┌─────────────────┐                     │                              │
│   │  OrderShipped   │                     │                              │
│   │  seq: 101       │                     │                              │
│   └─────────────────┘                     │                              │
│          │                                │                              │
│          │ append                         │                              │
│          ▼                                │                              │
│   ┌─────────────────┐                     │                              │
│   │  Merkle Tree    │                     │                              │
│   │  Updated        │                     │                              │
│   │  root: 0xdef... │                     │                              │
│   └─────────────────┘                     │                              │
│          │                                │                              │
│          │                                │                              │
│   ┌─────────────────┐                     │                              │
│   │ DeliveryConfirm │                     │                              │
│   │  seq: 102       │                     │                              │
│   └─────────────────┘                     │                              │
│          │                                │                              │
│          │ append                         │                              │
│          ▼                                │                              │
│   ┌─────────────────┐                     │                              │
│   │  Merkle Tree    │                     │                              │
│   │  Updated        │◄────────────────────┘                              │
│   │  root: 0x123... │     anchor_root()                                  │
│   └─────────────────┘                                                    │
│          │                                                               │
│          │ generate proof                                                │
│          ▼                                                               │
│   ┌─────────────────┐              ┌─────────────────┐                   │
│   │  Merkle Proof   │─────────────▶│ release_escrow  │                   │
│   │  for event 102  │              │ verify proof    │                   │
│   │  path: [...]    │              │ check root      │                   │
│   └─────────────────┘              │ transfer funds  │                   │
│                                    └─────────────────┘                   │
│                                           │                              │
│                                           ▼                              │
│                                    ┌─────────────────┐                   │
│                                    │  Seller receives│                   │
│                                    │  100 USDC       │                   │
│                                    └─────────────────┘                   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Security Considerations

1. **Root Anchoring**: Merkle roots must be anchored on-chain before proofs can be verified
2. **Timeout Protection**: Escrows have automatic timeout for buyer protection
3. **Event Type Matching**: Contract verifies exact event type matches release conditions
4. **Replay Prevention**: Each escrow can only be released once
5. **Authority Checks**: Only designated parties can interact with escrow

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `InvalidMerkleProof` | Proof doesn't verify against root | Re-generate proof with correct events |
| `EventTypeMismatch` | Wrong event type for release | Use correct release event |
| `EntityMismatch` | Event doesn't match escrow entity | Check entity ID configuration |
| `RootNotAnchored` | Merkle root not on-chain | Anchor the root first |
| `EscrowExpired` | Timeout exceeded | Can only refund to buyer |
| `AlreadyReleased` | Escrow already released | No action needed |

## Next Steps

- Review [VES-CONTRACT-1 Specification](./VES_CONTRACT_1_SPECIFICATION.md) for full details
- Explore [VES-MULTI-1](./VES_MULTI_1_SPECIFICATION.md) for multi-signature escrow
- See [VES-STARK-1](./VES_STARK_1_SPECIFICATION.md) for batch proof verification
