# AI Commerce Agent Demo - Sample Output

This document shows the expected output when running the AI Commerce Agent demo.

## Demo Execution

```
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     🤖 VES-CHAIN-1 AI Commerce Agent Demo                                ║
║                                                                          ║
║     Demonstrating AI-driven stablecoin payments with full audit trail    ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝


🤖 AI Commerce Agent "Commerce-Agent-Alpha" initialized
   Solana Address: FsaLodPu4VmSwXGr3gWfwANe4vKf8XSZcCh1CEeJ3jpD
   Network: devnet

📦 Sample Order Created:
   Order ID: ORD-2025-001234
   Customer: CUST-5678
   Items:
     - 2x Premium Widget @ $49.99 (SUPPLIER-001)
     - 1x Smart Gadget @ $129.99 (SUPPLIER-001)
     - 3x Power Tool @ $79.99 (SUPPLIER-002)
   Total: $469.94

⏳ Starting order processing...

======================================================================
🛒 PROCESSING ORDER: ORD-2025-001234
======================================================================
   Customer: CUST-5678
   Items: 3
   Total: $469.94 USD

📝 VES Event Recorded:
   Event ID: e7f3a8b2-1c4d-5e6f-7a8b-9c0d1e2f3a4b
   Type: Order.OrderReceived
   Entity: ORD-2025-001234
   Signature: 0x3f8a9b2c1d4e5f6a...

📊 Supplier Payments Calculated:
   SUPPLIER-001: $160.99 USDC
   SUPPLIER-002: $167.99 USDC

──────────────────────────────────────────────────
💳 Processing payment to SUPPLIER-001
──────────────────────────────────────────────────

   📝 Recording payment intent...

📝 VES Event Recorded:
   Event ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
   Type: Payment.PaymentIntentCreated
   Entity: intent-uuid-1
   Signature: 0x7d4a2e9b1f3c8d7a...

   🔍 Resolving token accounts...
      From ATA: 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
      To ATA: 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM

   💰 Checking USDC balance...
      Balance: 500.00 USDC

   🔨 Building transaction...

   ✍️ Signing transaction...

📝 VES Event Recorded:
   Event ID: b2c3d4e5-f6a7-8901-bcde-f23456789012
   Type: Payment.TransactionSigned
   Entity: intent-uuid-1
   Signature: 0x9e8f7a6b5c4d3e2f...

   📤 Submitting to Solana network...

   ⛓️ Transaction confirmed!
      Signature: 5wHu1qwD7q4V9q8KqpTJ2tJ2Cy7h8GYrFkJkVJhjgXmN
      Explorer: https://explorer.solana.com/tx/5wHu1qwD7q4V9q8KqpTJ2tJ2Cy7h8GYrFkJkVJhjgXmN?cluster=devnet

📝 VES Event Recorded:
   Event ID: c3d4e5f6-a7b8-9012-cdef-34567890abcd
   Type: Payment.TransactionConfirmed
   Entity: intent-uuid-1
   Signature: 0x1a2b3c4d5e6f7a8b...

📝 VES Event Recorded:
   Event ID: d4e5f6a7-b8c9-0123-defa-4567890bcdef
   Type: Payment.PaymentCompleted
   Entity: intent-uuid-1
   Signature: 0x2b3c4d5e6f7a8b9c...

   ✅ Payment successful!
   TX: 5wHu1qwD7q4V9q8KqpTJ2tJ2Cy7h8GYrFkJkVJhjgXmN

──────────────────────────────────────────────────
💳 Processing payment to SUPPLIER-002
──────────────────────────────────────────────────

   📝 Recording payment intent...

📝 VES Event Recorded:
   Event ID: e5f6a7b8-c9d0-1234-efab-567890cdef01
   Type: Payment.PaymentIntentCreated
   Entity: intent-uuid-2
   Signature: 0x3c4d5e6f7a8b9c0d...

   🔍 Resolving token accounts...
      From ATA: 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
      To ATA: Hf4rPJqfC9CvhKhxFFePGcSqGXWBRJLfpjFvqQ7hPBLe

   💰 Checking USDC balance...
      Balance: 339.01 USDC

   🔨 Building transaction...

   ✍️ Signing transaction...

📝 VES Event Recorded:
   Event ID: f6a7b8c9-d0e1-2345-fabc-67890def0123
   Type: Payment.TransactionSigned
   Entity: intent-uuid-2
   Signature: 0x4d5e6f7a8b9c0d1e...

   📤 Submitting to Solana network...

   ⛓️ Transaction confirmed!
      Signature: 8xY7Z6W5V4U3T2S1R0Q9P8O7N6M5L4K3J2I1H0GFedCBA
      Explorer: https://explorer.solana.com/tx/8xY7Z6W5V4U3T2S1R0Q9P8O7N6M5L4K3J2I1H0GFedCBA?cluster=devnet

📝 VES Event Recorded:
   Event ID: a7b8c9d0-e1f2-3456-abcd-7890ef012345
   Type: Payment.TransactionConfirmed
   Entity: intent-uuid-2
   Signature: 0x5e6f7a8b9c0d1e2f...

📝 VES Event Recorded:
   Event ID: b8c9d0e1-f2a3-4567-bcde-890f01234567
   Type: Payment.PaymentCompleted
   Entity: intent-uuid-2
   Signature: 0x6f7a8b9c0d1e2f3a...

   ✅ Payment successful!
   TX: 8xY7Z6W5V4U3T2S1R0Q9P8O7N6M5L4K3J2I1H0GFedCBA

📝 VES Event Recorded:
   Event ID: c9d0e1f2-a3b4-5678-cdef-90ab12345678
   Type: Order.OrderPaid
   Entity: ORD-2025-001234
   Signature: 0x7a8b9c0d1e2f3a4b...

======================================================================
📊 PAYMENT SUMMARY
======================================================================
   Total Payments: 2
   Successful: 2
   Failed: 0

   Payment a1b2c3d4...
   ├─ Status: ✅ Success
   ├─ TX Hash: 5wHu1qwD7q4V9q8KqpTJ2tJ2Cy7h8GYrFkJkVJhjgXmN
   ├─ Explorer: https://explorer.solana.com/tx/5wHu1qwD7q4V9q8KqpTJ2tJ2Cy7h8GYrFkJkVJhjgXmN?cluster=devnet
   └─ VES Events: 4 recorded

   Payment e5f6a7b8...
   ├─ Status: ✅ Success
   ├─ TX Hash: 8xY7Z6W5V4U3T2S1R0Q9P8O7N6M5L4K3J2I1H0GFedCBA
   ├─ Explorer: https://explorer.solana.com/tx/8xY7Z6W5V4U3T2S1R0Q9P8O7N6M5L4K3J2I1H0GFedCBA?cluster=devnet
   └─ VES Events: 4 recorded

======================================================================
📋 AUDIT TRAIL FOR: ORD-2025-001234
======================================================================

   OrderReceived
   ├─ Event ID: e7f3a8b2-1c4d-5e6f-7a8b-9c0d1e2f3a4b
   ├─ Time: 2025-01-15T14:30:00.000Z
   ├─ Agent: 550e8400-e29b-41d4-a716-446655440003
   ├─ Payload Hash: 0x1a2b3c4d5e6f7a8b...
   └─ Signature: 0x3f8a9b2c1d4e5f6a...

   OrderPaid
   ├─ Event ID: c9d0e1f2-a3b4-5678-cdef-90ab12345678
   ├─ Time: 2025-01-15T14:30:15.000Z
   ├─ Agent: 550e8400-e29b-41d4-a716-446655440003
   ├─ Payload Hash: 0x8b9c0d1e2f3a4b5c...
   └─ Signature: 0x7a8b9c0d1e2f3a4b...

======================================================================
📜 FULL VES EVENT LOG
======================================================================
   Total Events: 11

   [2025-01-15T14:30:00.000Z]
   Order.OrderReceived
   Entity: ORD-2025-001234
   Event ID: e7f3a8b2-1c4d-5e6f-7a8b-9c0d1e2f3a4b

   [2025-01-15T14:30:01.000Z]
   Payment.PaymentIntentCreated
   Entity: intent-uuid-1
   Event ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890

   [2025-01-15T14:30:03.000Z]
   Payment.TransactionSigned
   Entity: intent-uuid-1
   Event ID: b2c3d4e5-f6a7-8901-bcde-f23456789012

   [2025-01-15T14:30:07.000Z]
   Payment.TransactionConfirmed
   Entity: intent-uuid-1
   Event ID: c3d4e5f6-a7b8-9012-cdef-34567890abcd

   [2025-01-15T14:30:07.500Z]
   Payment.PaymentCompleted
   Entity: intent-uuid-1
   Event ID: d4e5f6a7-b8c9-0123-defa-4567890bcdef

   [2025-01-15T14:30:08.000Z]
   Payment.PaymentIntentCreated
   Entity: intent-uuid-2
   Event ID: e5f6a7b8-c9d0-1234-efab-567890cdef01

   [2025-01-15T14:30:10.000Z]
   Payment.TransactionSigned
   Entity: intent-uuid-2
   Event ID: f6a7b8c9-d0e1-2345-fabc-67890def0123

   [2025-01-15T14:30:14.000Z]
   Payment.TransactionConfirmed
   Entity: intent-uuid-2
   Event ID: a7b8c9d0-e1f2-3456-abcd-7890ef012345

   [2025-01-15T14:30:14.500Z]
   Payment.PaymentCompleted
   Entity: intent-uuid-2
   Event ID: b8c9d0e1-f2a3-4567-bcde-890f01234567

   [2025-01-15T14:30:15.000Z]
   Order.OrderPaid
   Entity: ORD-2025-001234
   Event ID: c9d0e1f2-a3b4-5678-cdef-90ab12345678

╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     Demo Complete!                                                       ║
║                                                                          ║
║     This demo showed:                                                    ║
║     • AI agent with cryptographic identity (Ed25519 keys)               ║
║     • Order processing with supplier payment calculation                 ║
║     • USDC stablecoin transfers on Solana                               ║
║     • Full VES audit trail with signed events                           ║
║     • Non-repudiation through cryptographic signatures                  ║
║                                                                          ║
║     See VES_CHAIN_1_SPECIFICATION.md for full details                   ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

## Key Concepts Demonstrated

### 1. AI Agent Identity

The AI agent has a cryptographic identity derived from a BIP-39 mnemonic:

```typescript
// Derive VES signing key (for signing events)
const vesPath = "m/44'/9999'/0'/0'/0";
const vesKey = master.derive(vesPath);

// Derive Solana key (for signing transactions)
const solanaPath = "m/44'/501'/0'/0'/0";
const solanaKey = master.derive(solanaPath);
```

Both keys are Ed25519, enabling the agent to:
- Sign VES events (non-repudiable audit trail)
- Sign Solana transactions (stablecoin payments)

### 2. Commerce Flow

```
┌─────────────────┐
│  Order Received │
│    (VES Event)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Calculate       │
│ Supplier        │
│ Payments        │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│Pay    │ │Pay    │
│Supp 1 │ │Supp 2 │
└───┬───┘ └───┬───┘
    │         │
    ▼         ▼
┌─────────────────┐
│  Order Paid     │
│   (VES Event)   │
└─────────────────┘
```

### 3. Payment Flow with VES Recording

Each payment generates multiple VES events:

| Event | Description |
|-------|-------------|
| `PaymentIntentCreated` | Payment request recorded before execution |
| `TransactionSigned` | Transaction signed by agent |
| `TransactionConfirmed` | Transaction confirmed on Solana |
| `PaymentCompleted` | Full payment flow completed |

### 4. USDC Transfer on Solana

```typescript
// Build SPL token transfer
const tx = new Transaction().add(
  createTransferInstruction(
    fromAta,           // Agent's USDC account
    toAta,             // Supplier's USDC account
    agentPublicKey,    // Signer
    amount,            // Amount in base units (6 decimals)
    [],
    TOKEN_PROGRAM_ID
  )
);

// Sign with agent's Ed25519 key
tx.sign(agentKeypair);

// Submit to Solana
const signature = await sendAndConfirmTransaction(connection, tx, [agentKeypair]);
```

### 5. Full Audit Trail

Every action is recorded in VES with:
- Cryptographic signature from the agent
- Payload hash for integrity
- Timestamp
- References to related entities (orders, payments)

This creates an immutable, verifiable audit trail that proves:
- **Who** performed the action (agent signature)
- **What** was done (event type and payload)
- **When** it happened (timestamp)
- **Why** it was authorized (linked to order)

## Running the Demo

```bash
# Install dependencies
npm install @solana/web3.js @solana/spl-token @scure/bip32 @scure/bip39 @noble/ed25519 @noble/hashes

# Run the demo
npx ts-node examples/ai-commerce-agent-demo.ts
```

**Note:** To execute real transactions, you need:
1. Devnet USDC tokens in the agent's wallet
2. Supplier addresses with Associated Token Accounts
3. Network connectivity to Solana devnet

Get devnet tokens from: https://spl-token-faucet.com/
