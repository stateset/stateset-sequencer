# VES-CHAIN-1: Blockchain Integration Specification

**Version:** 1.0
**Status:** Draft
**Last Updated:** 2025-12-22
**Dependencies:** VES-SIG-1, VES-ENC-1

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Principles](#2-design-principles)
3. [Supported Blockchains](#3-supported-blockchains)
4. [Key Architecture](#4-key-architecture)
5. [Key Derivation](#5-key-derivation)
6. [Transaction Signing](#6-transaction-signing)
7. [VES Event Recording](#7-ves-event-recording)
8. [Chain-Specific Implementations](#8-chain-specific-implementations)
9. [Multi-Chain Operations](#9-multi-chain-operations)
10. [On-Chain Anchoring](#10-on-chain-anchoring)
11. [Database Schema](#11-database-schema)
12. [Security Considerations](#12-security-considerations)
13. [Code Examples](#13-code-examples)
14. [Implementation Checklist](#14-implementation-checklist)
15. [Appendix A: Chain Parameters](#appendix-a-chain-parameters)
16. [Appendix B: BIP-44 Coin Types](#appendix-b-bip-44-coin-types)

---

## 1. Overview

VES-CHAIN-1 defines how VES agents can create, sign, and submit blockchain transactions using their Ed25519 cryptographic keys. This enables:

- **Unified Identity**: Single agent identity across VES and blockchain networks
- **Auditable Payments**: All blockchain transactions recorded as VES events
- **Multi-Chain Operations**: Agents operate across multiple Ed25519-compatible chains
- **Deterministic Addresses**: Blockchain addresses derived from VES agent keys
- **Atomic Recording**: Transaction execution and VES event creation in single flow

### 1.1 Key Capabilities

| Capability | Description |
|------------|-------------|
| **Transaction Signing** | Sign blockchain transactions with agent Ed25519 keys |
| **Payment Recording** | Record all payments as verifiable VES events |
| **Multi-Chain Wallets** | Derive addresses for multiple blockchains |
| **Escrow Operations** | Create and release escrow with VES proof |
| **On-Chain Anchoring** | Anchor VES commitments to blockchains |
| **Token Operations** | Transfer tokens, NFTs, and other on-chain assets |

### 1.2 Supported Operations

```
┌─────────────────────────────────────────────────────────────────┐
│                    VES-CHAIN-1 Operations                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Payments  │  │   Escrow    │  │  Anchoring  │              │
│  │             │  │             │  │             │              │
│  │ • Transfer  │  │ • Create    │  │ • Commit    │              │
│  │ • Batch     │  │ • Release   │  │ • Verify    │              │
│  │ • Scheduled │  │ • Refund    │  │ • Prove     │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Tokens    │  │    NFTs     │  │   Staking   │              │
│  │             │  │             │  │             │              │
│  │ • Transfer  │  │ • Mint      │  │ • Delegate  │              │
│  │ • Approve   │  │ • Transfer  │  │ • Undelegate│              │
│  │ • Swap      │  │ • Burn      │  │ • Claim     │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Design Principles

### 2.1 Cryptographic Alignment

VES-SIG-1 uses Ed25519, which is natively supported by many modern blockchains. This enables:

- **Zero conversion overhead**: Same key format, same signature algorithm
- **Unified key management**: Single key registry for VES and blockchain
- **Cross-verification**: VES signatures verifiable on-chain (where supported)

### 2.2 Event-Sourced Blockchain Operations

Every blockchain operation MUST be recorded as a VES event:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Intent    │────►│  Execute    │────►│   Record    │
│  (VES Event)│     │  (On-Chain) │     │  (VES Event)│
└─────────────┘     └─────────────┘     └─────────────┘
      │                    │                    │
      ▼                    ▼                    ▼
 PaymentIntent       Transaction          PaymentExecuted
   Recorded            Signed              + TX Reference
```

### 2.3 Deterministic Derivation

All blockchain addresses MUST be deterministically derived from agent identity:

```
Agent Identity (tenant_id, agent_id)
    ↓
Master Seed
    ↓
HD Derivation Path
    ↓
Chain-Specific Address
```

### 2.4 Atomicity Guarantees

| Scenario | Guarantee |
|----------|-----------|
| TX succeeds, VES fails | TX on-chain, VES event retried |
| TX fails, VES succeeds | VES records failure with error |
| Both succeed | Complete audit trail |
| Both fail | Retry entire operation |

---

## 3. Supported Blockchains

### 3.1 Ed25519-Native Chains (Full Support)

| Chain | Signature | Address Format | Status |
|-------|-----------|----------------|--------|
| **Solana** | Ed25519 | Base58 (32 bytes) | ✅ Full |
| **NEAR Protocol** | Ed25519 | Named accounts | ✅ Full |
| **Stellar** | Ed25519 | G... (StrKey) | ✅ Full |
| **Cardano** | Ed25519 | addr1... (Bech32) | ✅ Full |
| **Polkadot** | Ed25519/Sr25519 | SS58 | ✅ Full |
| **Cosmos/Tendermint** | Ed25519 | cosmos1... | ✅ Full |
| **Algorand** | Ed25519 | Base32 | ✅ Full |
| **Aptos** | Ed25519 | 0x... (Hex) | ✅ Full |
| **Sui** | Ed25519 | 0x... (Hex) | ✅ Full |
| **Tezos** | Ed25519 | tz1... | ✅ Full |

### 3.2 secp256k1 Chains (Bridge Required)

| Chain | Signature | Integration |
|-------|-----------|-------------|
| Bitcoin | secp256k1 ECDSA | Via bridge contract |
| Ethereum | secp256k1 ECDSA | Via bridge contract |
| EVM Chains | secp256k1 ECDSA | Via bridge contract |

### 3.3 Chain Capabilities Matrix

| Chain | Native Tokens | Fungible Tokens | NFTs | Smart Contracts | Anchoring |
|-------|---------------|-----------------|------|-----------------|-----------|
| Solana | SOL | SPL | Metaplex | ✅ | ✅ |
| NEAR | NEAR | NEP-141 | NEP-171 | ✅ | ✅ |
| Stellar | XLM | Assets | - | Limited | ✅ |
| Cardano | ADA | Native | CIP-25 | Plutus | ✅ |
| Cosmos | ATOM | IBC | - | CosmWasm | ✅ |
| Aptos | APT | Coins | Tokens | Move | ✅ |

---

## 4. Key Architecture

### 4.1 Unified Key Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     Agent Key Architecture                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Master Seed                           │    │
│  │              (BIP-39 Mnemonic / Raw Entropy)            │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           │                                      │
│            ┌──────────────┼──────────────┐                      │
│            │              │              │                      │
│            ▼              ▼              ▼                      │
│     ┌────────────┐ ┌────────────┐ ┌────────────┐               │
│     │ VES Keys   │ │ Chain Keys │ │ Encryption │               │
│     │            │ │            │ │   Keys     │               │
│     │ m/44'/9999'│ │ m/44'/501' │ │ m/44'/9998'│               │
│     │ (Signing)  │ │ (Solana)   │ │ (X25519)   │               │
│     └────────────┘ └────────────┘ └────────────┘               │
│            │              │              │                      │
│            ▼              ▼              ▼                      │
│      Sign Events    Sign TXs      Encrypt Payloads             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Key Types

| Key Type | Algorithm | Purpose | Derivation Path |
|----------|-----------|---------|-----------------|
| VES Signing | Ed25519 | Sign VES events | m/44'/9999'/tenant'/agent'/key_id |
| Blockchain | Ed25519 | Sign transactions | m/44'/COIN'/account'/0/0 |
| Encryption | X25519 | Encrypt payloads | m/44'/9998'/tenant'/agent'/key_id |

### 4.3 Key Registry Extension

```sql
-- Extended agent_keys table for blockchain support
CREATE TABLE agent_blockchain_keys (
    tenant_id       UUID NOT NULL,
    agent_id        UUID NOT NULL,
    chain_id        VARCHAR(32) NOT NULL,  -- 'solana', 'near', etc.

    -- Derived key info
    derivation_path VARCHAR(64) NOT NULL,
    public_key      BYTEA NOT NULL CHECK (length(public_key) = 32),
    address         VARCHAR(128) NOT NULL,  -- Chain-specific address format

    -- Status
    status          VARCHAR(16) DEFAULT 'active',
    created_at      TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (tenant_id, agent_id, chain_id),

    -- Link to VES signing key
    FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agent_signing_keys(tenant_id, agent_id)
);

-- Index for address lookups
CREATE INDEX idx_blockchain_keys_address
    ON agent_blockchain_keys(chain_id, address);
```

---

## 5. Key Derivation

### 5.1 BIP-44 Derivation Paths

```
Standard BIP-44 Path: m / purpose' / coin_type' / account' / change / address_index

VES-CHAIN-1 Paths:
├── m/44'/9999'/T'/A'/K   VES Signing Keys
├── m/44'/9998'/T'/A'/K   VES Encryption Keys (converted to X25519)
├── m/44'/501'/T'/A'/0    Solana
├── m/44'/397'/T'/A'/0    NEAR
├── m/44'/148'/T'/A'/0    Stellar
├── m/44'/1815'/T'/A'/0   Cardano
├── m/44'/354'/T'/A'/0    Polkadot
├── m/44'/118'/T'/A'/0    Cosmos
├── m/44'/283'/T'/A'/0    Algorand
├── m/44'/637'/T'/A'/0    Aptos
└── m/44'/784'/T'/A'/0    Sui

Where:
  T = tenant_index (derived from tenant_id)
  A = agent_index (derived from agent_id)
  K = key_id
```

### 5.2 Tenant/Agent Index Derivation

```typescript
// Derive deterministic index from UUID
function uuidToIndex(uuid: string): number {
  const bytes = uuidBytes(uuid);
  // Use first 4 bytes as big-endian u32, mask to 31 bits for hardened derivation
  const view = new DataView(bytes.buffer);
  return view.getUint32(0, false) & 0x7FFFFFFF;
}

// Example:
// tenant_id: "00000000-0000-0000-0000-000000000001" → index 0
// agent_id:  "22222222-2222-2222-2222-222222222222" → index 572662306
```

### 5.3 Key Derivation Implementation

```typescript
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';

interface DerivedKeys {
  vesSigningKey: Uint8Array;
  vesPublicKey: Uint8Array;
  blockchainKeys: Map<string, {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    address: string;
  }>;
}

function deriveAgentKeys(
  mnemonic: string,
  tenantId: string,
  agentId: string,
  chains: string[]
): DerivedKeys {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);

  const tenantIndex = uuidToIndex(tenantId);
  const agentIndex = uuidToIndex(agentId);

  // Derive VES signing key
  const vesPath = `m/44'/9999'/${tenantIndex}'/${agentIndex}'/0`;
  const vesKey = master.derive(vesPath);

  // Derive blockchain keys
  const blockchainKeys = new Map();
  for (const chain of chains) {
    const coinType = CHAIN_COIN_TYPES[chain];
    const path = `m/44'/${coinType}'/${tenantIndex}'/${agentIndex}'/0`;
    const key = master.derive(path);

    blockchainKeys.set(chain, {
      privateKey: key.privateKey!,
      publicKey: key.publicKey!,
      address: deriveAddress(chain, key.publicKey!),
    });
  }

  return {
    vesSigningKey: vesKey.privateKey!,
    vesPublicKey: vesKey.publicKey!,
    blockchainKeys,
  };
}
```

### 5.4 Address Derivation

```typescript
const ADDRESS_DERIVERS: Record<string, (pubkey: Uint8Array) => string> = {
  solana: (pk) => base58.encode(pk),

  near: (pk) => `ed25519:${base58.encode(pk)}`,

  stellar: (pk) => {
    // StrKey encoding with 'G' prefix for public keys
    const versionByte = 6 << 3; // G prefix
    const payload = new Uint8Array([versionByte, ...pk]);
    const checksum = crc16(payload);
    return base32.encode(new Uint8Array([...payload, ...checksum]));
  },

  cosmos: (pk) => {
    const hash = ripemd160(sha256(pk));
    return bech32.encode('cosmos', bech32.toWords(hash));
  },

  aptos: (pk) => {
    // Single signer authentication key
    const authKey = sha3_256(new Uint8Array([...pk, 0x00]));
    return '0x' + hex(authKey);
  },

  sui: (pk) => {
    // Ed25519 flag (0x00) + public key hash
    const flag = new Uint8Array([0x00]);
    const hash = blake2b(new Uint8Array([...flag, ...pk]), { dkLen: 32 });
    return '0x' + hex(hash);
  },
};

function deriveAddress(chain: string, publicKey: Uint8Array): string {
  const deriver = ADDRESS_DERIVERS[chain];
  if (!deriver) throw new Error(`Unsupported chain: ${chain}`);
  return deriver(publicKey);
}
```

---

## 6. Transaction Signing

### 6.1 Generic Signing Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Transaction Signing Flow                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. BUILD TRANSACTION                                           │
│     ┌─────────────────┐                                         │
│     │ Chain-Specific  │                                         │
│     │   TX Builder    │                                         │
│     └────────┬────────┘                                         │
│              │                                                   │
│              ▼                                                   │
│  2. SERIALIZE FOR SIGNING                                       │
│     ┌─────────────────┐                                         │
│     │  TX Message     │ ◄── Chain-specific serialization        │
│     │   (bytes)       │                                         │
│     └────────┬────────┘                                         │
│              │                                                   │
│              ▼                                                   │
│  3. SIGN WITH ED25519                                           │
│     ┌─────────────────┐                                         │
│     │ Ed25519.Sign    │                                         │
│     │ (private_key,   │                                         │
│     │  tx_message)    │                                         │
│     └────────┬────────┘                                         │
│              │                                                   │
│              ▼                                                   │
│  4. ATTACH SIGNATURE                                            │
│     ┌─────────────────┐                                         │
│     │ Signed TX       │                                         │
│     │ (ready to send) │                                         │
│     └────────┬────────┘                                         │
│              │                                                   │
│              ▼                                                   │
│  5. SUBMIT TO NETWORK                                           │
│     ┌─────────────────┐                                         │
│     │   TX Hash /     │                                         │
│     │   Signature     │                                         │
│     └─────────────────┘                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Transaction Signer Interface

```typescript
interface ChainTransaction {
  chain: string;
  type: string;
  from: string;
  to?: string;
  amount?: bigint;
  data?: Uint8Array;
  memo?: string;
}

interface SignedTransaction {
  chain: string;
  txHash: string;
  signature: Uint8Array;
  rawTx: Uint8Array;
}

interface TransactionSigner {
  // Get agent's address for this chain
  getAddress(): string;

  // Build chain-specific transaction
  buildTransaction(params: TransactionParams): Promise<ChainTransaction>;

  // Sign transaction with agent's key
  signTransaction(tx: ChainTransaction): Promise<SignedTransaction>;

  // Submit signed transaction to network
  submitTransaction(signedTx: SignedTransaction): Promise<TransactionReceipt>;

  // Combined: build, sign, submit
  executeTransaction(params: TransactionParams): Promise<TransactionReceipt>;
}
```

### 6.3 Chain-Specific Signing

#### Solana

```typescript
import {
  Transaction,
  SystemProgram,
  Keypair,
  Connection,
  sendAndConfirmTransaction
} from '@solana/web3.js';

class SolanaTransactionSigner implements TransactionSigner {
  private keypair: Keypair;
  private connection: Connection;

  constructor(privateKey: Uint8Array, rpcUrl: string) {
    // Solana expects 64-byte key (32 private + 32 public)
    const publicKey = ed25519.getPublicKey(privateKey);
    this.keypair = Keypair.fromSecretKey(
      new Uint8Array([...privateKey, ...publicKey])
    );
    this.connection = new Connection(rpcUrl);
  }

  getAddress(): string {
    return this.keypair.publicKey.toBase58();
  }

  async signTransaction(tx: Transaction): Promise<SignedTransaction> {
    tx.sign(this.keypair);
    return {
      chain: 'solana',
      txHash: bs58.encode(tx.signature!),
      signature: tx.signature!,
      rawTx: tx.serialize(),
    };
  }

  async executeTransfer(
    recipient: string,
    lamports: bigint
  ): Promise<TransactionReceipt> {
    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: this.keypair.publicKey,
        toPubkey: new PublicKey(recipient),
        lamports: Number(lamports),
      })
    );

    const signature = await sendAndConfirmTransaction(
      this.connection,
      tx,
      [this.keypair]
    );

    return {
      chain: 'solana',
      txHash: signature,
      status: 'confirmed',
      blockNumber: await this.getBlockNumber(signature),
    };
  }
}
```

#### NEAR Protocol

```typescript
import { KeyPair, connect, keyStores, transactions } from 'near-api-js';

class NearTransactionSigner implements TransactionSigner {
  private keyPair: KeyPair;
  private accountId: string;
  private near: Near;

  constructor(privateKey: Uint8Array, accountId: string, networkId: string) {
    this.keyPair = KeyPair.fromString(
      'ed25519:' + base58.encode(privateKey)
    );
    this.accountId = accountId;
  }

  async executeTransfer(
    receiverId: string,
    amount: string  // yoctoNEAR
  ): Promise<TransactionReceipt> {
    const account = await this.near.account(this.accountId);
    const result = await account.sendMoney(receiverId, amount);

    return {
      chain: 'near',
      txHash: result.transaction.hash,
      status: 'confirmed',
      blockNumber: result.transaction.nonce,
    };
  }

  async executeFunctionCall(
    contractId: string,
    methodName: string,
    args: object,
    gas: string,
    deposit: string
  ): Promise<TransactionReceipt> {
    const account = await this.near.account(this.accountId);
    const result = await account.functionCall({
      contractId,
      methodName,
      args,
      gas,
      attachedDeposit: deposit,
    });

    return {
      chain: 'near',
      txHash: result.transaction.hash,
      status: 'confirmed',
    };
  }
}
```

#### Cosmos/Tendermint

```typescript
import { DirectSecp256k1HdWallet, Registry } from '@cosmjs/proto-signing';
import { SigningStargateClient, MsgSend } from '@cosmjs/stargate';

class CosmosTransactionSigner implements TransactionSigner {
  private client: SigningStargateClient;
  private address: string;

  async executeTransfer(
    recipient: string,
    amount: { denom: string; amount: string }[]
  ): Promise<TransactionReceipt> {
    const msg: MsgSend = {
      fromAddress: this.address,
      toAddress: recipient,
      amount,
    };

    const result = await this.client.signAndBroadcast(
      this.address,
      [{ typeUrl: '/cosmos.bank.v1beta1.MsgSend', value: msg }],
      'auto'
    );

    return {
      chain: 'cosmos',
      txHash: result.transactionHash,
      status: result.code === 0 ? 'confirmed' : 'failed',
      blockNumber: result.height,
    };
  }
}
```

---

## 7. VES Event Recording

### 7.1 Transaction Event Types

| Event Type | Description | Trigger |
|------------|-------------|---------|
| `PaymentIntentCreated` | Payment request recorded | Before TX |
| `TransactionSigned` | TX signed by agent | After signing |
| `TransactionSubmitted` | TX submitted to network | After submit |
| `TransactionConfirmed` | TX confirmed on-chain | After confirmation |
| `TransactionFailed` | TX failed | On error |
| `PaymentCompleted` | Full payment flow done | Final state |

### 7.2 Event Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  VES Event Recording Flow                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. PaymentIntentCreated                                        │
│     ├─ intent_id: UUID                                          │
│     ├─ chain: "solana"                                          │
│     ├─ recipient: "..."                                         │
│     ├─ amount: "1000000000"                                     │
│     └─ currency: "lamports"                                     │
│              │                                                   │
│              ▼                                                   │
│  2. TransactionSigned                                           │
│     ├─ intent_id: UUID (reference)                              │
│     ├─ tx_hash: "..."                                           │
│     ├─ signature: "0x..."                                       │
│     └─ raw_tx_hash: "0x..."                                     │
│              │                                                   │
│              ▼                                                   │
│  3. TransactionSubmitted                                        │
│     ├─ intent_id: UUID                                          │
│     ├─ tx_hash: "..."                                           │
│     └─ submitted_at: "2025-01-01T..."                           │
│              │                                                   │
│              ▼                                                   │
│  4. TransactionConfirmed                                        │
│     ├─ intent_id: UUID                                          │
│     ├─ tx_hash: "..."                                           │
│     ├─ block_number: 12345678                                   │
│     ├─ block_hash: "..."                                        │
│     └─ confirmations: 32                                        │
│              │                                                   │
│              ▼                                                   │
│  5. PaymentCompleted                                            │
│     ├─ intent_id: UUID                                          │
│     ├─ tx_hash: "..."                                           │
│     ├─ status: "success"                                        │
│     └─ final_amount: "1000000000"                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 7.3 Event Payload Schemas

#### PaymentIntentCreated

```json
{
  "intent_id": "uuid",
  "chain": "solana",
  "network": "mainnet-beta",
  "operation": "transfer",
  "from_address": "...",
  "to_address": "...",
  "amount": "1000000000",
  "currency": "lamports",
  "token_mint": null,
  "memo": "Invoice #1234",
  "idempotency_key": "uuid",
  "expires_at": "2025-01-02T00:00:00Z",
  "metadata": {
    "invoice_id": "INV-1234",
    "customer_id": "CUST-5678"
  }
}
```

#### TransactionConfirmed

```json
{
  "intent_id": "uuid",
  "chain": "solana",
  "network": "mainnet-beta",
  "tx_hash": "5wHu1qwD7q4...",
  "tx_signature": "0x3f8a...",
  "block_number": 234567890,
  "block_hash": "...",
  "block_time": "2025-01-01T12:00:05Z",
  "slot": 234567890,
  "confirmations": 32,
  "fee": {
    "amount": "5000",
    "currency": "lamports"
  },
  "status": "finalized"
}
```

### 7.4 Recording Implementation

```typescript
class VesBlockchainRecorder {
  private vesClient: VesClient;

  async recordPaymentIntent(
    tenantId: string,
    storeId: string,
    intent: PaymentIntent
  ): Promise<string> {
    const eventId = crypto.randomUUID();

    await this.vesClient.submitEvent({
      eventId,
      tenantId,
      storeId,
      entityType: 'Payment',
      entityId: intent.intentId,
      eventType: 'PaymentIntentCreated',
      payload: intent,
    });

    return eventId;
  }

  async recordTransactionConfirmed(
    tenantId: string,
    storeId: string,
    intentId: string,
    receipt: TransactionReceipt
  ): Promise<string> {
    const eventId = crypto.randomUUID();

    await this.vesClient.submitEvent({
      eventId,
      tenantId,
      storeId,
      entityType: 'Payment',
      entityId: intentId,
      eventType: 'TransactionConfirmed',
      payload: {
        intent_id: intentId,
        chain: receipt.chain,
        tx_hash: receipt.txHash,
        block_number: receipt.blockNumber,
        status: receipt.status,
        confirmed_at: new Date().toISOString(),
      },
    });

    return eventId;
  }
}
```

---

## 8. Chain-Specific Implementations

### 8.1 Solana Implementation

```typescript
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  SystemProgram,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import {
  getAssociatedTokenAddress,
  createTransferInstruction,
  TOKEN_PROGRAM_ID,
} from '@solana/spl-token';

class SolanaVesAgent {
  private keypair: Keypair;
  private connection: Connection;
  private vesRecorder: VesBlockchainRecorder;

  constructor(
    privateKey: Uint8Array,
    rpcUrl: string,
    vesRecorder: VesBlockchainRecorder
  ) {
    const publicKey = ed25519.getPublicKey(privateKey);
    this.keypair = Keypair.fromSecretKey(
      new Uint8Array([...privateKey, ...publicKey])
    );
    this.connection = new Connection(rpcUrl, 'confirmed');
    this.vesRecorder = vesRecorder;
  }

  get address(): string {
    return this.keypair.publicKey.toBase58();
  }

  async transferSOL(
    tenantId: string,
    storeId: string,
    recipient: string,
    amount: number,
    memo?: string
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();
    const lamports = Math.floor(amount * LAMPORTS_PER_SOL);

    // 1. Record intent
    await this.vesRecorder.recordPaymentIntent(tenantId, storeId, {
      intentId,
      chain: 'solana',
      operation: 'transfer',
      fromAddress: this.address,
      toAddress: recipient,
      amount: lamports.toString(),
      currency: 'lamports',
      memo,
    });

    // 2. Build transaction
    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: this.keypair.publicKey,
        toPubkey: new PublicKey(recipient),
        lamports,
      })
    );

    if (memo) {
      tx.add(
        new TransactionInstruction({
          keys: [],
          programId: new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),
          data: Buffer.from(memo),
        })
      );
    }

    // 3. Sign and submit
    try {
      const signature = await sendAndConfirmTransaction(
        this.connection,
        tx,
        [this.keypair],
        { commitment: 'confirmed' }
      );

      // 4. Get confirmation details
      const confirmation = await this.connection.getTransaction(signature);

      // 5. Record confirmation
      await this.vesRecorder.recordTransactionConfirmed(
        tenantId,
        storeId,
        intentId,
        {
          chain: 'solana',
          txHash: signature,
          blockNumber: confirmation?.slot,
          status: 'confirmed',
        }
      );

      return {
        success: true,
        intentId,
        txHash: signature,
        chain: 'solana',
      };

    } catch (error) {
      // Record failure
      await this.vesRecorder.recordTransactionFailed(
        tenantId,
        storeId,
        intentId,
        error.message
      );

      return {
        success: false,
        intentId,
        error: error.message,
        chain: 'solana',
      };
    }
  }

  async transferSPLToken(
    tenantId: string,
    storeId: string,
    tokenMint: string,
    recipient: string,
    amount: bigint
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();
    const mint = new PublicKey(tokenMint);
    const recipientPubkey = new PublicKey(recipient);

    // Get token accounts
    const fromAta = await getAssociatedTokenAddress(
      mint,
      this.keypair.publicKey
    );
    const toAta = await getAssociatedTokenAddress(
      mint,
      recipientPubkey
    );

    // Build transfer instruction
    const tx = new Transaction().add(
      createTransferInstruction(
        fromAta,
        toAta,
        this.keypair.publicKey,
        amount,
        [],
        TOKEN_PROGRAM_ID
      )
    );

    // Sign and submit (similar to SOL transfer)
    // ... recording flow same as above
  }
}
```

### 8.2 NEAR Protocol Implementation

```typescript
import {
  KeyPair,
  connect,
  keyStores,
  Near,
  Account,
  utils,
} from 'near-api-js';

class NearVesAgent {
  private keyPair: KeyPair;
  private near: Near;
  private account: Account;
  private vesRecorder: VesBlockchainRecorder;

  static async create(
    privateKey: Uint8Array,
    accountId: string,
    networkId: 'mainnet' | 'testnet',
    vesRecorder: VesBlockchainRecorder
  ): Promise<NearVesAgent> {
    const agent = new NearVesAgent();

    agent.keyPair = KeyPair.fromString(
      'ed25519:' + base58.encode(privateKey)
    );
    agent.vesRecorder = vesRecorder;

    const keyStore = new keyStores.InMemoryKeyStore();
    await keyStore.setKey(networkId, accountId, agent.keyPair);

    agent.near = await connect({
      networkId,
      keyStore,
      nodeUrl: networkId === 'mainnet'
        ? 'https://rpc.mainnet.near.org'
        : 'https://rpc.testnet.near.org',
    });

    agent.account = await agent.near.account(accountId);

    return agent;
  }

  get address(): string {
    return this.account.accountId;
  }

  async transferNEAR(
    tenantId: string,
    storeId: string,
    recipient: string,
    amount: string  // in NEAR (not yoctoNEAR)
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();
    const yoctoNear = utils.format.parseNearAmount(amount)!;

    // 1. Record intent
    await this.vesRecorder.recordPaymentIntent(tenantId, storeId, {
      intentId,
      chain: 'near',
      operation: 'transfer',
      fromAddress: this.address,
      toAddress: recipient,
      amount: yoctoNear,
      currency: 'yoctoNEAR',
    });

    // 2. Execute transfer
    try {
      const result = await this.account.sendMoney(recipient, yoctoNear);

      // 3. Record confirmation
      await this.vesRecorder.recordTransactionConfirmed(
        tenantId,
        storeId,
        intentId,
        {
          chain: 'near',
          txHash: result.transaction.hash,
          blockNumber: result.transaction.nonce,
          status: 'confirmed',
        }
      );

      return {
        success: true,
        intentId,
        txHash: result.transaction.hash,
        chain: 'near',
      };

    } catch (error) {
      await this.vesRecorder.recordTransactionFailed(
        tenantId,
        storeId,
        intentId,
        error.message
      );

      return {
        success: false,
        intentId,
        error: error.message,
        chain: 'near',
      };
    }
  }

  async callContract(
    tenantId: string,
    storeId: string,
    contractId: string,
    methodName: string,
    args: object,
    gas?: string,
    deposit?: string
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();

    // Record intent
    await this.vesRecorder.recordPaymentIntent(tenantId, storeId, {
      intentId,
      chain: 'near',
      operation: 'contract_call',
      fromAddress: this.address,
      toAddress: contractId,
      amount: deposit || '0',
      currency: 'yoctoNEAR',
      metadata: { methodName, args },
    });

    try {
      const result = await this.account.functionCall({
        contractId,
        methodName,
        args,
        gas: gas || '30000000000000',
        attachedDeposit: deposit || '0',
      });

      await this.vesRecorder.recordTransactionConfirmed(
        tenantId,
        storeId,
        intentId,
        {
          chain: 'near',
          txHash: result.transaction.hash,
          status: 'confirmed',
        }
      );

      return {
        success: true,
        intentId,
        txHash: result.transaction.hash,
        chain: 'near',
        returnValue: result.status,
      };

    } catch (error) {
      await this.vesRecorder.recordTransactionFailed(
        tenantId,
        storeId,
        intentId,
        error.message
      );

      return { success: false, intentId, error: error.message, chain: 'near' };
    }
  }
}
```

### 8.3 Cosmos Implementation

```typescript
import {
  DirectSecp256k1HdWallet,
  Registry,
} from '@cosmjs/proto-signing';
import {
  SigningStargateClient,
  StargateClient,
  coin,
} from '@cosmjs/stargate';

class CosmosVesAgent {
  private client: SigningStargateClient;
  private address: string;
  private vesRecorder: VesBlockchainRecorder;

  static async create(
    privateKey: Uint8Array,
    rpcUrl: string,
    prefix: string,  // 'cosmos', 'osmo', 'juno', etc.
    vesRecorder: VesBlockchainRecorder
  ): Promise<CosmosVesAgent> {
    const agent = new CosmosVesAgent();

    // Create wallet from Ed25519 key
    // Note: Cosmos typically uses secp256k1, but some chains support Ed25519
    const wallet = await DirectSecp256k1HdWallet.fromKey(privateKey, prefix);
    const [{ address }] = await wallet.getAccounts();

    agent.address = address;
    agent.client = await SigningStargateClient.connectWithSigner(rpcUrl, wallet);
    agent.vesRecorder = vesRecorder;

    return agent;
  }

  async transferTokens(
    tenantId: string,
    storeId: string,
    recipient: string,
    amount: string,
    denom: string
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();

    await this.vesRecorder.recordPaymentIntent(tenantId, storeId, {
      intentId,
      chain: 'cosmos',
      operation: 'transfer',
      fromAddress: this.address,
      toAddress: recipient,
      amount,
      currency: denom,
    });

    try {
      const result = await this.client.sendTokens(
        this.address,
        recipient,
        [coin(amount, denom)],
        'auto'
      );

      await this.vesRecorder.recordTransactionConfirmed(
        tenantId,
        storeId,
        intentId,
        {
          chain: 'cosmos',
          txHash: result.transactionHash,
          blockNumber: result.height,
          status: result.code === 0 ? 'confirmed' : 'failed',
        }
      );

      return {
        success: result.code === 0,
        intentId,
        txHash: result.transactionHash,
        chain: 'cosmos',
      };

    } catch (error) {
      await this.vesRecorder.recordTransactionFailed(
        tenantId,
        storeId,
        intentId,
        error.message
      );

      return { success: false, intentId, error: error.message, chain: 'cosmos' };
    }
  }
}
```

---

## 9. Multi-Chain Operations

### 9.1 Multi-Chain Agent

```typescript
class MultiChainVesAgent {
  private vesSigningKey: Uint8Array;
  private chainAgents: Map<string, ChainAgent>;
  private vesClient: VesClient;
  private vesRecorder: VesBlockchainRecorder;

  constructor(
    mnemonic: string,
    tenantId: string,
    agentId: string,
    vesClient: VesClient
  ) {
    const keys = deriveAgentKeys(mnemonic, tenantId, agentId, [
      'solana', 'near', 'cosmos', 'stellar'
    ]);

    this.vesSigningKey = keys.vesSigningKey;
    this.vesClient = vesClient;
    this.vesRecorder = new VesBlockchainRecorder(vesClient);
    this.chainAgents = new Map();
  }

  async initializeChain(chain: string, config: ChainConfig): Promise<void> {
    const keys = this.chainAgents.get(chain);

    switch (chain) {
      case 'solana':
        this.chainAgents.set(chain, new SolanaVesAgent(
          keys.privateKey,
          config.rpcUrl,
          this.vesRecorder
        ));
        break;
      case 'near':
        this.chainAgents.set(chain, await NearVesAgent.create(
          keys.privateKey,
          config.accountId,
          config.networkId,
          this.vesRecorder
        ));
        break;
      // ... other chains
    }
  }

  async transfer(
    tenantId: string,
    storeId: string,
    chain: string,
    recipient: string,
    amount: string,
    currency: string
  ): Promise<PaymentResult> {
    const agent = this.chainAgents.get(chain);
    if (!agent) throw new Error(`Chain ${chain} not initialized`);

    return agent.transfer(tenantId, storeId, recipient, amount, currency);
  }

  async getAddresses(): Promise<Record<string, string>> {
    const addresses: Record<string, string> = {};
    for (const [chain, agent] of this.chainAgents) {
      addresses[chain] = agent.address;
    }
    return addresses;
  }

  async getBalances(): Promise<Record<string, Balance[]>> {
    const balances: Record<string, Balance[]> = {};
    for (const [chain, agent] of this.chainAgents) {
      balances[chain] = await agent.getBalances();
    }
    return balances;
  }
}
```

### 9.2 Cross-Chain Payment

```typescript
interface CrossChainPayment {
  intentId: string;
  sourceChain: string;
  destChain: string;
  sourceAmount: string;
  destAmount: string;
  sourceTxHash?: string;
  destTxHash?: string;
  bridgeProtocol: string;
  status: 'pending' | 'bridging' | 'completed' | 'failed';
}

class CrossChainPaymentService {
  async initiateCrossChainPayment(
    tenantId: string,
    storeId: string,
    sourceChain: string,
    destChain: string,
    recipient: string,
    amount: string
  ): Promise<CrossChainPayment> {
    const intentId = crypto.randomUUID();

    // Record cross-chain intent
    await this.vesRecorder.recordPaymentIntent(tenantId, storeId, {
      intentId,
      chain: sourceChain,
      operation: 'cross_chain_transfer',
      destChain,
      toAddress: recipient,
      amount,
      bridgeProtocol: 'wormhole',  // or 'layerzero', 'axelar', etc.
    });

    // Execute bridge transaction on source chain
    // ... bridge-specific implementation

    return {
      intentId,
      sourceChain,
      destChain,
      sourceAmount: amount,
      destAmount: amount,  // minus fees
      bridgeProtocol: 'wormhole',
      status: 'bridging',
    };
  }
}
```

---

## 10. On-Chain Anchoring

### 10.1 Anchoring VES Commitments

VES batch commitments can be anchored on-chain for public verifiability:

```typescript
interface AnchorCommitment {
  streamId: string;      // SHA256 of tenant_id || store_id
  sequenceStart: number;
  sequenceEnd: number;
  eventsRoot: string;    // Merkle root of events
  prevEventsRoot: string;
  timestamp: number;
}

class VesAnchoringService {
  async anchorToSolana(
    commitment: AnchorCommitment
  ): Promise<string> {
    // Encode commitment data
    const data = this.encodeCommitment(commitment);

    // Create anchor transaction
    const tx = new Transaction().add(
      new TransactionInstruction({
        keys: [
          { pubkey: this.anchorAccount, isSigner: false, isWritable: true },
          { pubkey: this.payer.publicKey, isSigner: true, isWritable: true },
        ],
        programId: this.anchorProgramId,
        data,
      })
    );

    // Submit
    const signature = await sendAndConfirmTransaction(
      this.connection,
      tx,
      [this.payer]
    );

    return signature;
  }

  async anchorToNear(
    commitment: AnchorCommitment
  ): Promise<string> {
    const result = await this.nearAccount.functionCall({
      contractId: 'ves-anchor.near',
      methodName: 'anchor_commitment',
      args: {
        stream_id: commitment.streamId,
        sequence_start: commitment.sequenceStart,
        sequence_end: commitment.sequenceEnd,
        events_root: commitment.eventsRoot,
        prev_events_root: commitment.prevEventsRoot,
      },
      gas: '30000000000000',
    });

    return result.transaction.hash;
  }
}
```

### 10.2 Solana Anchor Program

```rust
// Solana program for VES anchoring
use anchor_lang::prelude::*;

#[program]
pub mod ves_anchor {
    use super::*;

    pub fn anchor_commitment(
        ctx: Context<AnchorCommitment>,
        stream_id: [u8; 32],
        sequence_start: u64,
        sequence_end: u64,
        events_root: [u8; 32],
        prev_events_root: [u8; 32],
    ) -> Result<()> {
        let anchor = &mut ctx.accounts.anchor;

        // Verify chaining (if not genesis)
        if anchor.initialized {
            require!(
                prev_events_root == anchor.events_root,
                VesError::ChainMismatch
            );
            require!(
                sequence_start == anchor.sequence_end + 1,
                VesError::SequenceGap
            );
        }

        // Update anchor state
        anchor.stream_id = stream_id;
        anchor.sequence_start = sequence_start;
        anchor.sequence_end = sequence_end;
        anchor.events_root = events_root;
        anchor.prev_events_root = prev_events_root;
        anchor.timestamp = Clock::get()?.unix_timestamp;
        anchor.initialized = true;

        emit!(CommitmentAnchored {
            stream_id,
            sequence_start,
            sequence_end,
            events_root,
        });

        Ok(())
    }
}

#[account]
pub struct VesAnchor {
    pub stream_id: [u8; 32],
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub events_root: [u8; 32],
    pub prev_events_root: [u8; 32],
    pub timestamp: i64,
    pub initialized: bool,
}

#[event]
pub struct CommitmentAnchored {
    pub stream_id: [u8; 32],
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub events_root: [u8; 32],
}
```

---

## 11. Database Schema

### 11.1 Blockchain Keys Table

```sql
CREATE TABLE agent_blockchain_keys (
    tenant_id           UUID NOT NULL,
    agent_id            UUID NOT NULL,
    chain_id            VARCHAR(32) NOT NULL,
    network_id          VARCHAR(32) NOT NULL,  -- mainnet, testnet, etc.
    derivation_path     VARCHAR(64) NOT NULL,
    public_key          BYTEA NOT NULL CHECK (length(public_key) = 32),
    address             VARCHAR(128) NOT NULL,
    status              VARCHAR(16) DEFAULT 'active',
    created_at          TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (tenant_id, agent_id, chain_id, network_id)
);

CREATE INDEX idx_blockchain_keys_address
    ON agent_blockchain_keys(chain_id, network_id, address);
```

### 11.2 Transaction Records Table

```sql
CREATE TABLE blockchain_transactions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    store_id            UUID NOT NULL,
    agent_id            UUID NOT NULL,
    intent_id           UUID NOT NULL UNIQUE,

    -- Chain info
    chain_id            VARCHAR(32) NOT NULL,
    network_id          VARCHAR(32) NOT NULL,

    -- Transaction details
    tx_hash             VARCHAR(128),
    tx_signature        BYTEA,
    from_address        VARCHAR(128) NOT NULL,
    to_address          VARCHAR(128),
    amount              NUMERIC(78, 0),  -- Large enough for any token
    currency            VARCHAR(32),
    token_address       VARCHAR(128),

    -- Operation
    operation_type      VARCHAR(32) NOT NULL,
    operation_data      JSONB,

    -- Status tracking
    status              VARCHAR(32) NOT NULL DEFAULT 'pending',
    block_number        BIGINT,
    block_hash          VARCHAR(128),
    block_time          TIMESTAMPTZ,
    confirmations       INTEGER DEFAULT 0,
    error_message       TEXT,

    -- Fees
    fee_amount          NUMERIC(78, 0),
    fee_currency        VARCHAR(32),

    -- VES reference
    ves_event_ids       UUID[] NOT NULL DEFAULT '{}',

    -- Timestamps
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    submitted_at        TIMESTAMPTZ,
    confirmed_at        TIMESTAMPTZ,

    CONSTRAINT chk_status CHECK (status IN (
        'pending', 'signed', 'submitted', 'confirmed',
        'finalized', 'failed', 'cancelled'
    ))
);

CREATE INDEX idx_blockchain_tx_intent ON blockchain_transactions(intent_id);
CREATE INDEX idx_blockchain_tx_hash ON blockchain_transactions(chain_id, tx_hash);
CREATE INDEX idx_blockchain_tx_tenant ON blockchain_transactions(tenant_id, created_at DESC);
CREATE INDEX idx_blockchain_tx_status ON blockchain_transactions(status)
    WHERE status IN ('pending', 'submitted');
```

### 11.3 Anchor Records Table

```sql
CREATE TABLE ves_anchor_records (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    store_id            UUID NOT NULL,

    -- VES commitment
    stream_id           BYTEA NOT NULL CHECK (length(stream_id) = 32),
    sequence_start      BIGINT NOT NULL,
    sequence_end        BIGINT NOT NULL,
    events_root         BYTEA NOT NULL CHECK (length(events_root) = 32),
    prev_events_root    BYTEA NOT NULL CHECK (length(prev_events_root) = 32),

    -- On-chain anchor
    chain_id            VARCHAR(32) NOT NULL,
    network_id          VARCHAR(32) NOT NULL,
    tx_hash             VARCHAR(128) NOT NULL,
    block_number        BIGINT,
    anchor_address      VARCHAR(128),

    -- Status
    status              VARCHAR(32) NOT NULL DEFAULT 'pending',
    anchored_at         TIMESTAMPTZ,

    CONSTRAINT uq_anchor_stream_seq UNIQUE (stream_id, sequence_start)
);

CREATE INDEX idx_anchor_chain ON ves_anchor_records(chain_id, tx_hash);
```

---

## 12. Security Considerations

### 12.1 Key Security

| Risk | Mitigation |
|------|------------|
| Key extraction | HSM storage for production keys |
| Key reuse across domains | Use derived keys per chain/purpose |
| Signing unauthorized TXs | Implement spending limits and approvals |
| Man-in-the-middle | Verify TX contents before signing |

### 12.2 Transaction Security

```typescript
interface TransactionPolicy {
  // Spending limits
  maxSingleTransaction: bigint;
  dailyLimit: bigint;

  // Approvals
  requireApprovalAbove: bigint;
  approvers: string[];
  requiredApprovals: number;

  // Restrictions
  allowedRecipients?: string[];
  blockedRecipients?: string[];
  allowedTokens?: string[];

  // Time restrictions
  allowedHours?: { start: number; end: number };
  allowedDays?: number[];  // 0-6
}

async function enforcePolicy(
  tx: ChainTransaction,
  policy: TransactionPolicy
): Promise<boolean> {
  // Check single transaction limit
  if (tx.amount > policy.maxSingleTransaction) {
    throw new Error('Exceeds single transaction limit');
  }

  // Check daily limit
  const dailySpent = await getDailySpent(tx.from);
  if (dailySpent + tx.amount > policy.dailyLimit) {
    throw new Error('Exceeds daily limit');
  }

  // Check approval requirement
  if (tx.amount > policy.requireApprovalAbove) {
    const approvals = await getApprovals(tx);
    if (approvals.length < policy.requiredApprovals) {
      throw new Error('Insufficient approvals');
    }
  }

  // Check allowed recipients
  if (policy.allowedRecipients && !policy.allowedRecipients.includes(tx.to)) {
    throw new Error('Recipient not in allowlist');
  }

  return true;
}
```

### 12.3 Audit Trail

Every blockchain operation creates VES events that:
- Cannot be deleted or modified (append-only)
- Are cryptographically signed by the agent
- Include complete transaction details
- Reference on-chain transaction hashes
- Are included in Merkle commitments

### 12.4 Key Compromise Response

```typescript
async function handleKeyCompromise(
  tenantId: string,
  agentId: string,
  compromisedChains: string[]
): Promise<void> {
  // 1. Revoke VES signing key
  await keyRegistry.revokeKey(tenantId, agentId);

  // 2. Record compromise event
  await vesClient.submitEvent({
    entityType: 'SecurityIncident',
    entityId: `compromise-${Date.now()}`,
    eventType: 'KeyCompromiseDetected',
    payload: {
      agent_id: agentId,
      compromised_chains: compromisedChains,
      action: 'keys_revoked',
    },
  });

  // 3. Attempt to move funds (if keys still work)
  for (const chain of compromisedChains) {
    await attemptEmergencyTransfer(tenantId, agentId, chain);
  }

  // 4. Alert administrators
  await alertService.sendCriticalAlert({
    type: 'key_compromise',
    tenant_id: tenantId,
    agent_id: agentId,
    chains: compromisedChains,
  });
}
```

---

## 13. Code Examples

### 13.1 Complete Payment Flow

```typescript
import { MultiChainVesAgent } from './multi-chain-agent';

async function executePayment() {
  // Initialize agent
  const agent = new MultiChainVesAgent(
    process.env.MNEMONIC!,
    'tenant-uuid',
    'agent-uuid',
    vesClient
  );

  // Initialize Solana chain
  await agent.initializeChain('solana', {
    rpcUrl: 'https://api.mainnet-beta.solana.com',
  });

  // Get agent's Solana address
  const addresses = await agent.getAddresses();
  console.log('Solana address:', addresses.solana);

  // Execute payment with full VES recording
  const result = await agent.transfer(
    'tenant-uuid',
    'store-uuid',
    'solana',
    'recipient-address',
    '1.5',  // SOL
    'SOL'
  );

  if (result.success) {
    console.log('Payment successful!');
    console.log('TX Hash:', result.txHash);
    console.log('VES Intent ID:', result.intentId);
  } else {
    console.error('Payment failed:', result.error);
  }
}
```

### 13.2 Batch Payments

```typescript
interface BatchPayment {
  recipient: string;
  amount: string;
  memo?: string;
}

async function executeBatchPayments(
  agent: MultiChainVesAgent,
  tenantId: string,
  storeId: string,
  chain: string,
  payments: BatchPayment[]
): Promise<BatchResult> {
  const batchId = crypto.randomUUID();
  const results: PaymentResult[] = [];

  // Record batch intent
  await vesRecorder.recordPaymentIntent(tenantId, storeId, {
    intentId: batchId,
    chain,
    operation: 'batch_transfer',
    batch_size: payments.length,
    total_amount: payments.reduce((sum, p) => sum + BigInt(p.amount), 0n).toString(),
  });

  // Execute each payment
  for (const payment of payments) {
    const result = await agent.transfer(
      tenantId,
      storeId,
      chain,
      payment.recipient,
      payment.amount,
      'native'
    );
    results.push(result);
  }

  // Record batch completion
  const successCount = results.filter(r => r.success).length;
  await vesRecorder.submitEvent({
    entityType: 'PaymentBatch',
    entityId: batchId,
    eventType: 'BatchPaymentCompleted',
    payload: {
      batch_id: batchId,
      total_payments: payments.length,
      successful: successCount,
      failed: payments.length - successCount,
      results: results.map(r => ({
        intent_id: r.intentId,
        success: r.success,
        tx_hash: r.txHash,
      })),
    },
  });

  return {
    batchId,
    total: payments.length,
    successful: successCount,
    failed: payments.length - successCount,
    results,
  };
}
```

### 13.3 Escrow with VES Proof

```typescript
interface EscrowParams {
  buyer: string;
  seller: string;
  amount: string;
  releaseConditions: {
    type: 'ves_event' | 'time' | 'signature';
    params: object;
  }[];
}

class VesEscrowService {
  async createEscrow(
    tenantId: string,
    storeId: string,
    chain: string,
    params: EscrowParams
  ): Promise<EscrowResult> {
    const escrowId = crypto.randomUUID();

    // Record escrow creation in VES
    await this.vesRecorder.submitEvent({
      entityType: 'Escrow',
      entityId: escrowId,
      eventType: 'EscrowCreated',
      payload: {
        escrow_id: escrowId,
        chain,
        buyer: params.buyer,
        seller: params.seller,
        amount: params.amount,
        release_conditions: params.releaseConditions,
      },
    });

    // Create on-chain escrow
    const escrowAddress = await this.createOnChainEscrow(chain, params);

    // Fund escrow
    const fundResult = await this.agent.transfer(
      tenantId,
      storeId,
      chain,
      escrowAddress,
      params.amount,
      'native'
    );

    // Record funding
    await this.vesRecorder.submitEvent({
      entityType: 'Escrow',
      entityId: escrowId,
      eventType: 'EscrowFunded',
      payload: {
        escrow_id: escrowId,
        funding_tx: fundResult.txHash,
        escrow_address: escrowAddress,
      },
    });

    return {
      escrowId,
      escrowAddress,
      fundingTx: fundResult.txHash,
    };
  }

  async releaseEscrow(
    tenantId: string,
    storeId: string,
    escrowId: string,
    vesProof: {
      eventId: string;
      merkleProof: string[];
      eventsRoot: string;
    }
  ): Promise<ReleaseResult> {
    // Verify VES proof
    const verified = await this.verifyVesProof(vesProof);
    if (!verified) {
      throw new Error('Invalid VES proof');
    }

    // Release escrow on-chain
    const releaseResult = await this.executeEscrowRelease(escrowId, vesProof);

    // Record release
    await this.vesRecorder.submitEvent({
      entityType: 'Escrow',
      entityId: escrowId,
      eventType: 'EscrowReleased',
      payload: {
        escrow_id: escrowId,
        release_tx: releaseResult.txHash,
        proof_event_id: vesProof.eventId,
        proof_events_root: vesProof.eventsRoot,
      },
    });

    return releaseResult;
  }
}
```

---

## 14. Implementation Checklist

### 14.1 Key Management

- [ ] BIP-39 mnemonic generation and storage
- [ ] HD key derivation (BIP-32/44)
- [ ] Per-chain address derivation
- [ ] Key registry database schema
- [ ] Key rotation support

### 14.2 Chain Integrations

- [ ] Solana (SOL + SPL tokens)
- [ ] NEAR Protocol
- [ ] Cosmos/Tendermint
- [ ] Stellar
- [ ] Additional Ed25519 chains

### 14.3 Transaction Management

- [ ] Transaction building per chain
- [ ] Ed25519 signing
- [ ] Submission and confirmation tracking
- [ ] Error handling and retries
- [ ] Fee estimation

### 14.4 VES Integration

- [ ] Payment intent events
- [ ] Transaction confirmation events
- [ ] Failure recording
- [ ] Batch payment events
- [ ] Cross-chain events

### 14.5 Security

- [ ] Spending policy enforcement
- [ ] Multi-signature support
- [ ] Rate limiting
- [ ] Audit logging
- [ ] Key compromise procedures

---

## Appendix A: Chain Parameters

| Chain | Coin Type | Address Prefix | Native Token | Decimals |
|-------|-----------|----------------|--------------|----------|
| Solana | 501 | (base58) | SOL | 9 |
| NEAR | 397 | (named) | NEAR | 24 |
| Stellar | 148 | G | XLM | 7 |
| Cardano | 1815 | addr1 | ADA | 6 |
| Polkadot | 354 | (SS58) | DOT | 10 |
| Cosmos | 118 | cosmos1 | ATOM | 6 |
| Algorand | 283 | (base32) | ALGO | 6 |
| Aptos | 637 | 0x | APT | 8 |
| Sui | 784 | 0x | SUI | 9 |
| Tezos | 1729 | tz1 | XTZ | 6 |

---

## Appendix B: BIP-44 Coin Types

| Coin Type | Chain | Registration |
|-----------|-------|--------------|
| 9999 | VES Signing | Custom (reserved) |
| 9998 | VES Encryption | Custom (reserved) |
| 501 | Solana | SLIP-0044 |
| 397 | NEAR | SLIP-0044 |
| 148 | Stellar | SLIP-0044 |
| 1815 | Cardano | SLIP-0044 |
| 354 | Polkadot | SLIP-0044 |
| 118 | Cosmos Hub | SLIP-0044 |
| 283 | Algorand | SLIP-0044 |
| 637 | Aptos | SLIP-0044 |
| 784 | Sui | SLIP-0044 |
| 1729 | Tezos | SLIP-0044 |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-22 | Initial specification |

---

*This specification extends VES-SIG-1 and VES-ENC-1 for blockchain integration. See [VES_SIG_1_SPECIFICATION.md](./VES_SIG_1_SPECIFICATION.md) for agent signatures and [VES_ENC_1_SPECIFICATION.md](./VES_ENC_1_SPECIFICATION.md) for encryption.*
