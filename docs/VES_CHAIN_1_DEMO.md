# VES-CHAIN-1 Demo Guide

This guide demonstrates blockchain integration with VES agents, showing how to derive keys, sign transactions, and record payments as verifiable events.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Key Generation & Derivation](#key-generation--derivation)
3. [Address Derivation](#address-derivation)
4. [Solana Integration Demo](#solana-integration-demo)
5. [NEAR Protocol Demo](#near-protocol-demo)
6. [Cosmos SDK Demo](#cosmos-sdk-demo)
7. [Multi-Chain Agent Demo](#multi-chain-agent-demo)
8. [VES Event Recording](#ves-event-recording)
9. [On-Chain Anchoring Demo](#on-chain-anchoring-demo)
10. [Batch Payments Demo](#batch-payments-demo)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Dependencies

```bash
# Node.js dependencies
npm install @scure/bip39 @scure/bip32 @noble/ed25519 @noble/hashes
npm install @solana/web3.js @solana/spl-token
npm install near-api-js
npm install @cosmjs/stargate @cosmjs/proto-signing

# Python dependencies
pip install mnemonic ed25519 solana near-api-py

# Rust dependencies
cargo add bip39 ed25519-dalek solana-sdk near-jsonrpc-client
```

### Test Networks

| Chain | Network | Faucet |
|-------|---------|--------|
| Solana | devnet | https://faucet.solana.com |
| NEAR | testnet | https://near-faucet.io |
| Cosmos | theta-testnet | https://faucet.cosmos.network |

---

## Key Generation & Derivation

### Step 1: Generate Master Seed

```typescript
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';

// Generate BIP-39 mnemonic (256-bit entropy = 24 words)
const mnemonic = generateMnemonic(wordlist, 256);
console.log('Mnemonic:', mnemonic);
// Example: "abandon ability able about above absent absorb abstract..."

// Convert to seed
const seed = mnemonicToSeedSync(mnemonic);
console.log('Seed (hex):', Buffer.from(seed).toString('hex'));

// Create HD master key
const master = HDKey.fromMasterSeed(seed);
console.log('Master fingerprint:', master.fingerprint.toString(16));
```

### Step 2: Derive Agent Keys

```typescript
// UUID to index helper
function uuidToIndex(uuid: string): number {
  const bytes = Buffer.from(uuid.replace(/-/g, ''), 'hex');
  return bytes.readUInt32BE(0) & 0x7FFFFFFF;
}

// Test identifiers
const tenantId = '00000000-0000-0000-0000-000000000001';
const agentId = '22222222-2222-2222-2222-222222222222';

const tenantIndex = uuidToIndex(tenantId);  // 0
const agentIndex = uuidToIndex(agentId);    // 572662306

console.log('Tenant index:', tenantIndex);
console.log('Agent index:', agentIndex);

// Derive VES signing key
const vesPath = `m/44'/9999'/${tenantIndex}'/${agentIndex}'/0`;
const vesKey = master.derive(vesPath);

console.log('VES Signing Key:');
console.log('  Path:', vesPath);
console.log('  Private key:', Buffer.from(vesKey.privateKey!).toString('hex'));
console.log('  Public key:', Buffer.from(vesKey.publicKey!).toString('hex'));
```

### Step 3: Derive Chain-Specific Keys

```typescript
// Chain coin types
const COIN_TYPES = {
  solana: 501,
  near: 397,
  stellar: 148,
  cosmos: 118,
  aptos: 637,
  sui: 784,
};

// Derive keys for each chain
for (const [chain, coinType] of Object.entries(COIN_TYPES)) {
  const path = `m/44'/${coinType}'/${tenantIndex}'/${agentIndex}'/0`;
  const key = master.derive(path);

  console.log(`\n${chain.toUpperCase()} Key:`);
  console.log('  Path:', path);
  console.log('  Private key:', Buffer.from(key.privateKey!).toString('hex'));
  console.log('  Public key:', Buffer.from(key.publicKey!).toString('hex'));
}
```

**Expected Output:**
```
VES Signing Key:
  Path: m/44'/9999'/0'/572662306'/0
  Private key: 3b5e8a1c9f... (32 bytes hex)
  Public key: 7d4a2e9b1f... (32 bytes hex)

SOLANA Key:
  Path: m/44'/501'/0'/572662306'/0
  Private key: 8f2c1a4b7d... (32 bytes hex)
  Public key: a1e4b7c2d9... (32 bytes hex)

NEAR Key:
  Path: m/44'/397'/0'/572662306'/0
  ...
```

---

## Address Derivation

### Solana Address

```typescript
import * as bs58 from 'bs58';

function deriveSolanaAddress(publicKey: Uint8Array): string {
  // Solana addresses are simply base58-encoded public keys
  return bs58.encode(publicKey);
}

const solanaKey = master.derive(`m/44'/501'/${tenantIndex}'/${agentIndex}'/0`);
const solanaAddress = deriveSolanaAddress(solanaKey.publicKey!);
console.log('Solana address:', solanaAddress);
// Example: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
```

### NEAR Address

```typescript
function deriveNearAddress(publicKey: Uint8Array): string {
  // NEAR uses ed25519: prefix + base58 public key
  return `ed25519:${bs58.encode(publicKey)}`;
}

const nearKey = master.derive(`m/44'/397'/${tenantIndex}'/${agentIndex}'/0`);
const nearImplicitAccount = deriveNearAddress(nearKey.publicKey!);
console.log('NEAR implicit account:', nearImplicitAccount);
// Example: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
```

### Cosmos Address

```typescript
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { bech32 } from 'bech32';

function deriveCosmosAddress(publicKey: Uint8Array, prefix = 'cosmos'): string {
  // Cosmos: bech32(prefix, ripemd160(sha256(pubkey)))
  const hash = ripemd160(sha256(publicKey));
  return bech32.encode(prefix, bech32.toWords(hash));
}

const cosmosKey = master.derive(`m/44'/118'/${tenantIndex}'/${agentIndex}'/0`);
const cosmosAddress = deriveCosmosAddress(cosmosKey.publicKey!);
console.log('Cosmos address:', cosmosAddress);
// Example: "cosmos1abc123def456..."
```

### Stellar Address

```typescript
import { crc16 } from 'crc';

function deriveStellarAddress(publicKey: Uint8Array): string {
  // Stellar StrKey: version byte (6 << 3 = 48 for G) + pubkey + checksum
  const versionByte = 6 << 3;  // 0x30 for public key (G prefix)
  const payload = new Uint8Array([versionByte, ...publicKey]);

  // CRC-16-CCITT checksum, little-endian
  const checksum = crc16('xmodem', Buffer.from(payload));
  const checksumBytes = Buffer.alloc(2);
  checksumBytes.writeUInt16LE(checksum);

  // Base32 encode
  const full = new Uint8Array([...payload, ...checksumBytes]);
  return base32Encode(full);
}

const stellarKey = master.derive(`m/44'/148'/${tenantIndex}'/${agentIndex}'/0`);
const stellarAddress = deriveStellarAddress(stellarKey.publicKey!);
console.log('Stellar address:', stellarAddress);
// Example: "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOUJ3QBOAGZ3HJPX"
```

### Complete Address Summary

```typescript
function deriveAllAddresses(
  mnemonic: string,
  tenantId: string,
  agentId: string
): Record<string, string> {
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);

  const t = uuidToIndex(tenantId);
  const a = uuidToIndex(agentId);

  return {
    solana: deriveSolanaAddress(master.derive(`m/44'/501'/${t}'/${a}'/0`).publicKey!),
    near: deriveNearAddress(master.derive(`m/44'/397'/${t}'/${a}'/0`).publicKey!),
    stellar: deriveStellarAddress(master.derive(`m/44'/148'/${t}'/${a}'/0`).publicKey!),
    cosmos: deriveCosmosAddress(master.derive(`m/44'/118'/${t}'/${a}'/0`).publicKey!),
    aptos: '0x' + Buffer.from(master.derive(`m/44'/637'/${t}'/${a}'/0`).publicKey!).toString('hex'),
    sui: '0x' + Buffer.from(master.derive(`m/44'/784'/${t}'/${a}'/0`).publicKey!).toString('hex'),
  };
}

const addresses = deriveAllAddresses(mnemonic, tenantId, agentId);
console.log('\nAgent Addresses:');
console.table(addresses);
```

---

## Solana Integration Demo

### Setup

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

// Create connection to devnet
const connection = new Connection('https://api.devnet.solana.com', 'confirmed');

// Create keypair from derived key
function createSolanaKeypair(privateKey: Uint8Array): Keypair {
  // Solana expects 64-byte secret (32 private + 32 public)
  const publicKey = ed25519.getPublicKey(privateKey);
  return Keypair.fromSecretKey(new Uint8Array([...privateKey, ...publicKey]));
}

const solanaPrivateKey = master.derive(`m/44'/501'/${tenantIndex}'/${agentIndex}'/0`).privateKey!;
const keypair = createSolanaKeypair(solanaPrivateKey);

console.log('Solana Keypair:');
console.log('  Public key:', keypair.publicKey.toBase58());
```

### Request Airdrop (Devnet)

```typescript
async function requestAirdrop(publicKey: PublicKey, sol: number) {
  console.log(`Requesting ${sol} SOL airdrop...`);

  const signature = await connection.requestAirdrop(
    publicKey,
    sol * LAMPORTS_PER_SOL
  );

  await connection.confirmTransaction(signature);

  const balance = await connection.getBalance(publicKey);
  console.log('New balance:', balance / LAMPORTS_PER_SOL, 'SOL');

  return signature;
}

// Request 1 SOL
await requestAirdrop(keypair.publicKey, 1);
```

### Transfer SOL

```typescript
async function transferSOL(
  from: Keypair,
  to: string,
  amount: number
): Promise<string> {
  const recipient = new PublicKey(to);
  const lamports = Math.floor(amount * LAMPORTS_PER_SOL);

  console.log(`Transferring ${amount} SOL to ${to}...`);

  // Build transaction
  const tx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: from.publicKey,
      toPubkey: recipient,
      lamports,
    })
  );

  // Sign and send
  const signature = await sendAndConfirmTransaction(
    connection,
    tx,
    [from],
    { commitment: 'confirmed' }
  );

  console.log('Transaction signature:', signature);
  console.log('Explorer:', `https://explorer.solana.com/tx/${signature}?cluster=devnet`);

  return signature;
}

// Transfer 0.1 SOL to a test address
const recipientAddress = 'Hf4rPJqfC9CvhKhxFFePGcSqGXWBRJLfpjFvqQ7hPBLe';
const txSignature = await transferSOL(keypair, recipientAddress, 0.1);
```

### Complete VES-Integrated Transfer

```typescript
interface PaymentIntent {
  intentId: string;
  chain: string;
  fromAddress: string;
  toAddress: string;
  amount: string;
  currency: string;
  memo?: string;
}

interface PaymentResult {
  success: boolean;
  intentId: string;
  txHash?: string;
  error?: string;
}

class SolanaVesDemo {
  private keypair: Keypair;
  private connection: Connection;

  constructor(privateKey: Uint8Array) {
    const publicKey = ed25519.getPublicKey(privateKey);
    this.keypair = Keypair.fromSecretKey(new Uint8Array([...privateKey, ...publicKey]));
    this.connection = new Connection('https://api.devnet.solana.com', 'confirmed');
  }

  get address(): string {
    return this.keypair.publicKey.toBase58();
  }

  async transferWithVesRecording(
    recipient: string,
    amount: number,
    memo?: string
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();
    const lamports = Math.floor(amount * LAMPORTS_PER_SOL);

    // 1. Create payment intent (would be VES event in production)
    const intent: PaymentIntent = {
      intentId,
      chain: 'solana',
      fromAddress: this.address,
      toAddress: recipient,
      amount: lamports.toString(),
      currency: 'lamports',
      memo,
    };
    console.log('\n1. Payment Intent Created:');
    console.log(JSON.stringify(intent, null, 2));

    try {
      // 2. Build transaction
      const tx = new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: this.keypair.publicKey,
          toPubkey: new PublicKey(recipient),
          lamports,
        })
      );

      // 3. Sign and submit
      console.log('\n2. Signing transaction...');
      const signature = await sendAndConfirmTransaction(
        this.connection,
        tx,
        [this.keypair],
        { commitment: 'confirmed' }
      );

      console.log('3. Transaction confirmed:', signature);

      // 4. Get confirmation details
      const confirmation = await this.connection.getTransaction(signature);

      // 5. Record confirmation (would be VES event in production)
      const confirmationEvent = {
        intentId,
        chain: 'solana',
        txHash: signature,
        blockNumber: confirmation?.slot,
        status: 'confirmed',
        confirmedAt: new Date().toISOString(),
      };
      console.log('\n4. Confirmation Event:');
      console.log(JSON.stringify(confirmationEvent, null, 2));

      return {
        success: true,
        intentId,
        txHash: signature,
      };

    } catch (error: any) {
      console.error('Transaction failed:', error.message);

      // Record failure (would be VES event in production)
      const failureEvent = {
        intentId,
        chain: 'solana',
        error: error.message,
        failedAt: new Date().toISOString(),
      };
      console.log('\n4. Failure Event:');
      console.log(JSON.stringify(failureEvent, null, 2));

      return {
        success: false,
        intentId,
        error: error.message,
      };
    }
  }
}

// Demo usage
const solanaDemo = new SolanaVesDemo(solanaPrivateKey);
console.log('Agent Solana address:', solanaDemo.address);

const result = await solanaDemo.transferWithVesRecording(
  recipientAddress,
  0.05,
  'VES-CHAIN-1 Demo Payment'
);

console.log('\nFinal Result:', result);
```

---

## NEAR Protocol Demo

### Setup

```typescript
import {
  KeyPair,
  connect,
  keyStores,
  utils,
} from 'near-api-js';

// Create key pair from derived key
const nearPrivateKey = master.derive(`m/44'/397'/${tenantIndex}'/${agentIndex}'/0`).privateKey!;
const nearKeyPair = KeyPair.fromString('ed25519:' + bs58.encode(nearPrivateKey));

// Setup NEAR connection
const keyStore = new keyStores.InMemoryKeyStore();
const nearConfig = {
  networkId: 'testnet',
  keyStore,
  nodeUrl: 'https://rpc.testnet.near.org',
  walletUrl: 'https://testnet.mynearwallet.com',
  helperUrl: 'https://helper.testnet.near.org',
};

// Account ID (implicit account from public key)
const nearAccountId = Buffer.from(nearKeyPair.getPublicKey().data).toString('hex');
console.log('NEAR implicit account:', nearAccountId);

// Add key to store
await keyStore.setKey('testnet', nearAccountId, nearKeyPair);

const near = await connect(nearConfig);
const account = await near.account(nearAccountId);
```

### Check Balance

```typescript
async function getNearBalance(account: Account): Promise<string> {
  const balance = await account.getAccountBalance();
  return utils.format.formatNearAmount(balance.available);
}

const balance = await getNearBalance(account);
console.log('NEAR balance:', balance, 'NEAR');
```

### Transfer NEAR

```typescript
class NearVesDemo {
  private account: Account;

  constructor(account: Account) {
    this.account = account;
  }

  get address(): string {
    return this.account.accountId;
  }

  async transferWithVesRecording(
    recipient: string,
    amount: string  // in NEAR
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();
    const yoctoNear = utils.format.parseNearAmount(amount)!;

    // 1. Create payment intent
    console.log('\n1. Payment Intent Created:');
    console.log(JSON.stringify({
      intentId,
      chain: 'near',
      fromAddress: this.address,
      toAddress: recipient,
      amount: yoctoNear,
      currency: 'yoctoNEAR',
    }, null, 2));

    try {
      // 2. Execute transfer
      console.log('\n2. Executing transfer...');
      const result = await this.account.sendMoney(recipient, yoctoNear);

      console.log('3. Transaction hash:', result.transaction.hash);
      console.log('Explorer:', `https://testnet.nearblocks.io/txns/${result.transaction.hash}`);

      // 3. Record confirmation
      console.log('\n4. Confirmation Event:');
      console.log(JSON.stringify({
        intentId,
        chain: 'near',
        txHash: result.transaction.hash,
        blockHash: result.transaction_outcome.block_hash,
        status: 'confirmed',
      }, null, 2));

      return {
        success: true,
        intentId,
        txHash: result.transaction.hash,
      };

    } catch (error: any) {
      console.error('Transaction failed:', error.message);
      return {
        success: false,
        intentId,
        error: error.message,
      };
    }
  }
}

// Demo usage
const nearDemo = new NearVesDemo(account);
const nearResult = await nearDemo.transferWithVesRecording(
  'recipient.testnet',
  '0.1'
);
```

### Contract Call Example

```typescript
async function callContract(
  account: Account,
  contractId: string,
  methodName: string,
  args: object
): Promise<any> {
  const intentId = crypto.randomUUID();

  console.log('\nContract Call Intent:');
  console.log(JSON.stringify({
    intentId,
    chain: 'near',
    operation: 'contract_call',
    contract: contractId,
    method: methodName,
    args,
  }, null, 2));

  const result = await account.functionCall({
    contractId,
    methodName,
    args,
    gas: '30000000000000',
    attachedDeposit: '0',
  });

  console.log('Transaction hash:', result.transaction.hash);

  return result;
}

// Example: Call a contract method
// await callContract(account, 'wrap.testnet', 'storage_deposit', {});
```

---

## Cosmos SDK Demo

### Setup

```typescript
import { DirectSecp256k1Wallet } from '@cosmjs/proto-signing';
import { SigningStargateClient, coin } from '@cosmjs/stargate';

// For Ed25519, Cosmos chains that support it (like some Tendermint chains)
// Note: Standard Cosmos Hub uses secp256k1, so this demo shows the pattern

const cosmosPrivateKey = master.derive(`m/44'/118'/${tenantIndex}'/${agentIndex}'/0`).privateKey!;

// Create wallet (this example uses the pattern, actual implementation depends on chain)
async function createCosmosWallet(privateKey: Uint8Array, prefix: string) {
  // For chains supporting Ed25519:
  const wallet = await DirectSecp256k1Wallet.fromKey(privateKey, prefix);
  const [firstAccount] = await wallet.getAccounts();
  return { wallet, address: firstAccount.address };
}

const { wallet, address } = await createCosmosWallet(cosmosPrivateKey, 'cosmos');
console.log('Cosmos address:', address);

// Connect to testnet
const rpcUrl = 'https://rpc.sentry-01.theta-testnet.polypore.xyz';
const client = await SigningStargateClient.connectWithSigner(rpcUrl, wallet);
```

### Transfer Tokens

```typescript
class CosmosVesDemo {
  private client: SigningStargateClient;
  private address: string;

  constructor(client: SigningStargateClient, address: string) {
    this.client = client;
    this.address = address;
  }

  async transferWithVesRecording(
    recipient: string,
    amount: string,
    denom: string
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();

    // 1. Create payment intent
    console.log('\n1. Payment Intent Created:');
    console.log(JSON.stringify({
      intentId,
      chain: 'cosmos',
      fromAddress: this.address,
      toAddress: recipient,
      amount,
      currency: denom,
    }, null, 2));

    try {
      // 2. Execute transfer
      console.log('\n2. Executing transfer...');
      const result = await this.client.sendTokens(
        this.address,
        recipient,
        [coin(amount, denom)],
        'auto',
        'VES-CHAIN-1 Demo Payment'
      );

      console.log('3. Transaction hash:', result.transactionHash);
      console.log('Block height:', result.height);

      // 3. Record confirmation
      const status = result.code === 0 ? 'confirmed' : 'failed';
      console.log('\n4. Confirmation Event:');
      console.log(JSON.stringify({
        intentId,
        chain: 'cosmos',
        txHash: result.transactionHash,
        blockNumber: result.height,
        status,
        gasUsed: result.gasUsed,
      }, null, 2));

      return {
        success: result.code === 0,
        intentId,
        txHash: result.transactionHash,
      };

    } catch (error: any) {
      console.error('Transaction failed:', error.message);
      return {
        success: false,
        intentId,
        error: error.message,
      };
    }
  }
}

// Demo usage
const cosmosDemo = new CosmosVesDemo(client, address);
const cosmosResult = await cosmosDemo.transferWithVesRecording(
  'cosmos1recipient...',
  '1000000',
  'uatom'
);
```

---

## Multi-Chain Agent Demo

### Complete Multi-Chain Implementation

```typescript
interface ChainConfig {
  rpcUrl: string;
  networkId?: string;
  accountId?: string;
}

class MultiChainVesAgent {
  private mnemonic: string;
  private tenantId: string;
  private agentId: string;
  private chainClients: Map<string, any> = new Map();

  constructor(mnemonic: string, tenantId: string, agentId: string) {
    this.mnemonic = mnemonic;
    this.tenantId = tenantId;
    this.agentId = agentId;
  }

  private deriveKey(coinType: number): Uint8Array {
    const seed = mnemonicToSeedSync(this.mnemonic);
    const master = HDKey.fromMasterSeed(seed);
    const t = uuidToIndex(this.tenantId);
    const a = uuidToIndex(this.agentId);
    return master.derive(`m/44'/${coinType}'/${t}'/${a}'/0`).privateKey!;
  }

  async initializeSolana(config: ChainConfig): Promise<void> {
    const privateKey = this.deriveKey(501);
    const publicKey = ed25519.getPublicKey(privateKey);
    const keypair = Keypair.fromSecretKey(new Uint8Array([...privateKey, ...publicKey]));
    const connection = new Connection(config.rpcUrl, 'confirmed');

    this.chainClients.set('solana', { keypair, connection });
    console.log('Solana initialized:', keypair.publicKey.toBase58());
  }

  async initializeNear(config: ChainConfig): Promise<void> {
    const privateKey = this.deriveKey(397);
    const keyPair = KeyPair.fromString('ed25519:' + bs58.encode(privateKey));
    const accountId = config.accountId || Buffer.from(keyPair.getPublicKey().data).toString('hex');

    const keyStore = new keyStores.InMemoryKeyStore();
    await keyStore.setKey(config.networkId || 'testnet', accountId, keyPair);

    const near = await connect({
      networkId: config.networkId || 'testnet',
      keyStore,
      nodeUrl: config.rpcUrl,
    });

    const account = await near.account(accountId);
    this.chainClients.set('near', { account, keyPair });
    console.log('NEAR initialized:', accountId);
  }

  getAddresses(): Record<string, string> {
    const addresses: Record<string, string> = {};

    if (this.chainClients.has('solana')) {
      addresses.solana = this.chainClients.get('solana').keypair.publicKey.toBase58();
    }
    if (this.chainClients.has('near')) {
      addresses.near = this.chainClients.get('near').account.accountId;
    }

    return addresses;
  }

  async transfer(
    chain: string,
    recipient: string,
    amount: string
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();

    console.log(`\n=== ${chain.toUpperCase()} Transfer ===`);
    console.log('Intent ID:', intentId);
    console.log('Recipient:', recipient);
    console.log('Amount:', amount);

    switch (chain) {
      case 'solana':
        return this.transferSolana(intentId, recipient, parseFloat(amount));
      case 'near':
        return this.transferNear(intentId, recipient, amount);
      default:
        throw new Error(`Unsupported chain: ${chain}`);
    }
  }

  private async transferSolana(
    intentId: string,
    recipient: string,
    amount: number
  ): Promise<PaymentResult> {
    const { keypair, connection } = this.chainClients.get('solana');
    const lamports = Math.floor(amount * LAMPORTS_PER_SOL);

    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: keypair.publicKey,
        toPubkey: new PublicKey(recipient),
        lamports,
      })
    );

    const signature = await sendAndConfirmTransaction(connection, tx, [keypair]);
    console.log('Solana TX:', signature);

    return { success: true, intentId, txHash: signature };
  }

  private async transferNear(
    intentId: string,
    recipient: string,
    amount: string
  ): Promise<PaymentResult> {
    const { account } = this.chainClients.get('near');
    const yoctoNear = utils.format.parseNearAmount(amount)!;

    const result = await account.sendMoney(recipient, yoctoNear);
    console.log('NEAR TX:', result.transaction.hash);

    return { success: true, intentId, txHash: result.transaction.hash };
  }
}

// Demo usage
async function multiChainDemo() {
  const agent = new MultiChainVesAgent(
    mnemonic,
    '00000000-0000-0000-0000-000000000001',
    '22222222-2222-2222-2222-222222222222'
  );

  // Initialize chains
  await agent.initializeSolana({ rpcUrl: 'https://api.devnet.solana.com' });
  await agent.initializeNear({ rpcUrl: 'https://rpc.testnet.near.org' });

  // Show addresses
  console.log('\nAgent Addresses:');
  console.table(agent.getAddresses());

  // Execute transfers (uncomment to run)
  // await agent.transfer('solana', 'recipient-address', '0.1');
  // await agent.transfer('near', 'recipient.testnet', '0.1');
}

await multiChainDemo();
```

---

## VES Event Recording

### Complete Event Recording Flow

```typescript
interface VesEvent {
  eventId: string;
  tenantId: string;
  storeId: string;
  entityType: string;
  entityId: string;
  eventType: string;
  payload: object;
  createdAt: string;
}

class VesBlockchainRecorder {
  private events: VesEvent[] = [];

  async recordPaymentIntent(
    tenantId: string,
    storeId: string,
    intent: PaymentIntent
  ): Promise<string> {
    const event: VesEvent = {
      eventId: crypto.randomUUID(),
      tenantId,
      storeId,
      entityType: 'Payment',
      entityId: intent.intentId,
      eventType: 'PaymentIntentCreated',
      payload: intent,
      createdAt: new Date().toISOString(),
    };

    this.events.push(event);
    console.log('VES Event recorded:', event.eventType, event.eventId);
    return event.eventId;
  }

  async recordTransactionSigned(
    tenantId: string,
    storeId: string,
    intentId: string,
    signature: string,
    rawTxHash: string
  ): Promise<string> {
    const event: VesEvent = {
      eventId: crypto.randomUUID(),
      tenantId,
      storeId,
      entityType: 'Payment',
      entityId: intentId,
      eventType: 'TransactionSigned',
      payload: {
        intent_id: intentId,
        signature,
        raw_tx_hash: rawTxHash,
        signed_at: new Date().toISOString(),
      },
      createdAt: new Date().toISOString(),
    };

    this.events.push(event);
    console.log('VES Event recorded:', event.eventType, event.eventId);
    return event.eventId;
  }

  async recordTransactionConfirmed(
    tenantId: string,
    storeId: string,
    intentId: string,
    confirmation: {
      txHash: string;
      blockNumber?: number;
      blockHash?: string;
      status: string;
    }
  ): Promise<string> {
    const event: VesEvent = {
      eventId: crypto.randomUUID(),
      tenantId,
      storeId,
      entityType: 'Payment',
      entityId: intentId,
      eventType: 'TransactionConfirmed',
      payload: {
        intent_id: intentId,
        ...confirmation,
        confirmed_at: new Date().toISOString(),
      },
      createdAt: new Date().toISOString(),
    };

    this.events.push(event);
    console.log('VES Event recorded:', event.eventType, event.eventId);
    return event.eventId;
  }

  async recordTransactionFailed(
    tenantId: string,
    storeId: string,
    intentId: string,
    error: string
  ): Promise<string> {
    const event: VesEvent = {
      eventId: crypto.randomUUID(),
      tenantId,
      storeId,
      entityType: 'Payment',
      entityId: intentId,
      eventType: 'TransactionFailed',
      payload: {
        intent_id: intentId,
        error,
        failed_at: new Date().toISOString(),
      },
      createdAt: new Date().toISOString(),
    };

    this.events.push(event);
    console.log('VES Event recorded:', event.eventType, event.eventId);
    return event.eventId;
  }

  getEventsForPayment(intentId: string): VesEvent[] {
    return this.events.filter(e => e.entityId === intentId);
  }

  getAllEvents(): VesEvent[] {
    return [...this.events];
  }
}

// Demo: Complete payment flow with VES recording
async function vesRecordingDemo() {
  const recorder = new VesBlockchainRecorder();
  const tenantId = '00000000-0000-0000-0000-000000000001';
  const storeId = '00000000-0000-0000-0000-000000000002';
  const intentId = crypto.randomUUID();

  console.log('\n=== VES Event Recording Demo ===\n');

  // 1. Record payment intent
  await recorder.recordPaymentIntent(tenantId, storeId, {
    intentId,
    chain: 'solana',
    fromAddress: 'AgentAddress123...',
    toAddress: 'RecipientAddress456...',
    amount: '1000000000',
    currency: 'lamports',
    memo: 'Invoice #INV-2025-001',
  });

  // 2. Record transaction signed
  await recorder.recordTransactionSigned(
    tenantId,
    storeId,
    intentId,
    '0x' + 'a'.repeat(128),  // Mock signature
    '0x' + 'b'.repeat(64)   // Mock TX hash
  );

  // 3. Record confirmation
  await recorder.recordTransactionConfirmed(tenantId, storeId, intentId, {
    txHash: '5wHu1qwD7q4abc123...',
    blockNumber: 234567890,
    blockHash: 'abc123...',
    status: 'confirmed',
  });

  // Show all events for this payment
  console.log('\n=== Payment Event Timeline ===');
  const events = recorder.getEventsForPayment(intentId);
  events.forEach((event, i) => {
    console.log(`\n${i + 1}. ${event.eventType}`);
    console.log('   Event ID:', event.eventId);
    console.log('   Created:', event.createdAt);
    console.log('   Payload:', JSON.stringify(event.payload, null, 4).split('\n').join('\n   '));
  });
}

await vesRecordingDemo();
```

---

## On-Chain Anchoring Demo

### Anchor VES Commitments to Solana

```typescript
import { sha256 } from '@noble/hashes/sha256';

interface VesCommitment {
  streamId: Uint8Array;
  sequenceStart: number;
  sequenceEnd: number;
  eventsRoot: Uint8Array;
  prevEventsRoot: Uint8Array;
}

class VesAnchoringDemo {
  private connection: Connection;
  private payer: Keypair;

  constructor(connection: Connection, payer: Keypair) {
    this.connection = connection;
    this.payer = payer;
  }

  computeStreamId(tenantId: string, storeId: string): Uint8Array {
    const tenantBytes = Buffer.from(tenantId.replace(/-/g, ''), 'hex');
    const storeBytes = Buffer.from(storeId.replace(/-/g, ''), 'hex');
    return sha256(new Uint8Array([...tenantBytes, ...storeBytes]));
  }

  encodeCommitment(commitment: VesCommitment): Buffer {
    const buffer = Buffer.alloc(8 + 32 + 8 + 8 + 32 + 32);  // 120 bytes
    let offset = 0;

    // Instruction discriminator (simplified)
    buffer.writeBigUInt64LE(BigInt(0), offset);  // 0 = anchor_commitment
    offset += 8;

    // stream_id (32 bytes)
    Buffer.from(commitment.streamId).copy(buffer, offset);
    offset += 32;

    // sequence_start (u64)
    buffer.writeBigUInt64LE(BigInt(commitment.sequenceStart), offset);
    offset += 8;

    // sequence_end (u64)
    buffer.writeBigUInt64LE(BigInt(commitment.sequenceEnd), offset);
    offset += 8;

    // events_root (32 bytes)
    Buffer.from(commitment.eventsRoot).copy(buffer, offset);
    offset += 32;

    // prev_events_root (32 bytes)
    Buffer.from(commitment.prevEventsRoot).copy(buffer, offset);

    return buffer;
  }

  async anchorCommitment(commitment: VesCommitment): Promise<string> {
    console.log('\n=== Anchoring VES Commitment ===');
    console.log('Stream ID:', Buffer.from(commitment.streamId).toString('hex'));
    console.log('Sequence range:', commitment.sequenceStart, '-', commitment.sequenceEnd);
    console.log('Events root:', Buffer.from(commitment.eventsRoot).toString('hex'));

    // In production, this would call an actual anchor program
    // For demo, we use a memo transaction to store the commitment
    const data = this.encodeCommitment(commitment);

    const tx = new Transaction().add(
      new TransactionInstruction({
        keys: [],
        programId: new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),
        data,
      })
    );

    const signature = await sendAndConfirmTransaction(
      this.connection,
      tx,
      [this.payer]
    );

    console.log('Anchor TX:', signature);
    console.log('Explorer:', `https://explorer.solana.com/tx/${signature}?cluster=devnet`);

    return signature;
  }
}

// Demo usage
async function anchoringDemo() {
  const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
  const solanaPrivateKey = master.derive(`m/44'/501'/${tenantIndex}'/${agentIndex}'/0`).privateKey!;
  const publicKey = ed25519.getPublicKey(solanaPrivateKey);
  const payer = Keypair.fromSecretKey(new Uint8Array([...solanaPrivateKey, ...publicKey]));

  const anchoring = new VesAnchoringDemo(connection, payer);

  // Create mock commitment
  const tenantId = '00000000-0000-0000-0000-000000000001';
  const storeId = '00000000-0000-0000-0000-000000000002';

  const commitment: VesCommitment = {
    streamId: anchoring.computeStreamId(tenantId, storeId),
    sequenceStart: 1,
    sequenceEnd: 100,
    eventsRoot: sha256(Buffer.from('events-merkle-root')),
    prevEventsRoot: new Uint8Array(32),  // Genesis (all zeros)
  };

  const txSignature = await anchoring.anchorCommitment(commitment);
  console.log('\nCommitment anchored!');
}

// await anchoringDemo();  // Uncomment to run
```

---

## Batch Payments Demo

### Execute Multiple Payments

```typescript
interface BatchPayment {
  recipient: string;
  amount: string;
  memo?: string;
}

interface BatchResult {
  batchId: string;
  total: number;
  successful: number;
  failed: number;
  results: PaymentResult[];
}

async function executeBatchPayments(
  agent: MultiChainVesAgent,
  chain: string,
  payments: BatchPayment[],
  recorder: VesBlockchainRecorder,
  tenantId: string,
  storeId: string
): Promise<BatchResult> {
  const batchId = crypto.randomUUID();
  const results: PaymentResult[] = [];

  console.log('\n=== Batch Payments ===');
  console.log('Batch ID:', batchId);
  console.log('Total payments:', payments.length);

  // Record batch intent
  await recorder.recordPaymentIntent(tenantId, storeId, {
    intentId: batchId,
    chain,
    fromAddress: agent.getAddresses()[chain],
    toAddress: 'batch',
    amount: payments.reduce((sum, p) => sum + parseFloat(p.amount), 0).toString(),
    currency: chain === 'solana' ? 'SOL' : 'native',
    memo: `Batch of ${payments.length} payments`,
  });

  // Execute each payment
  for (let i = 0; i < payments.length; i++) {
    const payment = payments[i];
    console.log(`\nProcessing ${i + 1}/${payments.length}:`, payment.recipient);

    try {
      const result = await agent.transfer(chain, payment.recipient, payment.amount);
      results.push(result);

      if (result.success) {
        console.log('  Success:', result.txHash);
      } else {
        console.log('  Failed:', result.error);
      }
    } catch (error: any) {
      results.push({
        success: false,
        intentId: crypto.randomUUID(),
        error: error.message,
      });
      console.log('  Error:', error.message);
    }
  }

  // Record batch completion
  const successful = results.filter(r => r.success).length;
  const failed = results.length - successful;

  console.log('\n=== Batch Complete ===');
  console.log('Successful:', successful);
  console.log('Failed:', failed);

  return {
    batchId,
    total: payments.length,
    successful,
    failed,
    results,
  };
}

// Demo usage
async function batchDemo() {
  const agent = new MultiChainVesAgent(mnemonic, tenantId, agentId);
  await agent.initializeSolana({ rpcUrl: 'https://api.devnet.solana.com' });

  const recorder = new VesBlockchainRecorder();

  const payments: BatchPayment[] = [
    { recipient: 'Address1...', amount: '0.01', memo: 'Payment 1' },
    { recipient: 'Address2...', amount: '0.02', memo: 'Payment 2' },
    { recipient: 'Address3...', amount: '0.015', memo: 'Payment 3' },
  ];

  const result = await executeBatchPayments(
    agent,
    'solana',
    payments,
    recorder,
    tenantId,
    storeId
  );

  console.log('\nBatch result:', JSON.stringify(result, null, 2));
}

// await batchDemo();  // Uncomment to run
```

---

## Troubleshooting

### Common Issues

#### 1. Key Derivation Mismatch

**Problem:** Different addresses generated for the same mnemonic

**Solution:**
```typescript
// Ensure consistent UUID parsing
function uuidToIndex(uuid: string): number {
  // Always remove hyphens and parse as hex
  const bytes = Buffer.from(uuid.replace(/-/g, ''), 'hex');
  // Always use big-endian and mask to 31 bits
  return bytes.readUInt32BE(0) & 0x7FFFFFFF;
}

// Verify with test case:
const testUuid = '00000000-0000-0000-0000-000000000001';
console.assert(uuidToIndex(testUuid) === 0, 'Index should be 0');
```

#### 2. Solana Transaction Fails

**Problem:** "Insufficient funds for rent"

**Solution:**
```typescript
// Ensure minimum balance (rent exemption) before transfers
const MIN_BALANCE_LAMPORTS = 890880;  // For basic account

async function checkBalance(connection: Connection, publicKey: PublicKey) {
  const balance = await connection.getBalance(publicKey);
  if (balance < MIN_BALANCE_LAMPORTS) {
    throw new Error(`Insufficient balance. Need at least ${MIN_BALANCE_LAMPORTS} lamports`);
  }
  return balance;
}
```

#### 3. NEAR Account Not Found

**Problem:** "Account does not exist"

**Solution:**
```typescript
// For implicit accounts, the account must be funded first
async function ensureNearAccount(near: Near, accountId: string) {
  try {
    const account = await near.account(accountId);
    await account.state();
    return account;
  } catch (e) {
    console.log('Account needs funding. Send NEAR to:', accountId);
    throw new Error(`Account ${accountId} not funded`);
  }
}
```

#### 4. Invalid Signature Format

**Problem:** Chain rejects signature

**Solution:**
```typescript
// Different chains have different signature expectations

// Solana: 64-byte secret key (32 private + 32 public)
const solanaSecret = new Uint8Array([...privateKey, ...ed25519.getPublicKey(privateKey)]);

// NEAR: ed25519: prefix
const nearKey = 'ed25519:' + bs58.encode(privateKey);

// Cosmos: Depends on chain (some use secp256k1)
```

#### 5. Transaction Timeout

**Problem:** Transaction not confirmed in time

**Solution:**
```typescript
// Use appropriate commitment level and retry logic
async function sendWithRetry(
  connection: Connection,
  tx: Transaction,
  signers: Keypair[],
  maxRetries = 3
): Promise<string> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await sendAndConfirmTransaction(
        connection,
        tx,
        signers,
        {
          commitment: 'confirmed',
          maxRetries: 5,
        }
      );
    } catch (e) {
      if (i === maxRetries - 1) throw e;
      console.log(`Retry ${i + 1}/${maxRetries}...`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
  throw new Error('Max retries exceeded');
}
```

### Debug Checklist

1. **Verify key derivation**
   - Check mnemonic is valid BIP-39
   - Verify derivation path matches chain requirements
   - Confirm UUID to index conversion

2. **Check network configuration**
   - Correct RPC endpoint
   - Appropriate network (mainnet vs testnet)
   - Sufficient balance for fees

3. **Validate transaction structure**
   - Correct address formats
   - Proper amount encoding
   - Required signatures present

4. **Review VES recording**
   - Intent recorded before execution
   - Confirmation recorded after success
   - Failure recorded on error

---

## Next Steps

1. **Production Setup**
   - Use HSM for key storage
   - Configure rate limiting
   - Set up monitoring

2. **Additional Chains**
   - Implement Stellar, Aptos, Sui integrations
   - Add token support per chain

3. **Advanced Features**
   - Multi-signature transactions
   - Escrow smart contracts
   - Cross-chain bridges

---

*See [VES_CHAIN_1_SPECIFICATION.md](./VES_CHAIN_1_SPECIFICATION.md) for the complete specification.*
