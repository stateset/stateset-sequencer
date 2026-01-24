#!/usr/bin/env node
/**
 * x402 Agent-to-Agent Payments Demo
 *
 * This demo showcases the complete x402 payment flow:
 *
 * 1. Two AI agents (Alice and Bob) are initialized with Ed25519 keypairs
 * 2. Alice pays Bob 1.00 USDC for "API access"
 * 3. Bob pays Alice 0.50 USDC for "Data query"
 * 4. Both payments are sequenced by the StateSet Sequencer
 * 5. Payments are batched and committed with Merkle root
 * 6. Receipts with inclusion proofs are generated
 *
 * Usage:
 *   node scripts/x402_demo.mjs [--url <sequencer-url>]
 *
 * Environment:
 *   SEQUENCER_URL - Base URL for the sequencer (default: http://localhost:8080)
 */

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { webcrypto } from 'crypto';

// Polyfill for Node.js
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// =============================================================================
// Configuration
// =============================================================================

const SEQUENCER_URL = process.env.SEQUENCER_URL || process.argv.find(a => a.startsWith('--url='))?.split('=')[1] || 'http://localhost:8080';
const X402_DOMAIN_SEPARATOR = 'X402_PAYMENT_V1';

// Test tenant/store IDs (would be real UUIDs in production)
const TENANT_ID = '11111111-1111-1111-1111-111111111111';
const STORE_ID = '22222222-2222-2222-2222-222222222222';

// Network configuration
const NETWORK = 'set_chain';
const CHAIN_ID = 84532001n;

// =============================================================================
// Utilities
// =============================================================================

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function formatUsdc(amount) {
  return (Number(amount) / 1_000_000).toFixed(2);
}

function bigIntToBeBytes(value, length) {
  const bytes = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

function generateUuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// =============================================================================
// x402 Payment Functions
// =============================================================================

/**
 * Compute the signing hash for a payment intent
 */
function computeSigningHash(params) {
  const encoder = new TextEncoder();
  const parts = [
    encoder.encode(X402_DOMAIN_SEPARATOR),
    encoder.encode(params.payer),
    encoder.encode(params.payee),
    bigIntToBeBytes(BigInt(params.amount), 8),
    encoder.encode(params.asset.toLowerCase()),
    encoder.encode(params.network),
    bigIntToBeBytes(BigInt(params.chainId), 8),
    bigIntToBeBytes(BigInt(params.validUntil), 8),
    bigIntToBeBytes(BigInt(params.nonce), 8),
  ];

  const totalLength = parts.reduce((acc, p) => acc + p.length, 0);
  const message = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }

  return sha256(message);
}

/**
 * Create and sign a payment intent
 */
async function createPaymentIntent(agent, payee, amount, description) {
  const now = Math.floor(Date.now() / 1000);
  const validUntil = now + 3600; // 1 hour validity
  const nonce = now * 1000 + Math.floor(Math.random() * 1000);

  const params = {
    payer: agent.address,
    payee,
    amount,
    asset: 'usdc',
    network: NETWORK,
    chainId: CHAIN_ID,
    validUntil,
    nonce,
  };

  const signingHash = computeSigningHash(params);
  const signature = await ed.signAsync(signingHash, agent.privateKey);

  return {
    tenant_id: TENANT_ID,
    store_id: STORE_ID,
    agent_id: agent.id,
    agent_key_id: 1,
    payer_address: agent.address,
    payee_address: payee,
    amount,
    asset: 'usdc',
    network: NETWORK,
    valid_until: validUntil,
    nonce,
    signing_hash: '0x' + bytesToHex(signingHash),
    payer_signature: '0x' + bytesToHex(signature),
    payer_public_key: '0x' + bytesToHex(agent.publicKey),
    description,
    idempotency_key: `${agent.id}-${nonce}`,
  };
}

/**
 * Submit a payment intent to the sequencer
 */
async function submitPayment(intent) {
  const response = await fetch(`${SEQUENCER_URL}/api/v1/x402/payments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(intent),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Payment submission failed: ${response.status} - ${error}`);
  }

  return response.json();
}

/**
 * Get payment status
 */
async function getPaymentStatus(intentId) {
  const response = await fetch(`${SEQUENCER_URL}/api/v1/x402/payments/${intentId}`);
  if (!response.ok) {
    throw new Error(`Failed to get status: ${response.status}`);
  }
  return response.json();
}

/**
 * Get payment receipt
 */
async function getPaymentReceipt(intentId) {
  const response = await fetch(`${SEQUENCER_URL}/api/v1/x402/payments/${intentId}/receipt`);
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to get receipt: ${response.status} - ${error}`);
  }
  return response.json();
}

/**
 * Create a payment batch
 */
async function createBatch() {
  const response = await fetch(`${SEQUENCER_URL}/api/v1/x402/batches`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      tenant_id: TENANT_ID,
      store_id: STORE_ID,
      network: NETWORK,
      max_size: 100,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Batch creation failed: ${response.status} - ${error}`);
  }

  return response.json();
}

/**
 * Get batch status
 */
async function getBatchStatus(batchId) {
  const response = await fetch(`${SEQUENCER_URL}/api/v1/x402/batches/${batchId}`);
  if (!response.ok) {
    throw new Error(`Failed to get batch: ${response.status}`);
  }
  return response.json();
}

// =============================================================================
// Agent Class
// =============================================================================

class Agent {
  constructor(name, privateKey) {
    this.name = name;
    this.id = generateUuid();
    this.privateKey = privateKey;
    this.publicKey = null;
    this.address = null;
  }

  async initialize() {
    this.publicKey = await ed.getPublicKeyAsync(this.privateKey);
    this.address = '0x' + bytesToHex(this.publicKey);
    return this;
  }

  static async create(name) {
    const privateKey = ed.utils.randomPrivateKey();
    const agent = new Agent(name, privateKey);
    await agent.initialize();
    return agent;
  }

  toString() {
    return `${this.name} (${this.address.slice(0, 10)}...${this.address.slice(-8)})`;
  }
}

// =============================================================================
// Demo Script
// =============================================================================

async function runDemo() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║           x402 Agent-to-Agent Payments Demo                      ║');
  console.log('║                  StateSet Sequencer                              ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`Sequencer URL: ${SEQUENCER_URL}`);
  console.log(`Network: ${NETWORK} (Chain ID: ${CHAIN_ID})`);
  console.log('');

  // =========================================================================
  // Step 1: Initialize Agents
  // =========================================================================

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('STEP 1: Initialize AI Agents');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  const alice = await Agent.create('Alice');
  const bob = await Agent.create('Bob');

  console.log('Created two AI agents with Ed25519 keypairs:');
  console.log('');
  console.log(`  Agent A: ${alice.name}`);
  console.log(`    ID:      ${alice.id}`);
  console.log(`    Address: ${alice.address}`);
  console.log('');
  console.log(`  Agent B: ${bob.name}`);
  console.log(`    ID:      ${bob.id}`);
  console.log(`    Address: ${bob.address}`);
  console.log('');

  // =========================================================================
  // Step 2: Alice pays Bob
  // =========================================================================

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('STEP 2: Alice Pays Bob (1.00 USDC for API Access)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  const payment1Amount = 1_000_000; // 1.00 USDC
  console.log(`Alice is paying Bob ${formatUsdc(payment1Amount)} USDC for "API access"...`);
  console.log('');

  // Create and sign payment intent
  console.log('  1. Creating payment intent...');
  const intent1 = await createPaymentIntent(alice, bob.address, payment1Amount, 'Payment for API access');
  console.log(`     Signing hash: ${intent1.signing_hash.slice(0, 18)}...`);
  console.log(`     Signature:    ${intent1.payer_signature.slice(0, 18)}...`);
  console.log('');

  // Submit to sequencer
  console.log('  2. Submitting to sequencer...');
  let result1;
  try {
    result1 = await submitPayment(intent1);
    console.log(`     Intent ID:       ${result1.intent_id}`);
    console.log(`     Status:          ${result1.status}`);
    console.log(`     Sequence Number: ${result1.sequence_number}`);
    console.log('');
  } catch (e) {
    console.log(`     ERROR: ${e.message}`);
    console.log('     (Make sure the sequencer is running and the database has the x402 tables)');
    console.log('');
    return;
  }

  // =========================================================================
  // Step 3: Bob pays Alice
  // =========================================================================

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('STEP 3: Bob Pays Alice (0.50 USDC for Data Query)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  const payment2Amount = 500_000; // 0.50 USDC
  console.log(`Bob is paying Alice ${formatUsdc(payment2Amount)} USDC for "Data query"...`);
  console.log('');

  // Create and sign payment intent
  console.log('  1. Creating payment intent...');
  const intent2 = await createPaymentIntent(bob, alice.address, payment2Amount, 'Payment for data query');
  console.log(`     Signing hash: ${intent2.signing_hash.slice(0, 18)}...`);
  console.log(`     Signature:    ${intent2.payer_signature.slice(0, 18)}...`);
  console.log('');

  // Submit to sequencer
  console.log('  2. Submitting to sequencer...');
  let result2;
  try {
    result2 = await submitPayment(intent2);
    console.log(`     Intent ID:       ${result2.intent_id}`);
    console.log(`     Status:          ${result2.status}`);
    console.log(`     Sequence Number: ${result2.sequence_number}`);
    console.log('');
  } catch (e) {
    console.log(`     ERROR: ${e.message}`);
    return;
  }

  // =========================================================================
  // Step 4: Check Payment Status
  // =========================================================================

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('STEP 4: Check Payment Status');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  console.log('Querying payment status from sequencer...');
  console.log('');

  try {
    const status1 = await getPaymentStatus(result1.intent_id);
    console.log(`  Payment 1 (Alice -> Bob):`);
    console.log(`    Intent ID:  ${status1.intent_id}`);
    console.log(`    Status:     ${status1.status}`);
    console.log(`    Sequence #: ${status1.sequence_number}`);
    console.log('');

    const status2 = await getPaymentStatus(result2.intent_id);
    console.log(`  Payment 2 (Bob -> Alice):`);
    console.log(`    Intent ID:  ${status2.intent_id}`);
    console.log(`    Status:     ${status2.status}`);
    console.log(`    Sequence #: ${status2.sequence_number}`);
    console.log('');
  } catch (e) {
    console.log(`  ERROR: ${e.message}`);
    return;
  }

  // =========================================================================
  // Step 5: Create Batch
  // =========================================================================

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('STEP 5: Create Payment Batch');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  console.log('Creating batch from sequenced payments...');
  console.log('');

  let batchResult;
  try {
    batchResult = await createBatch();
    console.log(`  Batch ID:       ${batchResult.batch_id}`);
    console.log(`  Status:         ${batchResult.status}`);
    console.log(`  Payment Count:  ${batchResult.payment_count}`);
    console.log(`  Sequence Range: ${batchResult.sequence_range[0]} - ${batchResult.sequence_range[1]}`);
    if (batchResult.merkle_root) {
      console.log(`  Merkle Root:    ${batchResult.merkle_root}`);
    }
    console.log('');
  } catch (e) {
    console.log(`  ERROR: ${e.message}`);
    console.log('  (This may mean no pending payments to batch, which is OK if batch worker already ran)');
    console.log('');
  }

  // =========================================================================
  // Step 6: Get Receipts with Merkle Proofs
  // =========================================================================

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('STEP 6: Get Payment Receipts');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  console.log('Fetching receipts with Merkle inclusion proofs...');
  console.log('');

  try {
    const receipt1 = await getPaymentReceipt(result1.intent_id);
    console.log(`  Receipt for Payment 1 (Alice -> Bob):`);
    console.log(`    Receipt ID:    ${receipt1.receipt.receipt_id}`);
    console.log(`    Batch ID:      ${receipt1.receipt.batch_id}`);
    console.log(`    Sequence #:    ${receipt1.receipt.sequence_number}`);
    console.log(`    Merkle Root:   ${receipt1.receipt.merkle_root ? '0x' + bytesToHex(new Uint8Array(receipt1.receipt.merkle_root)) : 'N/A'}`);
    console.log(`    Leaf Index:    ${receipt1.receipt.leaf_index}`);
    console.log(`    Proof Length:  ${receipt1.receipt.inclusion_proof?.length || 0} elements`);
    console.log(`    Amount:        ${formatUsdc(receipt1.receipt.amount)} ${receipt1.receipt.asset.toUpperCase()}`);
    console.log(`    Payer:         ${receipt1.receipt.payer_address.slice(0, 10)}...`);
    console.log(`    Payee:         ${receipt1.receipt.payee_address.slice(0, 10)}...`);
    console.log('');
  } catch (e) {
    console.log(`  Receipt 1 not available yet: ${e.message}`);
    console.log('  (Payments need to be batched first)');
    console.log('');
  }

  try {
    const receipt2 = await getPaymentReceipt(result2.intent_id);
    console.log(`  Receipt for Payment 2 (Bob -> Alice):`);
    console.log(`    Receipt ID:    ${receipt2.receipt.receipt_id}`);
    console.log(`    Batch ID:      ${receipt2.receipt.batch_id}`);
    console.log(`    Sequence #:    ${receipt2.receipt.sequence_number}`);
    console.log(`    Merkle Root:   ${receipt2.receipt.merkle_root ? '0x' + bytesToHex(new Uint8Array(receipt2.receipt.merkle_root)) : 'N/A'}`);
    console.log(`    Leaf Index:    ${receipt2.receipt.leaf_index}`);
    console.log(`    Proof Length:  ${receipt2.receipt.inclusion_proof?.length || 0} elements`);
    console.log(`    Amount:        ${formatUsdc(receipt2.receipt.amount)} ${receipt2.receipt.asset.toUpperCase()}`);
    console.log(`    Payer:         ${receipt2.receipt.payer_address.slice(0, 10)}...`);
    console.log(`    Payee:         ${receipt2.receipt.payee_address.slice(0, 10)}...`);
    console.log('');
  } catch (e) {
    console.log(`  Receipt 2 not available yet: ${e.message}`);
    console.log('');
  }

  // =========================================================================
  // Summary
  // =========================================================================

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('DEMO COMPLETE');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  console.log('Summary:');
  console.log(`  - Created 2 AI agents with Ed25519 keypairs`);
  console.log(`  - Alice paid Bob ${formatUsdc(payment1Amount)} USDC (seq #${result1.sequence_number})`);
  console.log(`  - Bob paid Alice ${formatUsdc(payment2Amount)} USDC (seq #${result2.sequence_number})`);
  console.log(`  - Total value transferred: ${formatUsdc(payment1Amount + payment2Amount)} USDC`);
  if (batchResult) {
    console.log(`  - Batch created with ${batchResult.payment_count} payments`);
  }
  console.log('');
  console.log('The x402 protocol enables:');
  console.log('  1. Off-chain payment signing (Ed25519)');
  console.log('  2. Deterministic sequencing by the StateSet Sequencer');
  console.log('  3. Batch aggregation for gas-efficient L2 settlement');
  console.log('  4. Merkle proofs for trustless payment verification');
  console.log('');
  console.log('For production use:');
  console.log('  - Payments would be settled on Set Chain L2');
  console.log('  - USDC would be transferred via SetPaymentBatch contract');
  console.log('  - Receipts provide cryptographic proof of inclusion');
  console.log('');
}

// =============================================================================
// Main
// =============================================================================

runDemo().catch(e => {
  console.error('Demo failed:', e.message);
  process.exit(1);
});
