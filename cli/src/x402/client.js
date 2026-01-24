/**
 * x402 Payment Client for StateSet Sequencer
 *
 * Provides methods for:
 * - Computing signing hashes for payment intents
 * - Signing payment intents with Ed25519
 * - Submitting payments to the sequencer
 * - Querying payment status and receipts
 */

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// x402 protocol constants
const X402_DOMAIN_SEPARATOR = 'X402_PAYMENT_V1';

// Network chain IDs
const CHAIN_IDS = {
  set_chain: 84532001n,
  set_chain_testnet: 84532002n,
  base: 8453n,
  base_sepolia: 84532n,
  ethereum: 1n,
};

/**
 * x402 Payment Client
 */
export class X402Client {
  /**
   * @param {Object} options
   * @param {string} options.baseUrl - Sequencer API base URL
   * @param {string} options.tenantId - Tenant UUID
   * @param {string} options.storeId - Store UUID
   * @param {string} options.agentId - Agent UUID
   * @param {Uint8Array} options.privateKey - Ed25519 private key (32 bytes)
   * @param {number} [options.keyId=1] - Agent key ID
   */
  constructor(options) {
    this.baseUrl = options.baseUrl || 'http://localhost:8080';
    this.tenantId = options.tenantId;
    this.storeId = options.storeId;
    this.agentId = options.agentId;
    this.privateKey = options.privateKey;
    this.keyId = options.keyId || 1;
  }

  /**
   * Compute the signing hash for payment parameters
   *
   * Hash format: SHA256(X402_PAYMENT_V1 || payer || payee || amount_be64 || asset || network || chain_id_be64 || valid_until_be64 || nonce_be64)
   *
   * @param {Object} params
   * @param {string} params.payer - Payer wallet address
   * @param {string} params.payee - Payee wallet address
   * @param {bigint|number} params.amount - Payment amount in smallest unit
   * @param {string} params.asset - Asset type (usdc, usdt, ssusd, dai)
   * @param {string} params.network - Network (set_chain, base, ethereum)
   * @param {bigint|number} params.validUntil - Unix timestamp when payment expires
   * @param {bigint|number} params.nonce - Nonce for replay protection
   * @returns {Uint8Array} 32-byte signing hash
   */
  computeSigningHash(params) {
    const amount = BigInt(params.amount);
    const chainId = CHAIN_IDS[params.network] || 84532001n;
    const validUntil = BigInt(params.validUntil);
    const nonce = BigInt(params.nonce);

    // Build the message to hash
    const encoder = new TextEncoder();
    const parts = [
      encoder.encode(X402_DOMAIN_SEPARATOR),
      encoder.encode(params.payer),
      encoder.encode(params.payee),
      bigIntToBeBytes(amount, 8),
      encoder.encode(params.asset.toLowerCase()),
      encoder.encode(params.network),
      bigIntToBeBytes(chainId, 8),
      bigIntToBeBytes(validUntil, 8),
      bigIntToBeBytes(nonce, 8),
    ];

    // Concatenate all parts
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
   * Sign a payment intent
   *
   * @param {Object} params - Payment parameters (same as computeSigningHash)
   * @returns {Promise<Object>} Signed payment intent with signingHash and signature
   */
  async signPaymentIntent(params) {
    const signingHash = this.computeSigningHash(params);
    const signature = await ed.signAsync(signingHash, this.privateKey);
    const publicKey = await ed.getPublicKeyAsync(this.privateKey);

    return {
      ...params,
      signingHash: '0x' + bytesToHex(signingHash),
      payerSignature: '0x' + bytesToHex(signature),
      payerPublicKey: '0x' + bytesToHex(publicKey),
    };
  }

  /**
   * Submit a payment intent to the sequencer
   *
   * @param {Object} params
   * @param {string} params.payee - Payee wallet address
   * @param {bigint|number} params.amount - Payment amount
   * @param {string} [params.asset='usdc'] - Asset type
   * @param {string} [params.network='set_chain'] - Network
   * @param {number} [params.validitySeconds=3600] - Validity period in seconds
   * @param {string} [params.description] - Payment description
   * @param {string} [params.resourceUri] - Resource URI being paid for
   * @param {string} [params.idempotencyKey] - Idempotency key
   * @returns {Promise<Object>} Submission response with intent_id and sequence_number
   */
  async submitPayment(params) {
    const now = Math.floor(Date.now() / 1000);
    const validUntil = now + (params.validitySeconds || 3600);
    const nonce = params.nonce || now * 1000 + Math.floor(Math.random() * 1000);

    // Get payer address from public key
    const publicKey = await ed.getPublicKeyAsync(this.privateKey);
    const payerAddress = '0x' + bytesToHex(publicKey);

    const paymentParams = {
      payer: payerAddress,
      payee: params.payee,
      amount: params.amount,
      asset: params.asset || 'usdc',
      network: params.network || 'set_chain',
      validUntil,
      nonce,
    };

    const signed = await this.signPaymentIntent(paymentParams);

    const requestBody = {
      tenant_id: this.tenantId,
      store_id: this.storeId,
      agent_id: this.agentId,
      agent_key_id: this.keyId,
      payer_address: payerAddress,
      payee_address: params.payee,
      amount: Number(params.amount),
      asset: params.asset || 'usdc',
      network: params.network || 'set_chain',
      valid_until: validUntil,
      nonce: Number(nonce),
      signing_hash: signed.signingHash,
      payer_signature: signed.payerSignature,
      payer_public_key: signed.payerPublicKey,
      description: params.description,
      resource_uri: params.resourceUri,
      idempotency_key: params.idempotencyKey,
    };

    const response = await fetch(`${this.baseUrl}/api/v1/x402/payments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Payment submission failed: ${error.message || response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get payment intent status
   *
   * @param {string} intentId - Payment intent UUID
   * @returns {Promise<Object>} Payment status
   */
  async getStatus(intentId) {
    const response = await fetch(`${this.baseUrl}/api/v1/x402/payments/${intentId}`);

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Failed to get status: ${error.message || response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get payment receipt with Merkle proof
   *
   * @param {string} intentId - Payment intent UUID
   * @returns {Promise<Object>} Payment receipt
   */
  async getReceipt(intentId) {
    const response = await fetch(`${this.baseUrl}/api/v1/x402/payments/${intentId}/receipt`);

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Failed to get receipt: ${error.message || response.statusText}`);
    }

    return response.json();
  }

  /**
   * List payment intents with optional filtering
   *
   * @param {Object} [filter={}]
   * @param {string} [filter.status] - Filter by status
   * @param {string} [filter.payerAddress] - Filter by payer
   * @param {string} [filter.payeeAddress] - Filter by payee
   * @param {number} [filter.limit=100] - Max results
   * @param {number} [filter.offset=0] - Offset for pagination
   * @returns {Promise<Array>} List of payment intents
   */
  async listPayments(filter = {}) {
    const params = new URLSearchParams();
    params.append('tenant_id', this.tenantId);
    params.append('store_id', this.storeId);

    if (filter.status) params.append('status', filter.status);
    if (filter.payerAddress) params.append('payer_address', filter.payerAddress);
    if (filter.payeeAddress) params.append('payee_address', filter.payeeAddress);
    if (filter.limit) params.append('limit', filter.limit.toString());
    if (filter.offset) params.append('offset', filter.offset.toString());

    const response = await fetch(`${this.baseUrl}/api/v1/x402/payments?${params}`);

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Failed to list payments: ${error.message || response.statusText}`);
    }

    return response.json();
  }

  /**
   * Create a payment batch from pending intents
   *
   * @param {Object} [options={}]
   * @param {string} [options.network='set_chain'] - Network
   * @param {number} [options.maxSize=100] - Max batch size
   * @returns {Promise<Object>} Batch creation response
   */
  async createBatch(options = {}) {
    const requestBody = {
      tenant_id: this.tenantId,
      store_id: this.storeId,
      network: options.network || 'set_chain',
      max_size: options.maxSize || 100,
    };

    const response = await fetch(`${this.baseUrl}/api/v1/x402/batches`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Batch creation failed: ${error.message || response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get batch status
   *
   * @param {string} batchId - Batch UUID
   * @returns {Promise<Object>} Batch status
   */
  async getBatch(batchId) {
    const response = await fetch(`${this.baseUrl}/api/v1/x402/batches/${batchId}`);

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Failed to get batch: ${error.message || response.statusText}`);
    }

    return response.json();
  }
}

/**
 * Convert BigInt to big-endian bytes
 * @param {bigint} value
 * @param {number} length - Byte length
 * @returns {Uint8Array}
 */
function bigIntToBeBytes(value, length) {
  const bytes = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

/**
 * Load private key from environment or file
 * @param {string} [envVar='X402_PRIVATE_KEY'] - Environment variable name
 * @returns {Uint8Array} 32-byte private key
 */
export function loadPrivateKey(envVar = 'X402_PRIVATE_KEY') {
  const keyHex = process.env[envVar];
  if (!keyHex) {
    throw new Error(`${envVar} environment variable not set`);
  }
  const hex = keyHex.startsWith('0x') ? keyHex.slice(2) : keyHex;
  return hexToBytes(hex);
}

/**
 * Generate a new Ed25519 keypair
 * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array}>}
 */
export async function generateKeypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

export default X402Client;
