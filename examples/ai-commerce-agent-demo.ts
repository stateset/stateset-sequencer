/**
 * VES-CHAIN-1 AI Commerce Agent Demo
 *
 * This demo shows an AI agent processing e-commerce orders and automatically
 * paying suppliers with USDC stablecoins on Solana, with full VES audit trail.
 *
 * Flow:
 * 1. Customer places order
 * 2. AI Agent receives order event
 * 3. Agent validates inventory and calculates supplier payment
 * 4. Agent creates payment intent (VES event)
 * 5. Agent signs and sends USDC transaction on Solana
 * 6. Agent records confirmation (VES event)
 * 7. Agent updates order status
 *
 * All operations are cryptographically signed and recorded in VES for
 * complete auditability and non-repudiation.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from '@solana/web3.js';
import {
  getAssociatedTokenAddress,
  createTransferInstruction,
  TOKEN_PROGRAM_ID,
  getAccount,
} from '@solana/spl-token';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';

// =============================================================================
// CONFIGURATION
// =============================================================================

const CONFIG = {
  // Solana network
  SOLANA_RPC: 'https://api.devnet.solana.com',  // Use mainnet-beta for production

  // USDC token mint addresses
  USDC_MINT: {
    'mainnet-beta': 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    'devnet': '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',  // Devnet USDC
  },

  // VES identifiers
  TENANT_ID: '550e8400-e29b-41d4-a716-446655440001',
  STORE_ID: '550e8400-e29b-41d4-a716-446655440002',
  AGENT_ID: '550e8400-e29b-41d4-a716-446655440003',

  // Supplier addresses (example)
  SUPPLIERS: {
    'SUPPLIER-001': 'Hf4rPJqfC9CvhKhxFFePGcSqGXWBRJLfpjFvqQ7hPBLe',
    'SUPPLIER-002': '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM',
  },
};

// =============================================================================
// TYPES
// =============================================================================

interface Order {
  orderId: string;
  customerId: string;
  items: OrderItem[];
  totalAmount: number;
  currency: string;
  status: 'pending' | 'processing' | 'paid' | 'shipped' | 'completed';
  createdAt: string;
}

interface OrderItem {
  sku: string;
  name: string;
  quantity: number;
  unitPrice: number;
  supplierId: string;
}

interface SupplierPayment {
  supplierId: string;
  supplierAddress: string;
  amount: number;  // In USDC (6 decimals)
  orderIds: string[];
}

interface VesEvent {
  eventId: string;
  tenantId: string;
  storeId: string;
  sourceAgentId: string;
  agentKeyId: number;
  entityType: string;
  entityId: string;
  eventType: string;
  createdAt: string;
  payload: object;
  payloadPlainHash: string;
  agentSignature: string;
}

interface PaymentResult {
  success: boolean;
  intentId: string;
  txHash?: string;
  txSignature?: string;
  error?: string;
  vesEventIds: string[];
}

// =============================================================================
// VES CLIENT (Simplified for Demo)
// =============================================================================

class VesClient {
  private events: VesEvent[] = [];
  private signingKey: Uint8Array;
  private publicKey: Uint8Array;

  constructor(signingKey: Uint8Array) {
    this.signingKey = signingKey;
    this.publicKey = ed25519.getPublicKey(signingKey);
  }

  private computePayloadHash(payload: object): string {
    const DOMAIN = 'VES_PAYLOAD_PLAIN_V1';
    const canonical = JSON.stringify(payload, Object.keys(payload).sort());
    const preimage = new TextEncoder().encode(DOMAIN + canonical);
    const hash = sha256(preimage);
    return '0x' + Buffer.from(hash).toString('hex');
  }

  private async signEvent(eventData: Omit<VesEvent, 'agentSignature'>): Promise<string> {
    // Simplified signing - in production, use full VES-SIG-1 preimage
    const message = JSON.stringify(eventData);
    const signature = await ed25519.signAsync(
      new TextEncoder().encode(message),
      this.signingKey
    );
    return '0x' + Buffer.from(signature).toString('hex');
  }

  async submitEvent(params: {
    entityType: string;
    entityId: string;
    eventType: string;
    payload: object;
  }): Promise<string> {
    const eventId = crypto.randomUUID();
    const payloadHash = this.computePayloadHash(params.payload);

    const eventData: Omit<VesEvent, 'agentSignature'> = {
      eventId,
      tenantId: CONFIG.TENANT_ID,
      storeId: CONFIG.STORE_ID,
      sourceAgentId: CONFIG.AGENT_ID,
      agentKeyId: 1,
      entityType: params.entityType,
      entityId: params.entityId,
      eventType: params.eventType,
      createdAt: new Date().toISOString(),
      payload: params.payload,
      payloadPlainHash: payloadHash,
    };

    const signature = await this.signEvent(eventData);

    const event: VesEvent = {
      ...eventData,
      agentSignature: signature,
    };

    this.events.push(event);

    console.log(`\n📝 VES Event Recorded:`);
    console.log(`   Event ID: ${eventId}`);
    console.log(`   Type: ${params.entityType}.${params.eventType}`);
    console.log(`   Entity: ${params.entityId}`);
    console.log(`   Signature: ${signature.slice(0, 20)}...`);

    return eventId;
  }

  getEvents(): VesEvent[] {
    return [...this.events];
  }

  getEventsForEntity(entityId: string): VesEvent[] {
    return this.events.filter(e => e.entityId === entityId);
  }
}

// =============================================================================
// AI COMMERCE AGENT
// =============================================================================

class AICommerceAgent {
  private name: string;
  private vesClient: VesClient;
  private solanaKeypair: Keypair;
  private connection: Connection;
  private usdcMint: PublicKey;

  constructor(
    name: string,
    mnemonic: string,
    network: 'mainnet-beta' | 'devnet' = 'devnet'
  ) {
    this.name = name;

    // Derive keys from mnemonic
    const seed = mnemonicToSeedSync(mnemonic);
    const master = HDKey.fromMasterSeed(seed);

    // Derive VES signing key
    const vesPath = "m/44'/9999'/0'/0'/0";
    const vesKey = master.derive(vesPath);
    this.vesClient = new VesClient(vesKey.privateKey!);

    // Derive Solana key
    const solanaPath = "m/44'/501'/0'/0'/0";
    const solanaKey = master.derive(solanaPath);
    const solanaPublicKey = ed25519.getPublicKey(solanaKey.privateKey!);
    this.solanaKeypair = Keypair.fromSecretKey(
      new Uint8Array([...solanaKey.privateKey!, ...solanaPublicKey])
    );

    // Setup Solana connection
    this.connection = new Connection(CONFIG.SOLANA_RPC, 'confirmed');
    this.usdcMint = new PublicKey(CONFIG.USDC_MINT[network]);

    console.log(`\n🤖 AI Commerce Agent "${name}" initialized`);
    console.log(`   Solana Address: ${this.solanaKeypair.publicKey.toBase58()}`);
    console.log(`   Network: ${network}`);
  }

  get solanaAddress(): string {
    return this.solanaKeypair.publicKey.toBase58();
  }

  // ---------------------------------------------------------------------------
  // ORDER PROCESSING
  // ---------------------------------------------------------------------------

  async processOrder(order: Order): Promise<PaymentResult[]> {
    console.log(`\n${'='.repeat(70)}`);
    console.log(`🛒 PROCESSING ORDER: ${order.orderId}`);
    console.log(`${'='.repeat(70)}`);
    console.log(`   Customer: ${order.customerId}`);
    console.log(`   Items: ${order.items.length}`);
    console.log(`   Total: $${order.totalAmount.toFixed(2)} ${order.currency}`);

    // 1. Record order received event
    await this.vesClient.submitEvent({
      entityType: 'Order',
      entityId: order.orderId,
      eventType: 'OrderReceived',
      payload: {
        order_id: order.orderId,
        customer_id: order.customerId,
        items: order.items.map(i => ({
          sku: i.sku,
          quantity: i.quantity,
          unit_price: i.unitPrice,
          supplier_id: i.supplierId,
        })),
        total_amount: order.totalAmount,
        currency: order.currency,
        received_at: new Date().toISOString(),
        agent_id: CONFIG.AGENT_ID,
      },
    });

    // 2. Calculate supplier payments
    const supplierPayments = this.calculateSupplierPayments(order);

    console.log(`\n📊 Supplier Payments Calculated:`);
    for (const payment of supplierPayments) {
      console.log(`   ${payment.supplierId}: $${(payment.amount / 1_000_000).toFixed(2)} USDC`);
    }

    // 3. Process each supplier payment
    const results: PaymentResult[] = [];

    for (const payment of supplierPayments) {
      console.log(`\n${'─'.repeat(50)}`);
      console.log(`💳 Processing payment to ${payment.supplierId}`);
      console.log(`${'─'.repeat(50)}`);

      const result = await this.paySupplier(payment, order.orderId);
      results.push(result);

      if (result.success) {
        console.log(`   ✅ Payment successful!`);
        console.log(`   TX: ${result.txHash}`);
      } else {
        console.log(`   ❌ Payment failed: ${result.error}`);
      }
    }

    // 4. Update order status
    const allSuccessful = results.every(r => r.success);
    await this.vesClient.submitEvent({
      entityType: 'Order',
      entityId: order.orderId,
      eventType: allSuccessful ? 'OrderPaid' : 'OrderPaymentFailed',
      payload: {
        order_id: order.orderId,
        status: allSuccessful ? 'paid' : 'payment_failed',
        payments: results.map(r => ({
          intent_id: r.intentId,
          success: r.success,
          tx_hash: r.txHash,
          error: r.error,
        })),
        processed_at: new Date().toISOString(),
      },
    });

    return results;
  }

  private calculateSupplierPayments(order: Order): SupplierPayment[] {
    // Group items by supplier and calculate payment amounts
    const supplierTotals = new Map<string, number>();

    for (const item of order.items) {
      const current = supplierTotals.get(item.supplierId) || 0;
      // Calculate supplier cost (e.g., 70% of retail price)
      const supplierCost = item.unitPrice * item.quantity * 0.70;
      supplierTotals.set(item.supplierId, current + supplierCost);
    }

    const payments: SupplierPayment[] = [];

    for (const [supplierId, amount] of supplierTotals) {
      const supplierAddress = CONFIG.SUPPLIERS[supplierId as keyof typeof CONFIG.SUPPLIERS];
      if (!supplierAddress) {
        console.warn(`   ⚠️ Unknown supplier: ${supplierId}`);
        continue;
      }

      payments.push({
        supplierId,
        supplierAddress,
        // Convert to USDC base units (6 decimals)
        amount: Math.floor(amount * 1_000_000),
        orderIds: [order.orderId],
      });
    }

    return payments;
  }

  // ---------------------------------------------------------------------------
  // STABLECOIN PAYMENT
  // ---------------------------------------------------------------------------

  async paySupplier(
    payment: SupplierPayment,
    orderId: string
  ): Promise<PaymentResult> {
    const intentId = crypto.randomUUID();
    const vesEventIds: string[] = [];

    try {
      // 1. Record payment intent
      console.log(`\n   📝 Recording payment intent...`);

      const intentEventId = await this.vesClient.submitEvent({
        entityType: 'Payment',
        entityId: intentId,
        eventType: 'PaymentIntentCreated',
        payload: {
          intent_id: intentId,
          order_id: orderId,
          supplier_id: payment.supplierId,
          chain: 'solana',
          network: 'devnet',
          operation: 'token_transfer',
          from_address: this.solanaAddress,
          to_address: payment.supplierAddress,
          amount: payment.amount.toString(),
          currency: 'USDC',
          token_mint: this.usdcMint.toBase58(),
          token_decimals: 6,
          human_readable_amount: `$${(payment.amount / 1_000_000).toFixed(2)}`,
          memo: `Order ${orderId} - Supplier Payment`,
          created_at: new Date().toISOString(),
        },
      });
      vesEventIds.push(intentEventId);

      // 2. Get token accounts
      console.log(`   🔍 Resolving token accounts...`);

      const fromAta = await getAssociatedTokenAddress(
        this.usdcMint,
        this.solanaKeypair.publicKey
      );

      const toAta = await getAssociatedTokenAddress(
        this.usdcMint,
        new PublicKey(payment.supplierAddress)
      );

      console.log(`      From ATA: ${fromAta.toBase58()}`);
      console.log(`      To ATA: ${toAta.toBase58()}`);

      // 3. Check balance
      console.log(`   💰 Checking USDC balance...`);

      try {
        const fromAccount = await getAccount(this.connection, fromAta);
        const balance = Number(fromAccount.amount);
        console.log(`      Balance: ${(balance / 1_000_000).toFixed(2)} USDC`);

        if (balance < payment.amount) {
          throw new Error(`Insufficient USDC balance. Need ${payment.amount}, have ${balance}`);
        }
      } catch (e: any) {
        if (e.message.includes('could not find account')) {
          throw new Error('USDC token account not found. Please fund the agent wallet.');
        }
        throw e;
      }

      // 4. Build transaction
      console.log(`   🔨 Building transaction...`);

      const tx = new Transaction().add(
        createTransferInstruction(
          fromAta,
          toAta,
          this.solanaKeypair.publicKey,
          BigInt(payment.amount),
          [],
          TOKEN_PROGRAM_ID
        )
      );

      // 5. Sign transaction
      console.log(`   ✍️ Signing transaction...`);

      const { blockhash } = await this.connection.getLatestBlockhash();
      tx.recentBlockhash = blockhash;
      tx.feePayer = this.solanaKeypair.publicKey;
      tx.sign(this.solanaKeypair);

      // Record signing event
      const signEventId = await this.vesClient.submitEvent({
        entityType: 'Payment',
        entityId: intentId,
        eventType: 'TransactionSigned',
        payload: {
          intent_id: intentId,
          chain: 'solana',
          signer_address: this.solanaAddress,
          recent_blockhash: blockhash,
          signed_at: new Date().toISOString(),
        },
      });
      vesEventIds.push(signEventId);

      // 6. Submit transaction
      console.log(`   📤 Submitting to Solana network...`);

      const signature = await sendAndConfirmTransaction(
        this.connection,
        tx,
        [this.solanaKeypair],
        { commitment: 'confirmed' }
      );

      console.log(`   ⛓️ Transaction confirmed!`);
      console.log(`      Signature: ${signature}`);
      console.log(`      Explorer: https://explorer.solana.com/tx/${signature}?cluster=devnet`);

      // 7. Get confirmation details
      const confirmation = await this.connection.getTransaction(signature, {
        commitment: 'confirmed',
      });

      // 8. Record confirmation
      const confirmEventId = await this.vesClient.submitEvent({
        entityType: 'Payment',
        entityId: intentId,
        eventType: 'TransactionConfirmed',
        payload: {
          intent_id: intentId,
          chain: 'solana',
          network: 'devnet',
          tx_hash: signature,
          tx_signature: signature,
          slot: confirmation?.slot,
          block_time: confirmation?.blockTime
            ? new Date(confirmation.blockTime * 1000).toISOString()
            : null,
          fee_lamports: confirmation?.meta?.fee,
          status: 'confirmed',
          confirmed_at: new Date().toISOString(),
        },
      });
      vesEventIds.push(confirmEventId);

      // 9. Record payment completed
      const completedEventId = await this.vesClient.submitEvent({
        entityType: 'Payment',
        entityId: intentId,
        eventType: 'PaymentCompleted',
        payload: {
          intent_id: intentId,
          order_id: orderId,
          supplier_id: payment.supplierId,
          chain: 'solana',
          tx_hash: signature,
          amount: payment.amount.toString(),
          currency: 'USDC',
          human_readable_amount: `$${(payment.amount / 1_000_000).toFixed(2)}`,
          status: 'success',
          completed_at: new Date().toISOString(),
        },
      });
      vesEventIds.push(completedEventId);

      return {
        success: true,
        intentId,
        txHash: signature,
        txSignature: signature,
        vesEventIds,
      };

    } catch (error: any) {
      console.error(`   ❌ Error: ${error.message}`);

      // Record failure
      const failEventId = await this.vesClient.submitEvent({
        entityType: 'Payment',
        entityId: intentId,
        eventType: 'TransactionFailed',
        payload: {
          intent_id: intentId,
          order_id: orderId,
          supplier_id: payment.supplierId,
          chain: 'solana',
          error: error.message,
          error_code: error.code || 'UNKNOWN',
          failed_at: new Date().toISOString(),
        },
      });
      vesEventIds.push(failEventId);

      return {
        success: false,
        intentId,
        error: error.message,
        vesEventIds,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // AUDIT & REPORTING
  // ---------------------------------------------------------------------------

  printAuditTrail(entityId: string): void {
    console.log(`\n${'='.repeat(70)}`);
    console.log(`📋 AUDIT TRAIL FOR: ${entityId}`);
    console.log(`${'='.repeat(70)}`);

    const events = this.vesClient.getEventsForEntity(entityId);

    if (events.length === 0) {
      console.log('   No events found.');
      return;
    }

    for (const event of events) {
      console.log(`\n   ${event.eventType}`);
      console.log(`   ├─ Event ID: ${event.eventId}`);
      console.log(`   ├─ Time: ${event.createdAt}`);
      console.log(`   ├─ Agent: ${event.sourceAgentId}`);
      console.log(`   ├─ Payload Hash: ${event.payloadPlainHash.slice(0, 20)}...`);
      console.log(`   └─ Signature: ${event.agentSignature.slice(0, 20)}...`);
    }
  }

  printFullEventLog(): void {
    console.log(`\n${'='.repeat(70)}`);
    console.log(`📜 FULL VES EVENT LOG`);
    console.log(`${'='.repeat(70)}`);

    const events = this.vesClient.getEvents();
    console.log(`   Total Events: ${events.length}`);

    for (const event of events) {
      console.log(`\n   [${event.createdAt}]`);
      console.log(`   ${event.entityType}.${event.eventType}`);
      console.log(`   Entity: ${event.entityId}`);
      console.log(`   Event ID: ${event.eventId}`);
    }
  }
}

// =============================================================================
// DEMO EXECUTION
// =============================================================================

async function runDemo() {
  console.log(`
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     🤖 VES-CHAIN-1 AI Commerce Agent Demo                                ║
║                                                                          ║
║     Demonstrating AI-driven stablecoin payments with full audit trail    ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
`);

  // Use test mnemonic (NEVER use in production!)
  const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  // Initialize AI Commerce Agent
  const agent = new AICommerceAgent(
    'Commerce-Agent-Alpha',
    TEST_MNEMONIC,
    'devnet'
  );

  // Create sample order
  const order: Order = {
    orderId: 'ORD-2025-001234',
    customerId: 'CUST-5678',
    items: [
      {
        sku: 'WIDGET-001',
        name: 'Premium Widget',
        quantity: 2,
        unitPrice: 49.99,
        supplierId: 'SUPPLIER-001',
      },
      {
        sku: 'GADGET-002',
        name: 'Smart Gadget',
        quantity: 1,
        unitPrice: 129.99,
        supplierId: 'SUPPLIER-001',
      },
      {
        sku: 'TOOL-003',
        name: 'Power Tool',
        quantity: 3,
        unitPrice: 79.99,
        supplierId: 'SUPPLIER-002',
      },
    ],
    totalAmount: 469.94,
    currency: 'USD',
    status: 'pending',
    createdAt: new Date().toISOString(),
  };

  console.log(`\n📦 Sample Order Created:`);
  console.log(`   Order ID: ${order.orderId}`);
  console.log(`   Customer: ${order.customerId}`);
  console.log(`   Items:`);
  for (const item of order.items) {
    console.log(`     - ${item.quantity}x ${item.name} @ $${item.unitPrice} (${item.supplierId})`);
  }
  console.log(`   Total: $${order.totalAmount.toFixed(2)}`);

  // Process the order
  console.log(`\n⏳ Starting order processing...`);
  console.log(`   (Note: On devnet, ensure the agent wallet has USDC tokens)`);

  try {
    const results = await agent.processOrder(order);

    // Print summary
    console.log(`\n${'='.repeat(70)}`);
    console.log(`📊 PAYMENT SUMMARY`);
    console.log(`${'='.repeat(70)}`);

    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;

    console.log(`   Total Payments: ${results.length}`);
    console.log(`   Successful: ${successful}`);
    console.log(`   Failed: ${failed}`);

    for (const result of results) {
      console.log(`\n   Payment ${result.intentId.slice(0, 8)}...`);
      console.log(`   ├─ Status: ${result.success ? '✅ Success' : '❌ Failed'}`);
      if (result.txHash) {
        console.log(`   ├─ TX Hash: ${result.txHash}`);
        console.log(`   ├─ Explorer: https://explorer.solana.com/tx/${result.txHash}?cluster=devnet`);
      }
      if (result.error) {
        console.log(`   ├─ Error: ${result.error}`);
      }
      console.log(`   └─ VES Events: ${result.vesEventIds.length} recorded`);
    }

    // Print audit trail for the order
    agent.printAuditTrail(order.orderId);

    // Print full event log
    agent.printFullEventLog();

  } catch (error: any) {
    console.error(`\n❌ Demo Error: ${error.message}`);
    console.error(`\nNote: To run this demo successfully, you need to:`);
    console.error(`  1. Have USDC tokens in the agent's Solana wallet on devnet`);
    console.error(`  2. Ensure the supplier addresses have Associated Token Accounts`);
    console.error(`  3. The agent's devnet address is: ${agent.solanaAddress}`);
    console.error(`\n  Get devnet USDC from: https://spl-token-faucet.com/`);
  }

  console.log(`
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
`);
}

// Export for use as module
export { AICommerceAgent, VesClient, Order, PaymentResult };

// Run demo if executed directly
runDemo().catch(console.error);
