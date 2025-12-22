/**
 * VES-CONTRACT-1 Smart Contract Integration Module
 * Simulated escrow contracts for E2E testing
 */

import crypto from 'crypto';
import { TestCrypto, MerkleTree, uuid } from './test-utils.mjs';

// =============================================================================
// Simulated Blockchain State
// =============================================================================

export class SimulatedBlockchain {
  constructor(name = 'solana') {
    this.name = name;
    this.accounts = new Map();
    this.transactions = [];
    this.blockNumber = 0;
    this.anchoredRoots = new Map(); // tenantId -> { root, sequence }
  }

  createAccount(address, balance = 0n) {
    this.accounts.set(address, {
      address,
      balance,
      data: null
    });
    return address;
  }

  getAccount(address) {
    return this.accounts.get(address);
  }

  transfer(from, to, amount) {
    const fromAccount = this.accounts.get(from);
    const toAccount = this.accounts.get(to);

    if (!fromAccount) throw new Error(`Account not found: ${from}`);
    if (!toAccount) throw new Error(`Account not found: ${to}`);
    if (fromAccount.balance < amount) throw new Error('Insufficient balance');

    fromAccount.balance -= amount;
    toAccount.balance += amount;

    const tx = {
      txHash: '0x' + TestCrypto.hash(Buffer.from(`tx_${this.transactions.length}`)).toString('hex'),
      from,
      to,
      amount: amount.toString(),
      blockNumber: ++this.blockNumber,
      timestamp: new Date().toISOString()
    };

    this.transactions.push(tx);
    return tx;
  }

  /**
   * Anchor a VES Merkle root on-chain
   */
  anchorRoot(tenantId, root, sequenceNumber) {
    const existing = this.anchoredRoots.get(tenantId);
    if (existing && existing.sequence >= sequenceNumber) {
      throw new Error('Cannot anchor older root');
    }

    this.anchoredRoots.set(tenantId, {
      root,
      sequence: sequenceNumber,
      anchoredAt: new Date().toISOString(),
      blockNumber: ++this.blockNumber
    });

    const tx = {
      txHash: '0x' + TestCrypto.hash(Buffer.from(`anchor_${tenantId}_${sequenceNumber}`)).toString('hex'),
      type: 'anchor_root',
      tenantId,
      root,
      sequenceNumber,
      blockNumber: this.blockNumber,
      timestamp: new Date().toISOString()
    };

    this.transactions.push(tx);
    return tx;
  }

  /**
   * Get anchored root for tenant
   */
  getAnchoredRoot(tenantId) {
    return this.anchoredRoots.get(tenantId);
  }

  /**
   * Verify a Merkle root is anchored
   */
  verifyAnchoredRoot(tenantId, root) {
    const anchored = this.anchoredRoots.get(tenantId);
    return anchored && anchored.root === root;
  }
}

// =============================================================================
// VES Proof Verifier
// =============================================================================

export class VesProofVerifier {
  constructor(blockchain) {
    this.blockchain = blockchain;
  }

  /**
   * Verify a VES proof against anchored root
   */
  verifyProof(tenantId, proof) {
    // Check if root is anchored
    const anchoredRoot = this.blockchain.getAnchoredRoot(tenantId);
    if (!anchoredRoot) {
      return {
        valid: false,
        error: 'ROOT_NOT_ANCHORED',
        message: `No anchored root for tenant ${tenantId}`
      };
    }

    // Verify Merkle root matches
    if (anchoredRoot.root !== proof.merkleRoot) {
      return {
        valid: false,
        error: 'ROOT_MISMATCH',
        message: `Anchored root ${anchoredRoot.root} != proof root ${proof.merkleRoot}`
      };
    }

    // Verify Merkle proof
    const proofValid = MerkleTree.verifyProof(
      proof.eventHash,
      proof.proofPath,
      proof.merkleRoot
    );

    if (!proofValid) {
      return {
        valid: false,
        error: 'INVALID_MERKLE_PROOF',
        message: 'Merkle proof verification failed'
      };
    }

    return {
      valid: true,
      event: proof.event,
      anchoredAt: anchoredRoot.anchoredAt,
      blockNumber: anchoredRoot.blockNumber
    };
  }
}

// =============================================================================
// Escrow Contract (Simulated)
// =============================================================================

export class EscrowContract {
  constructor(blockchain, proofVerifier) {
    this.blockchain = blockchain;
    this.proofVerifier = proofVerifier;
    this.escrows = new Map();
  }

  /**
   * Create a new escrow
   */
  createEscrow({
    buyer,
    seller,
    tokenMint,
    amount,
    releaseConditions,
    timeoutSeconds = 7 * 24 * 60 * 60 // 7 days default
  }) {
    // Validate accounts exist
    const buyerAccount = this.blockchain.getAccount(buyer);
    if (!buyerAccount) throw new Error('Buyer account not found');
    if (buyerAccount.balance < BigInt(amount)) throw new Error('Insufficient buyer balance');

    const sellerAccount = this.blockchain.getAccount(seller);
    if (!sellerAccount) throw new Error('Seller account not found');

    // Generate escrow ID using random UUID for uniqueness
    const escrowId = '0x' + TestCrypto.hash(
      Buffer.from(`escrow_${buyer}_${seller}_${Date.now()}_${crypto.randomUUID()}`)
    ).toString('hex');

    // Create escrow vault account
    const vaultAddress = `vault_${escrowId.slice(0, 16)}`;
    this.blockchain.createAccount(vaultAddress, 0n);

    // Transfer funds to vault
    this.blockchain.transfer(buyer, vaultAddress, BigInt(amount));

    const escrow = {
      escrowId,
      buyer,
      seller,
      vaultAddress,
      tokenMint,
      amount: amount.toString(),
      releaseConditions,
      timeoutSeconds,
      status: 'active',
      createdAt: new Date().toISOString(),
      timeoutAt: new Date(Date.now() + timeoutSeconds * 1000).toISOString()
    };

    this.escrows.set(escrowId, escrow);

    return {
      escrowId,
      vaultAddress,
      status: 'active',
      txHash: this.blockchain.transactions[this.blockchain.transactions.length - 1].txHash
    };
  }

  /**
   * Release escrow with VES proof
   */
  releaseEscrow(escrowId, vesProof, tenantId) {
    const escrow = this.escrows.get(escrowId);
    if (!escrow) throw new Error('Escrow not found');
    if (escrow.status !== 'active') throw new Error(`Escrow status is ${escrow.status}`);

    // Verify VES proof
    const proofResult = this.proofVerifier.verifyProof(tenantId, vesProof);
    if (!proofResult.valid) {
      return {
        success: false,
        error: proofResult.error,
        message: proofResult.message
      };
    }

    // Verify release conditions match
    const event = vesProof.event;
    const conditions = escrow.releaseConditions;

    if (event.eventType !== conditions.eventType) {
      return {
        success: false,
        error: 'EVENT_TYPE_MISMATCH',
        message: `Expected ${conditions.eventType}, got ${event.eventType}`
      };
    }

    if (event.entityType !== conditions.entityType) {
      return {
        success: false,
        error: 'ENTITY_TYPE_MISMATCH',
        message: `Expected ${conditions.entityType}, got ${event.entityType}`
      };
    }

    if (event.entityId !== conditions.entityId) {
      return {
        success: false,
        error: 'ENTITY_ID_MISMATCH',
        message: `Expected ${conditions.entityId}, got ${event.entityId}`
      };
    }

    // Release funds to seller
    const tx = this.blockchain.transfer(
      escrow.vaultAddress,
      escrow.seller,
      BigInt(escrow.amount)
    );

    // Update escrow status
    escrow.status = 'released';
    escrow.releasedAt = new Date().toISOString();
    escrow.releaseTx = tx.txHash;
    escrow.releaseProof = {
      eventHash: vesProof.eventHash,
      merkleRoot: vesProof.merkleRoot
    };

    return {
      success: true,
      status: 'released',
      txHash: tx.txHash,
      sellerReceived: escrow.amount
    };
  }

  /**
   * Refund escrow after timeout
   */
  refundEscrow(escrowId) {
    const escrow = this.escrows.get(escrowId);
    if (!escrow) throw new Error('Escrow not found');
    if (escrow.status !== 'active') throw new Error(`Escrow status is ${escrow.status}`);

    // Check timeout
    if (new Date() < new Date(escrow.timeoutAt)) {
      return {
        success: false,
        error: 'ESCROW_NOT_EXPIRED',
        message: `Escrow expires at ${escrow.timeoutAt}`
      };
    }

    // Refund to buyer
    const tx = this.blockchain.transfer(
      escrow.vaultAddress,
      escrow.buyer,
      BigInt(escrow.amount)
    );

    // Update escrow status
    escrow.status = 'refunded';
    escrow.refundedAt = new Date().toISOString();
    escrow.refundTx = tx.txHash;

    return {
      success: true,
      status: 'refunded',
      txHash: tx.txHash,
      buyerReceived: escrow.amount
    };
  }

  /**
   * Get escrow status
   */
  getEscrow(escrowId) {
    return this.escrows.get(escrowId);
  }
}

// =============================================================================
// Token Account (Simulated SPL Token)
// =============================================================================

export class TokenAccount {
  constructor(blockchain, mint, decimals = 6) {
    this.blockchain = blockchain;
    this.mint = mint;
    this.decimals = decimals;
    this.accounts = new Map();
  }

  createAccount(owner, initialBalance = 0n) {
    const address = `token_${owner}_${this.mint}`;
    this.accounts.set(owner, {
      address,
      owner,
      mint: this.mint,
      balance: initialBalance
    });
    return address;
  }

  mint(owner, amount) {
    const account = this.accounts.get(owner);
    if (!account) throw new Error('Token account not found');
    account.balance += BigInt(amount);
    return account.balance;
  }

  transfer(from, to, amount) {
    const fromAccount = this.accounts.get(from);
    const toAccount = this.accounts.get(to);

    if (!fromAccount) throw new Error(`Token account not found: ${from}`);
    if (!toAccount) throw new Error(`Token account not found: ${to}`);
    if (fromAccount.balance < BigInt(amount)) throw new Error('Insufficient token balance');

    fromAccount.balance -= BigInt(amount);
    toAccount.balance += BigInt(amount);

    return {
      from,
      to,
      amount: amount.toString(),
      fromBalance: fromAccount.balance.toString(),
      toBalance: toAccount.balance.toString()
    };
  }

  getBalance(owner) {
    const account = this.accounts.get(owner);
    return account?.balance || 0n;
  }
}

// =============================================================================
// VES Anchor Program (Simulated)
// =============================================================================

export class VesAnchorProgram {
  constructor(blockchain) {
    this.blockchain = blockchain;
    this.tenants = new Map();
  }

  /**
   * Initialize a tenant
   */
  initializeTenant(tenantId, storeId, authority) {
    if (this.tenants.has(tenantId)) {
      throw new Error('Tenant already initialized');
    }

    const tenant = {
      tenantId,
      storeId,
      authority,
      currentRoot: '0x' + '0'.repeat(64),
      currentSequence: 0,
      initializedAt: new Date().toISOString()
    };

    this.tenants.set(tenantId, tenant);

    return {
      tenantId,
      status: 'initialized'
    };
  }

  /**
   * Update Merkle root
   */
  updateRoot(tenantId, newRoot, sequenceNumber, authority) {
    const tenant = this.tenants.get(tenantId);
    if (!tenant) throw new Error('Tenant not found');
    if (tenant.authority !== authority) throw new Error('Unauthorized');
    if (sequenceNumber <= tenant.currentSequence) {
      throw new Error('Sequence must be greater than current');
    }

    const previousRoot = tenant.currentRoot;
    tenant.currentRoot = newRoot;
    tenant.currentSequence = sequenceNumber;
    tenant.lastUpdated = new Date().toISOString();

    // Anchor on blockchain
    const tx = this.blockchain.anchorRoot(tenantId, newRoot, sequenceNumber);

    return {
      previousRoot,
      newRoot,
      sequenceNumber,
      txHash: tx.txHash
    };
  }

  /**
   * Get tenant state
   */
  getTenant(tenantId) {
    return this.tenants.get(tenantId);
  }
}

// =============================================================================
// Escrow Manager (High-level API)
// =============================================================================

export class EscrowManager {
  constructor(eventStore) {
    this.eventStore = eventStore;
    this.blockchain = new SimulatedBlockchain('solana');
    this.proofVerifier = new VesProofVerifier(this.blockchain);
    this.escrowContract = new EscrowContract(this.blockchain, this.proofVerifier);
    this.anchorProgram = new VesAnchorProgram(this.blockchain);

    // Initialize default token
    this.usdc = new TokenAccount(this.blockchain, 'USDC', 6);
  }

  /**
   * Setup tenant and accounts
   */
  setup(tenantId, storeId, authority) {
    // Initialize tenant
    this.anchorProgram.initializeTenant(tenantId, storeId, authority);

    // Create authority account
    this.blockchain.createAccount(authority, 1000000000n);

    return { tenantId, authority };
  }

  /**
   * Create buyer and seller accounts (idempotent)
   */
  createParticipants(buyerAddress, sellerAddress, buyerBalance) {
    // Create accounts only if they don't exist
    if (!this.blockchain.getAccount(buyerAddress)) {
      this.blockchain.createAccount(buyerAddress, BigInt(buyerBalance));
      this.usdc.createAccount(buyerAddress, BigInt(buyerBalance));
    }

    if (!this.blockchain.getAccount(sellerAddress)) {
      this.blockchain.createAccount(sellerAddress, 0n);
      this.usdc.createAccount(sellerAddress, 0n);
    }

    return { buyerAddress, sellerAddress };
  }

  /**
   * Sync VES state to chain
   */
  syncToChain(tenantId, authority) {
    const currentRoot = this.eventStore.merkleTree?.getRoot() || '0x' + '0'.repeat(64);
    const sequenceNumber = this.eventStore.events.length;

    if (sequenceNumber === 0) {
      return { synced: false, reason: 'No events to sync' };
    }

    const result = this.anchorProgram.updateRoot(
      tenantId,
      currentRoot,
      sequenceNumber,
      authority
    );

    return {
      synced: true,
      ...result
    };
  }

  /**
   * Create escrow for an order
   */
  createEscrowForOrder(orderId, buyer, seller, amount, tenantId) {
    return this.escrowContract.createEscrow({
      buyer,
      seller,
      tokenMint: 'USDC',
      amount,
      releaseConditions: {
        eventType: 'DeliveryConfirmed',
        entityType: 'Order',
        entityId: orderId
      }
    });
  }

  /**
   * Release escrow with delivery confirmation
   */
  releaseWithDeliveryConfirmation(escrowId, tenantId) {
    const escrow = this.escrowContract.getEscrow(escrowId);
    if (!escrow) throw new Error('Escrow not found');

    // Find the delivery confirmation event
    const event = this.eventStore.getEventByEntity(
      escrow.releaseConditions.entityType,
      escrow.releaseConditions.entityId,
      escrow.releaseConditions.eventType
    );

    if (!event) {
      throw new Error(`Release event not found: ${escrow.releaseConditions.eventType} for ${escrow.releaseConditions.entityId}`);
    }

    // Generate VES proof
    const proof = this.eventStore.generateProof(event.eventId);

    // Release escrow
    return this.escrowContract.releaseEscrow(escrowId, proof, tenantId);
  }
}
