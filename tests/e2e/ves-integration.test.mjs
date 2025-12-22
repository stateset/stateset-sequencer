/**
 * VES End-to-End Integration Test
 *
 * Tests VES-CONTRACT-1, VES-MULTI-1, and VES-STARK-1 working together
 * in a realistic e-commerce scenario.
 *
 * Scenario: Multi-Agent Treasury with Escrow and Batch Proofs
 *
 * 1. Create a multi-agent treasury group (2-of-3 threshold)
 * 2. Process multiple orders through escrow
 * 3. Generate STARK batch proofs for event verification
 * 4. Use threshold signatures for treasury payments
 */

import {
  EventStore,
  MerkleTree,
  TestRunner,
  Assert,
  uuid,
  toBaseUnits,
  formatAmount
} from './test-utils.mjs';

import {
  FrostDKG,
  FrostSigner,
  FrostCoordinator,
  AgentGroup,
  ProposalManager
} from './multi-agent.mjs';

import {
  StarkProver,
  StarkVerifier,
  BatchManager,
  ExecutionTrace,
  VesBatchAir
} from './stark-prover.mjs';

import {
  EscrowManager,
  SimulatedBlockchain,
  VesProofVerifier,
  EscrowContract,
  VesAnchorProgram
} from './escrow.mjs';

// =============================================================================
// Test Configuration
// =============================================================================

const CONFIG = {
  tenantId: '550e8400-e29b-41d4-a716-446655440000',
  storeId: '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
  authorityAddress: 'Authority11111111111111111111111111111111',
  agents: {
    cfo: 'agent-cfo-00000000-0000-0000-0000-000000000001',
    controller: 'agent-ctrl-0000-0000-0000-0000-000000000002',
    treasurer: 'agent-treas-000-0000-0000-0000-000000000003'
  },
  buyers: {
    alice: 'A1iceWa11etAddress1111111111111111111111111',
    bob: 'B0bWa11etAddress11111111111111111111111111'
  },
  sellers: {
    widgetCo: 'W1dgetC0Wa11etAddress111111111111111111111',
    acmeCorp: 'AcmeC0rpWa11etAddress11111111111111111111'
  }
};

// =============================================================================
// Test Suite: VES-MULTI-1 Multi-Agent Coordination
// =============================================================================

const multiAgentTests = new TestRunner('VES-MULTI-1: Multi-Agent Coordination');

multiAgentTests.test('DKG creates valid group key', async () => {
  const dkg = new FrostDKG(2, 3);

  // Round 1
  const round1 = new Map();
  for (let i = 1; i <= 3; i++) {
    round1.set(i, dkg.generateRound1(i));
  }

  Assert.equal(round1.size, 3, 'Should have 3 round 1 messages');

  // Round 2
  const shares = new Map();
  for (let i = 1; i <= 3; i++) {
    const received = new Map();
    for (let j = 1; j <= 3; j++) {
      received.set(j, round1.get(j).sharesForOthers.get(i));
    }
    shares.set(i, dkg.combineShares(i, received));
  }

  Assert.equal(shares.size, 3, 'Should have 3 final shares');

  // Compute group key
  const commitments = new Map();
  for (let i = 1; i <= 3; i++) {
    commitments.set(i, round1.get(i).commitments);
  }
  const groupKey = dkg.computeGroupPublicKey(commitments);

  Assert.ok(groupKey.startsWith('0x'), 'Group key should be hex');
  Assert.equal(groupKey.length, 66, 'Group key should be 32 bytes');
});

multiAgentTests.test('AgentGroup performs full DKG and signing', async () => {
  const group = new AgentGroup(
    'Treasury',
    CONFIG.tenantId,
    2, // threshold
    [CONFIG.agents.cfo, CONFIG.agents.controller, CONFIG.agents.treasurer]
  );

  Assert.equal(group.status, 'pending_dkg');

  // Run DKG
  const dkgResult = group.runDKG();

  Assert.equal(group.status, 'active');
  Assert.ok(dkgResult.groupPublicKey.startsWith('0x'));

  // Sign with 2-of-3
  const message = 'Approve payment of $50,000 to supplier';
  const result = group.sign(message, [CONFIG.agents.controller, CONFIG.agents.treasurer]);

  Assert.ok(result.signature.startsWith('0x'));
  Assert.equal(result.signature.length, 130, 'Signature should be 64 bytes');
  Assert.equal(result.signers.length, 2);
});

multiAgentTests.test('Signing fails with insufficient signers', async () => {
  const group = new AgentGroup(
    'Treasury',
    CONFIG.tenantId,
    2,
    [CONFIG.agents.cfo, CONFIG.agents.controller, CONFIG.agents.treasurer]
  );
  group.runDKG();

  Assert.throws(
    () => group.sign('message', [CONFIG.agents.cfo]),
    'Insufficient signers'
  );
});

multiAgentTests.test('Proposal voting reaches threshold', async () => {
  const eventStore = new EventStore(CONFIG.tenantId, CONFIG.storeId);
  const proposalManager = new ProposalManager(eventStore);

  const proposal = proposalManager.createProposal(
    uuid(),
    'payment',
    'Q1 Supplier Payment',
    { payment: { amount: '50000', recipient: CONFIG.sellers.widgetCo } },
    CONFIG.agents.cfo,
    2
  );

  Assert.equal(proposal.status, 'pending');

  // Vote 1
  proposalManager.vote(proposal.proposalId, CONFIG.agents.controller, 'approve', 'Verified');
  let updated = proposalManager.getProposal(proposal.proposalId);
  Assert.equal(updated.status, 'pending');
  Assert.equal(updated.votes.length, 1);

  // Vote 2 - threshold reached
  proposalManager.vote(proposal.proposalId, CONFIG.agents.treasurer, 'approve', 'Approved');
  updated = proposalManager.getProposal(proposal.proposalId);
  Assert.equal(updated.status, 'approved');
  Assert.equal(updated.votes.length, 2);
});

// =============================================================================
// Test Suite: VES-STARK-1 Validity Proofs
// =============================================================================

const starkTests = new TestRunner('VES-STARK-1: Validity Proofs');

starkTests.test('ExecutionTrace builds correctly', async () => {
  const events = [];
  for (let i = 1; i <= 10; i++) {
    events.push({
      eventId: `evt_${i}`,
      sequenceNumber: i,
      eventType: 'OrderCreated',
      entityType: 'Order',
      entityId: `ORD-${i}`,
      payloadHash: `0x${'a'.repeat(64)}`,
      timestamp: new Date().toISOString()
    });
  }

  const trace = new ExecutionTrace(events);

  Assert.equal(trace.realLength, 10);
  Assert.equal(trace.length, 16, 'Should pad to power of 2');
  Assert.equal(trace.columns.sequence[0], 1n);
  Assert.equal(trace.columns.sequence[9], 10n);
  Assert.equal(trace.columns.paddingFlag[9], 0n, 'Real row should not be padding');
  Assert.equal(trace.columns.paddingFlag[10], 1n, 'Padded row should be padding');
});

starkTests.test('AIR constraints validate correct trace', async () => {
  const events = [];
  for (let i = 1; i <= 5; i++) {
    events.push({
      eventId: `evt_${i}`,
      sequenceNumber: i,
      eventType: 'Test',
      entityType: 'Entity',
      entityId: `E-${i}`,
      payloadHash: `0x${'b'.repeat(64)}`,
      timestamp: new Date().toISOString()
    });
  }

  const trace = new ExecutionTrace(events);
  const air = new VesBatchAir(5, '0x' + '0'.repeat(64), '0x' + 'f'.repeat(64));

  const result = air.verifyAllConstraints(trace);

  Assert.ok(result.valid, 'Valid trace should satisfy all constraints');
  Assert.equal(result.violations.length, 0);
});

starkTests.test('StarkProver generates valid proof', async () => {
  const eventStore = new EventStore(CONFIG.tenantId, CONFIG.storeId);

  // Create events
  for (let i = 0; i < 20; i++) {
    eventStore.appendEvent({
      eventType: 'InventoryUpdated',
      entityType: 'Product',
      entityId: `PROD-${i}`,
      payload: { quantity: i * 10 }
    });
  }

  const batchManager = new BatchManager(eventStore);
  const batchInput = batchManager.createBatch(1, 20);

  Assert.equal(batchInput.batchSize, 20);
  Assert.equal(batchInput.sequenceStart, 1);
  Assert.equal(batchInput.sequenceEnd, 20);

  const { batchId, proof } = batchManager.proveBatch(batchInput);

  Assert.ok(batchId);
  Assert.equal(proof.version, 1);
  Assert.equal(proof.publicInputs.batchSize, 20);
  Assert.ok(proof.starkProof.traceCommitment.length > 0);
  Assert.ok(proof.starkProof.queryResponses.length >= 32);
  Assert.ok(proof.metadata.provingTimeMs > 0);
});

starkTests.test('StarkVerifier validates proof', async () => {
  const eventStore = new EventStore(CONFIG.tenantId, CONFIG.storeId);

  for (let i = 0; i < 10; i++) {
    eventStore.appendEvent({
      eventType: 'Test',
      entityType: 'Entity',
      entityId: `E-${i}`,
      payload: { value: i }
    });
  }

  const batchManager = new BatchManager(eventStore);
  const batchInput = batchManager.createBatch(1, 10);
  const { batchId, proof } = batchManager.proveBatch(batchInput);

  const result = batchManager.verifyBatch(batchId);

  Assert.ok(result.valid, `Proof should verify. Errors: ${JSON.stringify(result.errors)}`);
  // verificationTimeMs can be 0 on fast machines
  Assert.ok(result.verificationTimeMs >= 0, 'Should have verification time');
});

starkTests.test('Batch verification recorded in VES', async () => {
  const eventStore = new EventStore(CONFIG.tenantId, CONFIG.storeId);

  for (let i = 0; i < 5; i++) {
    eventStore.appendEvent({
      eventType: 'Test',
      entityType: 'Entity',
      entityId: `E-${i}`,
      payload: {}
    });
  }

  const batchManager = new BatchManager(eventStore);
  const batchInput = batchManager.createBatch(1, 5);
  const { batchId } = batchManager.proveBatch(batchInput);
  batchManager.verifyBatch(batchId);

  const verificationEvent = batchManager.recordVerification(batchId, {
    chain: 'solana',
    network: 'devnet',
    txHash: '0x' + 'abc'.repeat(21),
    status: 'verified'
  });

  Assert.ok(verificationEvent.eventId);
  Assert.equal(eventStore.events.length, 6, 'Should have 5 original + 1 verification event');

  const lastEvent = eventStore.events[eventStore.events.length - 1];
  Assert.equal(lastEvent.eventType, 'BatchVerified');
});

// =============================================================================
// Test Suite: VES-CONTRACT-1 Smart Contract Integration
// =============================================================================

const contractTests = new TestRunner('VES-CONTRACT-1: Smart Contract Integration');

contractTests.test('VES Anchor program initializes tenant', async () => {
  const blockchain = new SimulatedBlockchain();
  const anchorProgram = new VesAnchorProgram(blockchain);

  const result = anchorProgram.initializeTenant(
    CONFIG.tenantId,
    CONFIG.storeId,
    CONFIG.authorityAddress
  );

  Assert.equal(result.status, 'initialized');

  const tenant = anchorProgram.getTenant(CONFIG.tenantId);
  Assert.ok(tenant);
  Assert.equal(tenant.authority, CONFIG.authorityAddress);
  Assert.equal(tenant.currentSequence, 0);
});

contractTests.test('VES Anchor updates root on-chain', async () => {
  const blockchain = new SimulatedBlockchain();
  const anchorProgram = new VesAnchorProgram(blockchain);

  anchorProgram.initializeTenant(CONFIG.tenantId, CONFIG.storeId, CONFIG.authorityAddress);

  const newRoot = '0x' + 'a'.repeat(64);
  const result = anchorProgram.updateRoot(CONFIG.tenantId, newRoot, 100, CONFIG.authorityAddress);

  Assert.equal(result.newRoot, newRoot);
  Assert.equal(result.sequenceNumber, 100);
  Assert.ok(result.txHash.startsWith('0x'));

  const anchored = blockchain.getAnchoredRoot(CONFIG.tenantId);
  Assert.equal(anchored.root, newRoot);
  Assert.equal(anchored.sequence, 100);
});

contractTests.test('Escrow creates and locks funds', async () => {
  const eventStore = new EventStore(CONFIG.tenantId, CONFIG.storeId);
  const escrowManager = new EscrowManager(eventStore);

  escrowManager.setup(CONFIG.tenantId, CONFIG.storeId, CONFIG.authorityAddress);
  escrowManager.createParticipants(CONFIG.buyers.alice, CONFIG.sellers.widgetCo, '100000000');

  const result = escrowManager.createEscrowForOrder(
    'ORD-2025-001',
    CONFIG.buyers.alice,
    CONFIG.sellers.widgetCo,
    '50000000',
    CONFIG.tenantId
  );

  Assert.ok(result.escrowId.startsWith('0x'));
  Assert.equal(result.status, 'active');

  // Verify funds locked
  const buyerAccount = escrowManager.blockchain.getAccount(CONFIG.buyers.alice);
  Assert.equal(buyerAccount.balance, 50000000n, 'Buyer should have remaining balance');
});

contractTests.test('Escrow releases with valid VES proof', async () => {
  const eventStore = new EventStore(CONFIG.tenantId, CONFIG.storeId);
  const escrowManager = new EscrowManager(eventStore);

  escrowManager.setup(CONFIG.tenantId, CONFIG.storeId, CONFIG.authorityAddress);
  escrowManager.createParticipants(CONFIG.buyers.alice, CONFIG.sellers.widgetCo, '100000000');

  // Create escrow
  const escrow = escrowManager.createEscrowForOrder(
    'ORD-2025-002',
    CONFIG.buyers.alice,
    CONFIG.sellers.widgetCo,
    '75000000',
    CONFIG.tenantId
  );

  // Create order events
  eventStore.appendEvent({
    eventType: 'OrderCreated',
    entityType: 'Order',
    entityId: 'ORD-2025-002',
    payload: { buyer: CONFIG.buyers.alice, amount: '75000000' }
  });

  eventStore.appendEvent({
    eventType: 'OrderShipped',
    entityType: 'Order',
    entityId: 'ORD-2025-002',
    payload: { carrier: 'UPS', trackingNumber: '1Z999' }
  });

  eventStore.appendEvent({
    eventType: 'DeliveryConfirmed',
    entityType: 'Order',
    entityId: 'ORD-2025-002',
    payload: { confirmedBy: 'buyer', signedBy: 'Alice' }
  });

  // Sync to chain
  escrowManager.syncToChain(CONFIG.tenantId, CONFIG.authorityAddress);

  // Release escrow
  const releaseResult = escrowManager.releaseWithDeliveryConfirmation(
    escrow.escrowId,
    CONFIG.tenantId
  );

  Assert.ok(releaseResult.success);
  Assert.equal(releaseResult.status, 'released');
  Assert.equal(releaseResult.sellerReceived, '75000000');

  // Verify seller received funds
  const sellerAccount = escrowManager.blockchain.getAccount(CONFIG.sellers.widgetCo);
  Assert.equal(sellerAccount.balance, 75000000n);
});

contractTests.test('Escrow rejects wrong event type', async () => {
  const eventStore = new EventStore(CONFIG.tenantId, CONFIG.storeId);
  const escrowManager = new EscrowManager(eventStore);

  escrowManager.setup(CONFIG.tenantId, CONFIG.storeId, CONFIG.authorityAddress);
  escrowManager.createParticipants(CONFIG.buyers.bob, CONFIG.sellers.acmeCorp, '100000000');

  const escrow = escrowManager.createEscrowForOrder(
    'ORD-2025-003',
    CONFIG.buyers.bob,
    CONFIG.sellers.acmeCorp,
    '25000000',
    CONFIG.tenantId
  );

  // Only create shipped event (not delivery confirmation)
  eventStore.appendEvent({
    eventType: 'OrderShipped',
    entityType: 'Order',
    entityId: 'ORD-2025-003',
    payload: { carrier: 'FedEx' }
  });

  escrowManager.syncToChain(CONFIG.tenantId, CONFIG.authorityAddress);

  // Try to release without delivery confirmation
  Assert.throws(
    () => escrowManager.releaseWithDeliveryConfirmation(escrow.escrowId, CONFIG.tenantId),
    'Release event not found'
  );
});

contractTests.test('Merkle proof verification works', async () => {
  const eventStore = new EventStore(CONFIG.tenantId, CONFIG.storeId);

  // Add multiple events
  for (let i = 0; i < 10; i++) {
    eventStore.appendEvent({
      eventType: 'TestEvent',
      entityType: 'Test',
      entityId: `T-${i}`,
      payload: { index: i }
    });
  }

  // Generate proof for middle event
  const event = eventStore.events[5];
  const proof = eventStore.generateProof(event.eventId);

  Assert.ok(proof.eventHash.startsWith('0x'));
  Assert.ok(proof.merkleRoot.startsWith('0x'));
  Assert.ok(proof.proofPath.length > 0);

  // Verify proof
  const verified = MerkleTree.verifyProof(
    proof.eventHash,
    proof.proofPath,
    proof.merkleRoot
  );

  Assert.ok(verified, 'Merkle proof should verify');
});

// =============================================================================
// Test Suite: Full Integration Scenario
// =============================================================================

const integrationTests = new TestRunner('Full Integration: E-Commerce with Multi-Agent Treasury');

integrationTests.test('Complete e-commerce flow with all specs', async () => {
  console.log('\n    --- Starting Full Integration Scenario ---\n');

  // ==========================================================================
  // Step 1: Setup Multi-Agent Treasury (VES-MULTI-1)
  // ==========================================================================
  console.log('    [1] Setting up multi-agent treasury (2-of-3)...');

  const treasuryGroup = new AgentGroup(
    'Corporate Treasury',
    CONFIG.tenantId,
    2,
    [CONFIG.agents.cfo, CONFIG.agents.controller, CONFIG.agents.treasurer]
  );
  treasuryGroup.runDKG();

  Assert.equal(treasuryGroup.status, 'active');
  console.log(`        Group key: ${treasuryGroup.groupPublicKey.slice(0, 20)}...`);

  // ==========================================================================
  // Step 2: Setup Event Store and Escrow (VES-CONTRACT-1)
  // ==========================================================================
  console.log('    [2] Initializing VES and escrow contracts...');

  const eventStore = new EventStore(CONFIG.tenantId, CONFIG.storeId);
  const escrowManager = new EscrowManager(eventStore);
  const proposalManager = new ProposalManager(eventStore);

  escrowManager.setup(CONFIG.tenantId, CONFIG.storeId, CONFIG.authorityAddress);

  // Setup buyer accounts
  escrowManager.createParticipants(CONFIG.buyers.alice, CONFIG.sellers.widgetCo, '500000000'); // 500 USDC
  escrowManager.createParticipants(CONFIG.buyers.bob, CONFIG.sellers.acmeCorp, '300000000'); // 300 USDC

  console.log('        Accounts created for Alice, Bob, WidgetCo, AcmeCorp');

  // ==========================================================================
  // Step 3: Process Multiple Orders
  // ==========================================================================
  console.log('    [3] Processing orders...');

  const orders = [
    { id: 'ORD-001', buyer: CONFIG.buyers.alice, seller: CONFIG.sellers.widgetCo, amount: '100000000' },
    { id: 'ORD-002', buyer: CONFIG.buyers.alice, seller: CONFIG.sellers.widgetCo, amount: '150000000' },
    { id: 'ORD-003', buyer: CONFIG.buyers.bob, seller: CONFIG.sellers.acmeCorp, amount: '75000000' }
  ];

  const escrows = [];

  for (const order of orders) {
    // Create order event
    eventStore.appendEvent({
      eventType: 'OrderCreated',
      entityType: 'Order',
      entityId: order.id,
      payload: {
        buyer: order.buyer,
        seller: order.seller,
        amount: order.amount,
        currency: 'USDC'
      }
    });

    // Create escrow
    const escrow = escrowManager.createEscrowForOrder(
      order.id,
      order.buyer,
      order.seller,
      order.amount,
      CONFIG.tenantId
    );
    escrows.push({ ...order, escrowId: escrow.escrowId });

    console.log(`        Order ${order.id}: ${formatAmount(order.amount)} USDC escrowed`);
  }

  Assert.equal(escrows.length, 3);
  Assert.equal(eventStore.events.length, 3);

  // ==========================================================================
  // Step 4: Simulate Order Fulfillment
  // ==========================================================================
  console.log('    [4] Simulating order fulfillment...');

  for (const order of orders) {
    // Ship order
    eventStore.appendEvent({
      eventType: 'OrderShipped',
      entityType: 'Order',
      entityId: order.id,
      payload: { carrier: 'UPS', trackingNumber: `1Z${order.id}` }
    });

    // Confirm delivery
    eventStore.appendEvent({
      eventType: 'DeliveryConfirmed',
      entityType: 'Order',
      entityId: order.id,
      payload: { confirmedBy: 'buyer', condition: 'good' }
    });

    console.log(`        Order ${order.id}: Shipped and delivered`);
  }

  Assert.equal(eventStore.events.length, 9); // 3 orders * 3 events

  // ==========================================================================
  // Step 5: Sync to Chain and Release Escrows
  // ==========================================================================
  console.log('    [5] Syncing to chain and releasing escrows...');

  const syncResult = escrowManager.syncToChain(CONFIG.tenantId, CONFIG.authorityAddress);
  Assert.ok(syncResult.synced);
  console.log(`        Anchored root: ${syncResult.newRoot.slice(0, 20)}... at seq ${syncResult.sequenceNumber}`);

  let totalReleased = 0n;
  for (const escrow of escrows) {
    const result = escrowManager.releaseWithDeliveryConfirmation(
      escrow.escrowId,
      CONFIG.tenantId
    );
    Assert.ok(result.success);
    totalReleased += BigInt(escrow.amount);
    console.log(`        Escrow ${escrow.escrowId.slice(0, 16)}...: Released ${formatAmount(escrow.amount)} USDC`);
  }

  console.log(`        Total released: ${formatAmount(totalReleased.toString())} USDC`);

  // ==========================================================================
  // Step 6: Generate STARK Batch Proof (VES-STARK-1)
  // ==========================================================================
  console.log('    [6] Generating STARK batch proof...');

  const batchManager = new BatchManager(eventStore);
  const batchInput = batchManager.createBatch(1, eventStore.events.length);

  console.log(`        Batch size: ${batchInput.batchSize} events`);

  const { batchId, proof } = batchManager.proveBatch(batchInput);

  console.log(`        Proof generated in ${proof.metadata.provingTimeMs}ms`);
  console.log(`        Proof size: ${proof.metadata.proofSizeBytes} bytes`);

  // Verify proof
  const verifyResult = batchManager.verifyBatch(batchId);
  Assert.ok(verifyResult.valid);
  console.log(`        Proof verified in ${verifyResult.verificationTimeMs}ms`);

  // Record verification
  const verificationEvent = batchManager.recordVerification(batchId, {
    chain: 'solana',
    network: 'mainnet-beta',
    txHash: '0x' + 'verification_tx_hash'.padEnd(64, '0'),
    status: 'verified'
  });
  console.log(`        Verification recorded: ${verificationEvent.eventId}`);

  // ==========================================================================
  // Step 7: Treasury Payment with Threshold Signature
  // ==========================================================================
  console.log('    [7] Processing treasury payment with threshold signature...');

  // Create payment proposal
  const proposal = proposalManager.createProposal(
    treasuryGroup.groupId,
    'payment',
    'Supplier Settlement',
    {
      payment: {
        chain: 'solana',
        recipient: CONFIG.sellers.widgetCo,
        amount: '250000000', // Combined payment
        currency: 'USDC',
        memo: 'Settlement for ORD-001, ORD-002'
      }
    },
    CONFIG.agents.cfo,
    2 // 2-of-3 required
  );

  console.log(`        Proposal created: ${proposal.proposalId.slice(0, 8)}...`);

  // Vote
  proposalManager.vote(proposal.proposalId, CONFIG.agents.controller, 'approve', 'Verified invoices');
  proposalManager.vote(proposal.proposalId, CONFIG.agents.treasurer, 'approve', 'Funds available');

  const updatedProposal = proposalManager.getProposal(proposal.proposalId);
  Assert.equal(updatedProposal.status, 'approved');
  console.log('        Proposal approved with 2/3 votes');

  // Sign with threshold
  const paymentMessage = JSON.stringify({
    type: 'payment',
    recipient: CONFIG.sellers.widgetCo,
    amount: '250000000',
    proposalId: proposal.proposalId
  });

  const signResult = treasuryGroup.sign(
    paymentMessage,
    [CONFIG.agents.controller, CONFIG.agents.treasurer]
  );

  Assert.ok(signResult.signature.startsWith('0x'));
  console.log(`        Threshold signature: ${signResult.signature.slice(0, 20)}...`);

  // Record payment execution
  eventStore.appendEvent({
    eventType: 'PaymentExecuted',
    entityType: 'TreasuryPayment',
    entityId: proposal.proposalId,
    payload: {
      amount: '250000000',
      recipient: CONFIG.sellers.widgetCo,
      signers: signResult.signers,
      signature: signResult.signature
    }
  });

  // ==========================================================================
  // Step 8: Final State Verification
  // ==========================================================================
  console.log('    [8] Verifying final state...');

  const finalEventCount = eventStore.events.length;
  console.log(`        Total events: ${finalEventCount}`);

  const widgetCoBalance = escrowManager.blockchain.getAccount(CONFIG.sellers.widgetCo).balance;
  const acmeCorpBalance = escrowManager.blockchain.getAccount(CONFIG.sellers.acmeCorp).balance;

  console.log(`        WidgetCo balance: ${formatAmount(widgetCoBalance.toString())} USDC`);
  console.log(`        AcmeCorp balance: ${formatAmount(acmeCorpBalance.toString())} USDC`);

  Assert.equal(widgetCoBalance, 250000000n, 'WidgetCo should have received funds');
  Assert.equal(acmeCorpBalance, 75000000n, 'AcmeCorp should have received funds');

  console.log('\n    --- Integration Scenario Complete ---\n');
});

// =============================================================================
// Run All Tests
// =============================================================================

async function runAllTests() {
  console.log('\n' + '='.repeat(70));
  console.log('  VES End-to-End Integration Test Suite');
  console.log('  Testing VES-CONTRACT-1, VES-MULTI-1, VES-STARK-1');
  console.log('='.repeat(70));

  const results = [];

  results.push(await multiAgentTests.run());
  results.push(await starkTests.run());
  results.push(await contractTests.run());
  results.push(await integrationTests.run());

  const allPassed = results.every(r => r);

  console.log('='.repeat(70));
  if (allPassed) {
    console.log('  ALL TESTS PASSED');
  } else {
    console.log('  SOME TESTS FAILED');
    process.exitCode = 1;
  }
  console.log('='.repeat(70) + '\n');

  return allPassed;
}

// Run if executed directly
runAllTests().catch(err => {
  console.error('Test execution failed:', err);
  process.exitCode = 1;
});

export { runAllTests, multiAgentTests, starkTests, contractTests, integrationTests };
