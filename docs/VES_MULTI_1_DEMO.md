# VES-MULTI-1 Multi-Agent Coordination Demo

This walkthrough demonstrates VES-MULTI-1 multi-agent coordination using FROST threshold signatures for collective authorization.

## Prerequisites

- Node.js 18+
- VES Sequencer running
- PostgreSQL database
- @noble/curves library

## Demo Scenario: Treasury Management

A company treasury requires 2-of-3 approval for payments over $10,000. Three agents (CFO, Controller, Treasurer) collectively control the treasury wallet.

```
┌─────────────────────────────────────────────────────────────────┐
│              Multi-Agent Treasury Approval Flow                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐                  │
│   │   CFO   │     │Controller│    │Treasurer│                  │
│   │ Agent 1 │     │ Agent 2  │    │ Agent 3 │                  │
│   │ share_1 │     │ share_2  │    │ share_3 │                  │
│   └────┬────┘     └────┬─────┘    └────┬────┘                  │
│        │               │               │                        │
│        │    Threshold: 2-of-3          │                        │
│        │               │               │                        │
│        └───────────────┼───────────────┘                        │
│                        │                                        │
│                        ▼                                        │
│              ┌─────────────────┐                                │
│              │  Group Public   │                                │
│              │  Key (Treasury) │                                │
│              │  0x7f8c9d...    │                                │
│              └────────┬────────┘                                │
│                       │                                         │
│                       ▼                                         │
│              ┌─────────────────┐                                │
│              │ Treasury Wallet │                                │
│              │ Solana: ABC123  │                                │
│              │ Ethereum: 0x... │                                │
│              └─────────────────┘                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Step 1: Setup Multi-Agent Group

```javascript
// demo-create-group.mjs
import { MultiAgentCoordinator } from '../lib/multi-agent.js';
import { Sequencer } from '../lib/sequencer.js';
import crypto from 'crypto';

const sequencer = new Sequencer();
await sequencer.connect();

const coordinator = new MultiAgentCoordinator(sequencer);

// Define group members
const members = [
  {
    agentId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    name: "CFO Agent",
    role: "admin"
  },
  {
    agentId: "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    name: "Controller Agent",
    role: "signer"
  },
  {
    agentId: "c3d4e5f6-a7b8-9012-cdef-123456789012",
    name: "Treasurer Agent",
    role: "signer"
  }
];

// Create 2-of-3 threshold group
const group = await coordinator.createGroup({
  name: "Corporate Treasury",
  tenantId: "550e8400-e29b-41d4-a716-446655440000",
  threshold: 2,
  members: members.map(m => m.agentId)
});

console.log("Group created:", group.groupId);
console.log("Threshold:", `${group.threshold}-of-${group.totalMembers}`);

// Record group creation in VES
const event = {
  eventType: "MultiAgentGroupCreated",
  entityType: "AgentGroup",
  entityId: group.groupId,
  version: 1,
  payload: {
    name: group.name,
    threshold: group.threshold,
    totalMembers: group.totalMembers,
    memberIds: members.map(m => m.agentId)
  },
  timestamp: new Date().toISOString()
};

await sequencer.appendEvent(event);
```

## Step 2: Distributed Key Generation (DKG)

```javascript
// demo-dkg.mjs
import { FrostDKG } from '../lib/frost-dkg.js';
import { ed25519 } from '@noble/curves/ed25519';

class FrostDKG {
  constructor(threshold, totalParticipants) {
    this.t = threshold;
    this.n = totalParticipants;
    this.participants = new Map();
  }

  // Phase 1: Each participant generates polynomial and commitments
  generateRound1(participantIndex) {
    // Generate random polynomial coefficients
    const coefficients = [];
    for (let i = 0; i < this.t; i++) {
      coefficients.push(ed25519.utils.randomPrivateKey());
    }

    // Compute commitments (public polynomial)
    const commitments = coefficients.map(c =>
      ed25519.ExtendedPoint.BASE.multiply(bytesToBigInt(c))
    );

    // Generate shares for each participant
    const shares = new Map();
    for (let j = 1; j <= this.n; j++) {
      const share = this.evaluatePolynomial(coefficients, j);
      shares.set(j, share);
    }

    return {
      participantIndex,
      commitments: commitments.map(c => c.toHex()),
      shares // Keep secret, send encrypted to each participant
    };
  }

  evaluatePolynomial(coefficients, x) {
    let result = 0n;
    const xBig = BigInt(x);
    const order = ed25519.CURVE.n;

    for (let i = coefficients.length - 1; i >= 0; i--) {
      result = (result * xBig + bytesToBigInt(coefficients[i])) % order;
    }
    return result;
  }

  // Phase 2: Verify commitments and combine shares
  combineShares(participantIndex, receivedShares, allCommitments) {
    // Verify each received share against commitments
    for (const [fromIndex, share] of receivedShares) {
      const valid = this.verifyShare(
        participantIndex,
        share,
        allCommitments.get(fromIndex)
      );
      if (!valid) {
        throw new Error(`Invalid share from participant ${fromIndex}`);
      }
    }

    // Combine shares to get final secret share
    let secretShare = 0n;
    const order = ed25519.CURVE.n;

    for (const share of receivedShares.values()) {
      secretShare = (secretShare + share) % order;
    }

    // Compute public share
    const publicShare = ed25519.ExtendedPoint.BASE.multiply(secretShare);

    return {
      secretShare,
      publicShare: publicShare.toHex()
    };
  }

  // Compute group public key from commitments
  computeGroupPublicKey(allCommitments) {
    let groupKey = ed25519.ExtendedPoint.ZERO;

    for (const commitments of allCommitments.values()) {
      // Add constant term (first commitment) from each participant
      groupKey = groupKey.add(
        ed25519.ExtendedPoint.fromHex(commitments[0])
      );
    }

    return groupKey.toHex();
  }
}

// Run DKG ceremony
const dkg = new FrostDKG(2, 3);

// Each participant generates their round 1 message
const round1Messages = new Map();
for (let i = 1; i <= 3; i++) {
  round1Messages.set(i, dkg.generateRound1(i));
}

// Exchange shares securely (encrypted in production)
// Each participant combines their received shares
const finalShares = new Map();
for (let i = 1; i <= 3; i++) {
  const receivedShares = new Map();
  for (let j = 1; j <= 3; j++) {
    receivedShares.set(j, round1Messages.get(j).shares.get(i));
  }

  const allCommitments = new Map();
  for (let j = 1; j <= 3; j++) {
    allCommitments.set(j, round1Messages.get(j).commitments);
  }

  finalShares.set(i, dkg.combineShares(i, receivedShares, allCommitments));
}

// Compute group public key
const allCommitments = new Map();
for (let j = 1; j <= 3; j++) {
  allCommitments.set(j, round1Messages.get(j).commitments);
}
const groupPublicKey = dkg.computeGroupPublicKey(allCommitments);

console.log("DKG Complete!");
console.log("Group Public Key:", groupPublicKey);
console.log("Participant shares generated and verified");

// Record DKG completion in VES
const dkgEvent = {
  eventType: "DKGCompleted",
  entityType: "AgentGroup",
  entityId: group.groupId,
  version: 2,
  payload: {
    groupPublicKey,
    participantPublicShares: Object.fromEntries(
      [...finalShares.entries()].map(([i, s]) => [i, s.publicShare])
    )
  },
  timestamp: new Date().toISOString()
};

await sequencer.appendEvent(dkgEvent);
```

## Step 3: Create Payment Proposal

```javascript
// demo-create-proposal.mjs
import { ProposalManager } from '../lib/proposal-manager.js';

const proposalManager = new ProposalManager(sequencer, coordinator);

// CFO proposes a large payment
const proposal = await proposalManager.createProposal({
  groupId: group.groupId,
  type: "payment",
  title: "Q1 Supplier Payment",
  description: "Pay supplier invoice #INV-2025-0042 for raw materials",
  proposedBy: members[0].agentId, // CFO
  action: {
    payment: {
      chain: "solana",
      recipient: "SuppL1erWa11etAddress1111111111111111111111",
      amount: "50000000000", // 50,000 USDC (6 decimals)
      currency: "USDC",
      memo: "Invoice INV-2025-0042"
    }
  },
  requiredApprovals: 2,
  deadline: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
});

console.log("Proposal created:", proposal.proposalId);
console.log("Status:", proposal.status);
console.log("Required approvals:", proposal.requiredApprovals);

// Record proposal in VES
const proposalEvent = {
  eventType: "ProposalCreated",
  entityType: "Proposal",
  entityId: proposal.proposalId,
  version: 1,
  payload: {
    groupId: proposal.groupId,
    type: proposal.type,
    title: proposal.title,
    amount: proposal.action.payment.amount,
    recipient: proposal.action.payment.recipient,
    proposedBy: proposal.proposedBy,
    requiredApprovals: proposal.requiredApprovals,
    deadline: proposal.deadline
  },
  timestamp: new Date().toISOString()
};

await sequencer.appendEvent(proposalEvent);
```

## Step 4: Voting Process

```javascript
// demo-vote.mjs
import { ed25519 } from '@noble/curves/ed25519';

// Controller reviews and approves
const vote1 = await proposalManager.vote({
  proposalId: proposal.proposalId,
  voterId: members[1].agentId, // Controller
  decision: "approve",
  reason: "Invoice verified against PO-2025-0015"
});

console.log("Controller voted:", vote1.decision);

// Record vote in VES
await sequencer.appendEvent({
  eventType: "VoteCast",
  entityType: "Proposal",
  entityId: proposal.proposalId,
  version: 2,
  payload: {
    voteId: vote1.voteId,
    voterId: vote1.voterId,
    decision: vote1.decision,
    reason: vote1.reason
  },
  timestamp: new Date().toISOString()
});

// Treasurer also approves
const vote2 = await proposalManager.vote({
  proposalId: proposal.proposalId,
  voterId: members[2].agentId, // Treasurer
  decision: "approve",
  reason: "Funds available, payment authorized"
});

console.log("Treasurer voted:", vote2.decision);

// Record second vote
await sequencer.appendEvent({
  eventType: "VoteCast",
  entityType: "Proposal",
  entityId: proposal.proposalId,
  version: 3,
  payload: {
    voteId: vote2.voteId,
    voterId: vote2.voterId,
    decision: vote2.decision,
    reason: vote2.reason
  },
  timestamp: new Date().toISOString()
});

// Check if threshold reached
const updatedProposal = await proposalManager.getProposal(proposal.proposalId);
console.log("Current approvals:", updatedProposal.votes.filter(v => v.decision === "approve").length);
console.log("Proposal status:", updatedProposal.status);

if (updatedProposal.status === "approved") {
  console.log("Threshold reached! Ready for signing ceremony.");
}
```

## Step 5: FROST Signing Ceremony

```javascript
// demo-frost-signing.mjs
import { FrostSigner, combineSignatureShares } from '../lib/frost-signer.js';

class FrostSigner {
  constructor(participantIndex, secretShare, groupPublicKey) {
    this.index = participantIndex;
    this.secretShare = secretShare;
    this.groupPublicKey = groupPublicKey;
    this.nonces = new Map();
  }

  // Round 1: Generate nonce commitments
  generateNonceCommitment(sessionId) {
    // Generate two random nonces
    const hidingNonce = ed25519.utils.randomPrivateKey();
    const bindingNonce = ed25519.utils.randomPrivateKey();

    // Compute commitments
    const hidingCommitment = ed25519.ExtendedPoint.BASE.multiply(
      bytesToBigInt(hidingNonce)
    );
    const bindingCommitment = ed25519.ExtendedPoint.BASE.multiply(
      bytesToBigInt(bindingNonce)
    );

    // Store nonces for round 2
    this.nonces.set(sessionId, { hidingNonce, bindingNonce });

    return {
      participantIndex: this.index,
      hidingCommitment: hidingCommitment.toHex(),
      bindingCommitment: bindingCommitment.toHex()
    };
  }

  // Round 2: Compute signature share
  computeSignatureShare(sessionId, message, allCommitments, participantIndices) {
    const nonces = this.nonces.get(sessionId);
    if (!nonces) throw new Error("No nonces for session");

    // Compute binding factors
    const bindingFactors = this.computeBindingFactors(
      message,
      allCommitments,
      participantIndices
    );

    // Compute group commitment
    let groupCommitment = ed25519.ExtendedPoint.ZERO;
    for (const [idx, commitments] of allCommitments) {
      const rho = bindingFactors.get(idx);
      const hiding = ed25519.ExtendedPoint.fromHex(commitments.hidingCommitment);
      const binding = ed25519.ExtendedPoint.fromHex(commitments.bindingCommitment);

      const contribution = hiding.add(binding.multiply(rho));
      groupCommitment = groupCommitment.add(contribution);
    }

    // Compute challenge
    const challenge = this.computeChallenge(
      groupCommitment,
      this.groupPublicKey,
      message
    );

    // Compute Lagrange coefficient
    const lambda = this.computeLagrangeCoefficient(
      this.index,
      participantIndices
    );

    // Compute signature share
    const order = ed25519.CURVE.n;
    const hidingBig = bytesToBigInt(nonces.hidingNonce);
    const bindingBig = bytesToBigInt(nonces.bindingNonce);
    const rho = bindingFactors.get(this.index);

    const noncePart = (hidingBig + bindingBig * rho) % order;
    const secretPart = (challenge * lambda * this.secretShare) % order;
    const share = (noncePart + secretPart) % order;

    // Clear nonces (single use)
    this.nonces.delete(sessionId);

    return {
      participantIndex: this.index,
      signatureShare: bigIntToHex(share),
      groupCommitment: groupCommitment.toHex()
    };
  }

  computeBindingFactors(message, allCommitments, participantIndices) {
    const factors = new Map();

    for (const idx of participantIndices) {
      const commitments = allCommitments.get(idx);
      const input = Buffer.concat([
        Buffer.from(message),
        Buffer.from(idx.toString()),
        Buffer.from(commitments.hidingCommitment, 'hex'),
        Buffer.from(commitments.bindingCommitment, 'hex')
      ]);
      const hash = sha512(input);
      factors.set(idx, bytesToBigInt(hash.slice(0, 32)) % ed25519.CURVE.n);
    }

    return factors;
  }

  computeChallenge(R, publicKey, message) {
    const input = Buffer.concat([
      Buffer.from(R.toHex(), 'hex'),
      Buffer.from(publicKey, 'hex'),
      Buffer.from(message)
    ]);
    const hash = sha512(input);
    return bytesToBigInt(hash) % ed25519.CURVE.n;
  }

  computeLagrangeCoefficient(i, participantIndices) {
    const order = ed25519.CURVE.n;
    let num = 1n;
    let den = 1n;

    for (const j of participantIndices) {
      if (j !== i) {
        num = (num * BigInt(j)) % order;
        den = (den * (BigInt(j) - BigInt(i) + order)) % order;
      }
    }

    return (num * modInverse(den, order)) % order;
  }
}

function combineSignatureShares(groupCommitment, shares) {
  const order = ed25519.CURVE.n;
  let s = 0n;

  for (const share of shares) {
    s = (s + BigInt('0x' + share.signatureShare)) % order;
  }

  // Signature is (R, s) where R is group commitment
  const R = Buffer.from(groupCommitment, 'hex');
  const sBytes = bigIntToBytes(s);

  return Buffer.concat([R, sBytes]);
}

// Signing ceremony execution
const sessionId = crypto.randomUUID();
const participatingSigners = [1, 2]; // Controller and Treasurer (indices)

// Create message to sign (payment transaction)
const message = JSON.stringify({
  type: "payment",
  recipient: "SuppL1erWa11etAddress1111111111111111111111",
  amount: "50000000000",
  currency: "USDC",
  proposalId: proposal.proposalId,
  timestamp: new Date().toISOString()
});

// Round 1: Collect nonce commitments
const commitments = new Map();
for (const idx of participatingSigners) {
  const signer = new FrostSigner(
    idx,
    finalShares.get(idx).secretShare,
    groupPublicKey
  );
  commitments.set(idx, signer.generateNonceCommitment(sessionId));
}

console.log("Round 1: Nonce commitments collected");

// Round 2: Generate signature shares
const signatureShares = [];
let groupCommitment;

for (const idx of participatingSigners) {
  const signer = new FrostSigner(
    idx,
    finalShares.get(idx).secretShare,
    groupPublicKey
  );
  // Restore nonces (in practice, same object instance)
  signer.nonces.set(sessionId, storedNonces.get(idx));

  const share = signer.computeSignatureShare(
    sessionId,
    message,
    commitments,
    participatingSigners
  );
  signatureShares.push(share);
  groupCommitment = share.groupCommitment;
}

console.log("Round 2: Signature shares computed");

// Combine shares into final signature
const signature = combineSignatureShares(groupCommitment, signatureShares);
console.log("Final signature:", signature.toString('hex'));

// Verify signature
const publicKeyBytes = Buffer.from(groupPublicKey, 'hex');
const valid = ed25519.verify(signature, Buffer.from(message), publicKeyBytes);
console.log("Signature valid:", valid);
```

## Step 6: Execute Transaction

```javascript
// demo-execute.mjs
import { Connection, Transaction, SystemProgram } from '@solana/web3.js';
import { getAssociatedTokenAddress, createTransferInstruction } from '@solana/spl-token';

// Create Solana transaction
const connection = new Connection('https://api.devnet.solana.com');

const treasuryAddress = deriveAddress(groupPublicKey, 'solana');
const recipientAddress = 'SuppL1erWa11etAddress1111111111111111111111';
const amount = 50_000_000_000n; // 50,000 USDC

// Build transaction
const tx = new Transaction();

const treasuryTokenAccount = await getAssociatedTokenAddress(
  USDC_MINT,
  treasuryAddress
);

const recipientTokenAccount = await getAssociatedTokenAddress(
  USDC_MINT,
  recipientAddress
);

tx.add(
  createTransferInstruction(
    treasuryTokenAccount,
    recipientTokenAccount,
    treasuryAddress,
    amount
  )
);

// The signature from FROST is a standard Ed25519 signature
// It can be used directly with Solana
tx.addSignature(treasuryAddress, signature);

// Submit transaction
const txHash = await connection.sendRawTransaction(tx.serialize());
console.log("Transaction submitted:", txHash);

// Wait for confirmation
await connection.confirmTransaction(txHash);
console.log("Transaction confirmed!");

// Record execution in VES
await sequencer.appendEvent({
  eventType: "ProposalExecuted",
  entityType: "Proposal",
  entityId: proposal.proposalId,
  version: 4,
  payload: {
    executedBy: participatingSigners.map(i => members[i-1].agentId),
    txHash,
    chain: "solana",
    amount: "50000000000",
    recipient: recipientAddress
  },
  timestamp: new Date().toISOString()
});
```

## Complete Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    VES-MULTI-1 Complete Flow                             │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                     1. GROUP SETUP (One-time)                       │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │                                                                     │ │
│  │   Agent 1          Agent 2          Agent 3                         │ │
│  │   (CFO)           (Controller)     (Treasurer)                      │ │
│  │     │                │                │                             │ │
│  │     └────────────────┼────────────────┘                             │ │
│  │                      │                                              │ │
│  │              ┌───────▼───────┐                                      │ │
│  │              │  DKG Ceremony │                                      │ │
│  │              │  Round 1 & 2  │                                      │ │
│  │              └───────┬───────┘                                      │ │
│  │                      │                                              │ │
│  │              ┌───────▼───────┐                                      │ │
│  │              │ Group Key: PK │                                      │ │
│  │              │ Threshold: 2/3│                                      │ │
│  │              └───────────────┘                                      │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                     2. PROPOSAL PHASE                               │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │                                                                     │ │
│  │   CFO creates proposal:                                             │ │
│  │   ┌─────────────────────────────┐                                   │ │
│  │   │ Payment: $50,000 USDC       │                                   │ │
│  │   │ To: Supplier wallet         │                                   │ │
│  │   │ Required: 2 approvals       │                                   │ │
│  │   └─────────────────────────────┘                                   │ │
│  │                │                                                    │ │
│  │                ▼                                                    │ │
│  │   ┌─────────────────────────────┐                                   │ │
│  │   │ VES Event: ProposalCreated  │                                   │ │
│  │   └─────────────────────────────┘                                   │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                     3. VOTING PHASE                                 │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │                                                                     │ │
│  │   Controller: ✓ Approve      Treasurer: ✓ Approve                   │ │
│  │   "Invoice verified"         "Funds available"                      │ │
│  │        │                          │                                 │ │
│  │        ▼                          ▼                                 │ │
│  │   ┌───────────┐              ┌───────────┐                          │ │
│  │   │ VES Event │              │ VES Event │                          │ │
│  │   │ VoteCast  │              │ VoteCast  │                          │ │
│  │   └───────────┘              └───────────┘                          │ │
│  │                                                                     │ │
│  │   Threshold reached (2/3) → Status: APPROVED                        │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                     4. SIGNING CEREMONY                             │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │                                                                     │ │
│  │   Round 1: Nonce Commitments                                        │ │
│  │   ┌─────────┐                ┌─────────┐                            │ │
│  │   │Agent 2  │                │Agent 3  │                            │ │
│  │   │(D₂, E₂) │                │(D₃, E₃) │                            │ │
│  │   └────┬────┘                └────┬────┘                            │ │
│  │        │                          │                                 │ │
│  │        └──────────┬───────────────┘                                 │ │
│  │                   │                                                 │ │
│  │   Round 2: Signature Shares                                         │ │
│  │   ┌─────────┐     │          ┌─────────┐                            │ │
│  │   │Agent 2  │◄────┴─────────▶│Agent 3  │                            │ │
│  │   │ z₂      │                │ z₃      │                            │ │
│  │   └────┬────┘                └────┬────┘                            │ │
│  │        │                          │                                 │ │
│  │        └──────────┬───────────────┘                                 │ │
│  │                   │                                                 │ │
│  │                   ▼                                                 │ │
│  │           ┌───────────────┐                                         │ │
│  │           │ Combine:      │                                         │ │
│  │           │ σ = (R, z)    │                                         │ │
│  │           │ Standard      │                                         │ │
│  │           │ Ed25519 sig   │                                         │ │
│  │           └───────────────┘                                         │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                     5. EXECUTION                                    │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │                                                                     │ │
│  │   ┌─────────────────┐        ┌─────────────────┐                    │ │
│  │   │ Solana TX:      │        │ VES Event:      │                    │ │
│  │   │ Transfer 50K    │───────▶│ ProposalExecuted│                    │ │
│  │   │ USDC to Supplier│        │ tx_hash: ...    │                    │ │
│  │   └─────────────────┘        └─────────────────┘                    │ │
│  │                                                                     │ │
│  │   Supplier receives $50,000 USDC                                    │ │
│  │   Full audit trail in VES                                           │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Security Properties

| Property | Description |
|----------|-------------|
| **Threshold Security** | No single agent can sign; requires t-of-n cooperation |
| **Key Privacy** | Individual secret shares never revealed; only combined signature |
| **Audit Trail** | All actions recorded in VES with signatures |
| **Replay Prevention** | Session IDs and timestamps prevent signature reuse |
| **Accountability** | Voting records identify approving agents |

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `InsufficientSigners` | Not enough participants | Recruit additional signers |
| `InvalidShare` | DKG share verification failed | Restart DKG ceremony |
| `ProposalExpired` | Deadline passed | Create new proposal |
| `ThresholdNotMet` | Not enough approvals | Continue voting |
| `InvalidNonce` | Nonce reuse attempt | Generate fresh nonces |

## Next Steps

- Review [VES-MULTI-1 Specification](./VES_MULTI_1_SPECIFICATION.md) for full details
- Explore [VES-CONTRACT-1](./VES_CONTRACT_1_SPECIFICATION.md) for escrow integration
- See [VES-STARK-1](./VES_STARK_1_SPECIFICATION.md) for batch validity proofs
