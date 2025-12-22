/**
 * VES-MULTI-1 Multi-Agent Coordination Module
 * Implements FROST threshold signatures for E2E testing
 */

import crypto from 'crypto';
import { TestCrypto, uuid } from './test-utils.mjs';

// Field order for Ed25519 (simplified for testing)
const FIELD_ORDER = BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989');

// =============================================================================
// Utility Functions
// =============================================================================

function bytesToBigInt(bytes) {
  return BigInt('0x' + Buffer.from(bytes).toString('hex'));
}

function bigIntToBytes(n, length = 32) {
  let hex = n.toString(16);
  hex = hex.padStart(length * 2, '0');
  return Buffer.from(hex.slice(-length * 2), 'hex');
}

function modInverse(a, m) {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }

  return ((old_s % m) + m) % m;
}

function mod(a, m) {
  return ((a % m) + m) % m;
}

// Scalar multiplication simulation (simplified for testing)
function scalarMultiply(scalar, point) {
  // In real implementation, this would be EC point multiplication
  // For testing, we simulate with hash
  const input = Buffer.concat([
    bigIntToBytes(scalar),
    Buffer.from(point, 'hex')
  ]);
  return TestCrypto.hash(input);
}

function pointAdd(p1, p2) {
  // Simulated point addition for testing
  const combined = Buffer.concat([
    Buffer.from(p1, 'hex'),
    Buffer.from(p2, 'hex')
  ]);
  return TestCrypto.hash(combined);
}

// =============================================================================
// FROST DKG (Distributed Key Generation)
// =============================================================================

export class FrostDKG {
  constructor(threshold, totalParticipants) {
    this.t = threshold;
    this.n = totalParticipants;
    this.participantData = new Map();
  }

  /**
   * Phase 1: Generate polynomial and commitments for a participant
   */
  generateRound1(participantIndex) {
    // Generate random polynomial coefficients
    const coefficients = [];
    for (let i = 0; i < this.t; i++) {
      coefficients.push(bytesToBigInt(crypto.randomBytes(32)) % FIELD_ORDER);
    }

    // Compute commitments (C_i = g^a_i)
    const commitments = coefficients.map(c =>
      scalarMultiply(c, 'ed25519_base_point').toString('hex')
    );

    // Generate shares for each participant
    const shares = new Map();
    for (let j = 1; j <= this.n; j++) {
      const share = this.evaluatePolynomial(coefficients, BigInt(j));
      shares.set(j, share);
    }

    this.participantData.set(participantIndex, {
      coefficients,
      commitments,
      shares
    });

    return {
      participantIndex,
      commitments,
      sharesForOthers: shares
    };
  }

  evaluatePolynomial(coefficients, x) {
    let result = 0n;
    let xPower = 1n;

    for (const coef of coefficients) {
      result = mod(result + coef * xPower, FIELD_ORDER);
      xPower = mod(xPower * x, FIELD_ORDER);
    }

    return result;
  }

  /**
   * Phase 2: Combine shares to get final secret share
   */
  combineShares(participantIndex, receivedShares) {
    // Sum all received shares
    let secretShare = 0n;
    for (const share of receivedShares.values()) {
      secretShare = mod(secretShare + share, FIELD_ORDER);
    }

    // Compute public share
    const publicShare = scalarMultiply(secretShare, 'ed25519_base_point').toString('hex');

    return {
      participantIndex,
      secretShare,
      publicShare: '0x' + publicShare
    };
  }

  /**
   * Compute group public key from all commitments
   */
  computeGroupPublicKey(allCommitments) {
    // Sum the constant terms (first commitment from each participant)
    let groupKeyBuffer = Buffer.alloc(32);

    for (const [, commitments] of allCommitments) {
      const constantTerm = Buffer.from(commitments[0], 'hex');
      groupKeyBuffer = pointAdd(
        groupKeyBuffer.toString('hex'),
        constantTerm.toString('hex')
      );
    }

    return '0x' + groupKeyBuffer.toString('hex');
  }
}

// =============================================================================
// FROST Signer
// =============================================================================

export class FrostSigner {
  constructor(participantIndex, secretShare, groupPublicKey) {
    this.index = participantIndex;
    this.secretShare = secretShare;
    this.groupPublicKey = groupPublicKey;
    this.nonces = new Map();
  }

  /**
   * Round 1: Generate nonce commitments
   */
  generateNonceCommitment(sessionId) {
    const hidingNonce = bytesToBigInt(crypto.randomBytes(32)) % FIELD_ORDER;
    const bindingNonce = bytesToBigInt(crypto.randomBytes(32)) % FIELD_ORDER;

    // Compute commitments
    const hidingCommitment = scalarMultiply(hidingNonce, 'ed25519_base_point');
    const bindingCommitment = scalarMultiply(bindingNonce, 'ed25519_base_point');

    // Store nonces for round 2
    this.nonces.set(sessionId, { hidingNonce, bindingNonce });

    return {
      participantIndex: this.index,
      hidingCommitment: '0x' + hidingCommitment.toString('hex'),
      bindingCommitment: '0x' + bindingCommitment.toString('hex')
    };
  }

  /**
   * Round 2: Compute signature share
   */
  computeSignatureShare(sessionId, message, allCommitments, participantIndices) {
    const nonces = this.nonces.get(sessionId);
    if (!nonces) throw new Error('No nonces for session');

    // Compute binding factors
    const bindingFactors = this.computeBindingFactors(message, allCommitments, participantIndices);

    // Compute group commitment R
    let groupCommitmentParts = [];
    for (const idx of participantIndices) {
      const commitments = allCommitments.get(idx);
      const rho = bindingFactors.get(idx);

      // D_i + rho_i * E_i
      const hidingPart = Buffer.from(commitments.hidingCommitment.replace('0x', ''), 'hex');
      const bindingPart = scalarMultiply(rho, commitments.bindingCommitment.replace('0x', ''));

      groupCommitmentParts.push(pointAdd(
        hidingPart.toString('hex'),
        bindingPart.toString('hex')
      ));
    }

    // Sum all parts to get R
    let groupCommitment = groupCommitmentParts[0];
    for (let i = 1; i < groupCommitmentParts.length; i++) {
      groupCommitment = pointAdd(
        groupCommitment.toString('hex'),
        groupCommitmentParts[i].toString('hex')
      );
    }

    // Compute challenge c = H(R || PK || message)
    const challenge = this.computeChallenge(
      groupCommitment.toString('hex'),
      this.groupPublicKey,
      message
    );

    // Compute Lagrange coefficient
    const lambda = this.computeLagrangeCoefficient(this.index, participantIndices);

    // Compute signature share: z_i = d_i + e_i * rho_i + c * lambda_i * s_i
    const rho = bindingFactors.get(this.index);
    const { hidingNonce, bindingNonce } = nonces;

    let signatureShare = mod(
      hidingNonce +
      mod(bindingNonce * rho, FIELD_ORDER) +
      mod(mod(challenge * lambda, FIELD_ORDER) * this.secretShare, FIELD_ORDER),
      FIELD_ORDER
    );

    // Clear nonces (single use)
    this.nonces.delete(sessionId);

    return {
      participantIndex: this.index,
      signatureShare: '0x' + bigIntToBytes(signatureShare).toString('hex'),
      groupCommitment: '0x' + groupCommitment.toString('hex')
    };
  }

  computeBindingFactors(message, allCommitments, participantIndices) {
    const factors = new Map();

    for (const idx of participantIndices) {
      const commitments = allCommitments.get(idx);
      const input = Buffer.concat([
        Buffer.from(message),
        Buffer.from(idx.toString()),
        Buffer.from(commitments.hidingCommitment.replace('0x', ''), 'hex'),
        Buffer.from(commitments.bindingCommitment.replace('0x', ''), 'hex')
      ]);
      const hash = TestCrypto.hash(input);
      factors.set(idx, bytesToBigInt(hash) % FIELD_ORDER);
    }

    return factors;
  }

  computeChallenge(R, publicKey, message) {
    const input = Buffer.concat([
      Buffer.from(R.replace('0x', ''), 'hex'),
      Buffer.from(publicKey.replace('0x', ''), 'hex'),
      Buffer.from(message)
    ]);
    const hash = TestCrypto.hash(input);
    return bytesToBigInt(hash) % FIELD_ORDER;
  }

  computeLagrangeCoefficient(i, participantIndices) {
    let num = 1n;
    let den = 1n;

    for (const j of participantIndices) {
      if (j !== i) {
        num = mod(num * BigInt(j), FIELD_ORDER);
        den = mod(den * (BigInt(j) - BigInt(i)), FIELD_ORDER);
      }
    }

    return mod(num * modInverse(den, FIELD_ORDER), FIELD_ORDER);
  }
}

// =============================================================================
// FROST Coordinator
// =============================================================================

export class FrostCoordinator {
  constructor() {
    this.sessions = new Map();
  }

  /**
   * Start a new signing session
   */
  startSession(sessionId, participantIndices, message) {
    this.sessions.set(sessionId, {
      participantIndices,
      message,
      commitments: new Map(),
      signatureShares: [],
      status: 'collecting_commitments'
    });
    return sessionId;
  }

  /**
   * Collect a nonce commitment from a participant
   */
  addCommitment(sessionId, commitment) {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error('Session not found');

    session.commitments.set(commitment.participantIndex, commitment);

    if (session.commitments.size === session.participantIndices.length) {
      session.status = 'collecting_shares';
    }

    return session.status;
  }

  /**
   * Collect a signature share from a participant
   */
  addSignatureShare(sessionId, share) {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error('Session not found');

    session.signatureShares.push(share);

    if (session.signatureShares.length === session.participantIndices.length) {
      session.status = 'ready_to_combine';
    }

    return session.status;
  }

  /**
   * Combine signature shares into final signature
   */
  combineSignatures(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error('Session not found');
    if (session.status !== 'ready_to_combine') {
      throw new Error('Not all shares collected');
    }

    // Sum all signature shares
    let s = 0n;
    for (const share of session.signatureShares) {
      const shareBigInt = bytesToBigInt(
        Buffer.from(share.signatureShare.replace('0x', ''), 'hex')
      );
      s = mod(s + shareBigInt, FIELD_ORDER);
    }

    // R is the group commitment (same from all shares)
    const R = session.signatureShares[0].groupCommitment;

    // Signature is (R || s)
    const signature = Buffer.concat([
      Buffer.from(R.replace('0x', ''), 'hex'),
      bigIntToBytes(s)
    ]);

    session.status = 'complete';
    session.signature = '0x' + signature.toString('hex');

    return session.signature;
  }

  getSession(sessionId) {
    return this.sessions.get(sessionId);
  }
}

// =============================================================================
// Multi-Agent Group
// =============================================================================

export class AgentGroup {
  constructor(name, tenantId, threshold, memberAgentIds) {
    this.groupId = uuid();
    this.name = name;
    this.tenantId = tenantId;
    this.threshold = threshold;
    this.members = memberAgentIds.map((agentId, index) => ({
      agentId,
      shareIndex: index + 1,
      role: index === 0 ? 'admin' : 'signer'
    }));
    this.totalMembers = memberAgentIds.length;
    this.status = 'pending_dkg';
    this.groupPublicKey = null;
    this.signers = new Map();
    this.createdAt = new Date().toISOString();
  }

  /**
   * Run DKG ceremony to generate group key
   */
  runDKG() {
    const dkg = new FrostDKG(this.threshold, this.totalMembers);

    // Phase 1: Each participant generates commitments and shares
    const round1Messages = new Map();
    for (let i = 1; i <= this.totalMembers; i++) {
      round1Messages.set(i, dkg.generateRound1(i));
    }

    // Phase 2: Each participant combines received shares
    const finalShares = new Map();
    for (let i = 1; i <= this.totalMembers; i++) {
      const receivedShares = new Map();
      for (let j = 1; j <= this.totalMembers; j++) {
        receivedShares.set(j, round1Messages.get(j).sharesForOthers.get(i));
      }
      finalShares.set(i, dkg.combineShares(i, receivedShares));
    }

    // Compute group public key
    const allCommitments = new Map();
    for (let j = 1; j <= this.totalMembers; j++) {
      allCommitments.set(j, round1Messages.get(j).commitments);
    }
    this.groupPublicKey = dkg.computeGroupPublicKey(allCommitments);

    // Create signers for each member
    for (let i = 1; i <= this.totalMembers; i++) {
      const member = this.members[i - 1];
      const shareData = finalShares.get(i);

      this.signers.set(member.agentId, new FrostSigner(
        i,
        shareData.secretShare,
        this.groupPublicKey
      ));

      member.publicShare = shareData.publicShare;
    }

    this.status = 'active';
    this.dkgCompletedAt = new Date().toISOString();

    return {
      groupPublicKey: this.groupPublicKey,
      memberShares: Object.fromEntries(
        this.members.map(m => [m.agentId, m.publicShare])
      )
    };
  }

  /**
   * Sign a message with threshold participants
   */
  sign(message, participantAgentIds) {
    if (participantAgentIds.length < this.threshold) {
      throw new Error(`Insufficient signers: need ${this.threshold}, got ${participantAgentIds.length}`);
    }

    const sessionId = uuid();
    const coordinator = new FrostCoordinator();

    // Get participant indices
    const participantIndices = participantAgentIds.map(agentId => {
      const member = this.members.find(m => m.agentId === agentId);
      if (!member) throw new Error(`Unknown agent: ${agentId}`);
      return member.shareIndex;
    });

    coordinator.startSession(sessionId, participantIndices, message);

    // Round 1: Collect nonce commitments
    const commitments = new Map();
    for (const agentId of participantAgentIds) {
      const signer = this.signers.get(agentId);
      const commitment = signer.generateNonceCommitment(sessionId);
      commitments.set(commitment.participantIndex, commitment);
      coordinator.addCommitment(sessionId, commitment);
    }

    // Round 2: Compute signature shares
    for (const agentId of participantAgentIds) {
      const signer = this.signers.get(agentId);
      const share = signer.computeSignatureShare(
        sessionId,
        message,
        commitments,
        participantIndices
      );
      coordinator.addSignatureShare(sessionId, share);
    }

    // Combine into final signature
    const signature = coordinator.combineSignatures(sessionId);

    return {
      signature,
      signers: participantAgentIds,
      sessionId
    };
  }
}

// =============================================================================
// Proposal System
// =============================================================================

export class ProposalManager {
  constructor(eventStore) {
    this.proposals = new Map();
    this.eventStore = eventStore;
  }

  createProposal(groupId, type, title, action, proposedBy, requiredApprovals, deadlineHours = 168) {
    const proposal = {
      proposalId: uuid(),
      groupId,
      type,
      title,
      action,
      proposedBy,
      proposedAt: new Date().toISOString(),
      requiredApprovals,
      deadline: new Date(Date.now() + deadlineHours * 60 * 60 * 1000).toISOString(),
      votes: [],
      status: 'pending'
    };

    this.proposals.set(proposal.proposalId, proposal);

    // Record in VES
    this.eventStore.appendEvent({
      eventType: 'ProposalCreated',
      entityType: 'Proposal',
      entityId: proposal.proposalId,
      payload: {
        groupId: proposal.groupId,
        type: proposal.type,
        title: proposal.title,
        proposedBy: proposal.proposedBy,
        requiredApprovals: proposal.requiredApprovals
      }
    });

    return proposal;
  }

  vote(proposalId, voterId, decision, reason = '') {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) throw new Error('Proposal not found');
    if (proposal.status !== 'pending') throw new Error('Proposal not pending');

    // Check deadline
    if (new Date() > new Date(proposal.deadline)) {
      proposal.status = 'expired';
      throw new Error('Proposal expired');
    }

    // Check for duplicate vote
    if (proposal.votes.some(v => v.voterId === voterId)) {
      throw new Error('Already voted');
    }

    const vote = {
      voteId: uuid(),
      proposalId,
      voterId,
      decision,
      reason,
      votedAt: new Date().toISOString()
    };

    proposal.votes.push(vote);

    // Record in VES
    this.eventStore.appendEvent({
      eventType: 'VoteCast',
      entityType: 'Proposal',
      entityId: proposalId,
      payload: {
        voteId: vote.voteId,
        voterId,
        decision,
        reason
      }
    });

    // Check threshold
    const approvals = proposal.votes.filter(v => v.decision === 'approve').length;
    if (approvals >= proposal.requiredApprovals) {
      proposal.status = 'approved';
    }

    return vote;
  }

  getProposal(proposalId) {
    return this.proposals.get(proposalId);
  }
}
