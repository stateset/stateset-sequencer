# VES-MULTI-1: Multi-Agent Coordination Specification

**Version:** 1.0
**Status:** Draft
**Last Updated:** 2025-12-22
**Dependencies:** VES-SIG-1, VES-CHAIN-1

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Principles](#2-design-principles)
3. [Threshold Signatures](#3-threshold-signatures)
4. [Multi-Agent Architecture](#4-multi-agent-architecture)
5. [Coordination Protocols](#5-coordination-protocols)
6. [Proposal System](#6-proposal-system)
7. [Signing Ceremonies](#7-signing-ceremonies)
8. [Agent Communication](#8-agent-communication)
9. [Security Model](#9-security-model)
10. [Implementation](#10-implementation)
11. [Use Cases](#11-use-cases)
12. [Code Examples](#12-code-examples)
13. [Implementation Checklist](#13-implementation-checklist)

---

## 1. Overview

VES-MULTI-1 defines how multiple VES agents can coordinate to perform actions that require collective authorization. This enables:

- **Threshold Signatures**: t-of-n agents must agree for action
- **Distributed Control**: No single agent has unilateral control
- **Fault Tolerance**: System operates even if some agents offline
- **Audit Trail**: All coordination recorded in VES

### 1.1 Key Capabilities

| Capability | Description |
|------------|-------------|
| **Threshold Signing** | t-of-n Ed25519 threshold signatures (FROST) |
| **Multi-Sig Wallets** | Require multiple agents for payments |
| **Proposal Voting** | Agents vote on proposed actions |
| **Distributed Key Generation** | Generate shared keys without trusted dealer |
| **Agent Coordination** | Secure communication between agents |

### 1.2 System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    VES-MULTI-1 Multi-Agent System                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│                         ┌─────────────────┐                             │
│                         │   VES Sequencer │                             │
│                         │                 │                             │
│                         │  • Proposals    │                             │
│                         │  • Votes        │                             │
│                         │  • Signatures   │                             │
│                         └────────┬────────┘                             │
│                                  │                                       │
│              ┌───────────────────┼───────────────────┐                  │
│              │                   │                   │                  │
│              ▼                   ▼                   ▼                  │
│       ┌──────────┐        ┌──────────┐        ┌──────────┐             │
│       │ Agent A  │◄──────►│ Agent B  │◄──────►│ Agent C  │             │
│       │          │        │          │        │          │             │
│       │ Share 1  │        │ Share 2  │        │ Share 3  │             │
│       └────┬─────┘        └────┬─────┘        └────┬─────┘             │
│            │                   │                   │                    │
│            └───────────────────┼───────────────────┘                    │
│                                │                                         │
│                                ▼                                         │
│                    ┌───────────────────────┐                            │
│                    │   Threshold Signature │                            │
│                    │      (2-of-3)         │                            │
│                    └───────────────────────┘                            │
│                                │                                         │
│                                ▼                                         │
│                    ┌───────────────────────┐                            │
│                    │   Execute Transaction │                            │
│                    │   (Blockchain/VES)    │                            │
│                    └───────────────────────┘                            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Design Principles

### 2.1 No Single Point of Failure

```
❌ Bad:  Single agent controls funds
✅ Good: t-of-n threshold required

Example: 2-of-3 multi-sig
• Agent A alone: Cannot sign ✗
• Agent B alone: Cannot sign ✗
• Agent A + B:   Can sign ✓
• Agent A + C:   Can sign ✓
• Agent B + C:   Can sign ✓
```

### 2.2 Verifiable Coordination

All multi-agent coordination is recorded in VES:

```
┌─────────────────────────────────────────────────────────────────┐
│  VES Event Trail for Multi-Sig Payment                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Proposal.Created       (Agent A proposes payment)           │
│  2. Vote.Cast              (Agent B approves)                   │
│  3. Vote.Cast              (Agent C approves)                   │
│  4. Proposal.Approved      (Threshold reached)                  │
│  5. SigningSession.Started (Agents begin FROST protocol)        │
│  6. SigningSession.Completed (Threshold signature created)      │
│  7. Transaction.Executed   (Payment sent on-chain)              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Cryptographic Security

- FROST (Flexible Round-Optimized Schnorr Threshold) signatures
- Distributed Key Generation (DKG) without trusted dealer
- Verifiable Secret Sharing (VSS) for key shares

---

## 3. Threshold Signatures

### 3.1 FROST Overview

FROST (Flexible Round-Optimized Schnorr Threshold) enables t-of-n threshold signatures compatible with Ed25519:

```
┌─────────────────────────────────────────────────────────────────┐
│                    FROST Protocol Overview                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Setup Phase (One-time):                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Distributed Key Generation (DKG)                        │   │
│  │                                                          │   │
│  │  • Each agent generates random polynomial                │   │
│  │  • Agents exchange commitments                           │   │
│  │  • Each agent receives their secret share                │   │
│  │  • Group public key computed                             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Signing Phase (Per message):                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Round 1: Commitment                                     │   │
│  │  • Each signer generates nonce pair                      │   │
│  │  • Broadcast commitments to group                        │   │
│  │                                                          │   │
│  │  Round 2: Signature Share                                │   │
│  │  • Each signer computes partial signature                │   │
│  │  • Combine t shares into full signature                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Result: Standard Ed25519 signature                             │
│  • Verifiable with group public key                            │
│  • Indistinguishable from single-signer signature              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Key Shares

```typescript
interface AgentKeyShare {
  // Agent identification
  agentId: string;              // UUID
  groupId: string;              // Multi-sig group UUID
  shareIndex: number;           // 1, 2, 3, ... n

  // Secret share (NEVER shared)
  secretShare: Uint8Array;      // 32 bytes

  // Public components (shared with group)
  publicShare: Uint8Array;      // 32 bytes
  verificationKey: Uint8Array;  // For VSS verification

  // Group parameters
  threshold: number;            // t (minimum signers)
  totalMembers: number;         // n (total members)
  groupPublicKey: Uint8Array;   // 32 bytes - shared Ed25519 pubkey
}
```

### 3.3 Threshold Parameters

| Configuration | Use Case |
|---------------|----------|
| **2-of-3** | Small team, any 2 can authorize |
| **3-of-5** | Medium team with redundancy |
| **4-of-7** | Large committee, higher security |
| **5-of-9** | Critical operations, maximum security |

---

## 4. Multi-Agent Architecture

### 4.1 Agent Group

```typescript
interface AgentGroup {
  groupId: string;              // UUID
  name: string;                 // "Treasury Multi-Sig"
  tenantId: string;             // Parent tenant

  // Threshold configuration
  threshold: number;            // t
  totalMembers: number;         // n

  // Member agents
  members: AgentGroupMember[];

  // Shared identity
  groupPublicKey: string;       // Derived from DKG
  blockchainAddresses: Record<string, string>;  // Per-chain addresses

  // Policies
  policies: GroupPolicy[];

  // Status
  status: 'pending_dkg' | 'active' | 'suspended';
  createdAt: string;
}

interface AgentGroupMember {
  agentId: string;
  shareIndex: number;
  publicShare: string;          // Hex
  role: 'admin' | 'signer' | 'observer';
  addedAt: string;
  addedBy: string;              // Agent who added this member
}
```

### 4.2 Group Creation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Group Creation Flow                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. INITIATE                                                    │
│     Agent A creates group proposal:                             │
│     • Name: "Treasury Multi-Sig"                                │
│     • Threshold: 2-of-3                                         │
│     • Members: [Agent A, Agent B, Agent C]                      │
│              │                                                   │
│              ▼                                                   │
│  2. ACCEPT                                                      │
│     Each member agent accepts invitation:                       │
│     • VES: GroupInvitation.Accepted                             │
│              │                                                   │
│              ▼                                                   │
│  3. DKG (Distributed Key Generation)                            │
│     Agents perform FROST DKG:                                   │
│     • Round 1: Generate & share commitments                     │
│     • Round 2: Exchange secret shares                           │
│     • Verify all shares                                         │
│     • Compute group public key                                  │
│              │                                                   │
│              ▼                                                   │
│  4. REGISTER                                                    │
│     Record group in VES:                                        │
│     • VES: AgentGroup.Created                                   │
│     • Register on-chain addresses                               │
│              │                                                   │
│              ▼                                                   │
│  5. ACTIVE                                                      │
│     Group ready for multi-sig operations                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Coordination Protocols

### 5.1 Proposal Types

```typescript
type ProposalType =
  | 'payment'           // Send funds
  | 'token_transfer'    // Transfer tokens
  | 'contract_call'     // Execute contract
  | 'policy_change'     // Modify group policy
  | 'member_add'        // Add new member
  | 'member_remove'     // Remove member
  | 'threshold_change'  // Change t-of-n
  | 'key_rotation'      // Rotate group keys
  | 'custom';           // Custom action

interface Proposal {
  proposalId: string;           // UUID
  groupId: string;              // Agent group
  type: ProposalType;
  title: string;
  description: string;

  // Proposer
  proposedBy: string;           // Agent ID
  proposedAt: string;           // RFC 3339

  // Action details
  action: ProposalAction;

  // Voting
  votes: Vote[];
  requiredApprovals: number;    // Same as threshold
  deadline: string;             // RFC 3339

  // Status
  status: 'pending' | 'approved' | 'rejected' | 'executed' | 'expired';
  executedAt?: string;
  executedBy?: string;
  executionTxHash?: string;
}

interface ProposalAction {
  // For payment
  payment?: {
    chain: string;
    recipient: string;
    amount: string;
    currency: string;
    memo?: string;
  };

  // For policy change
  policyChange?: {
    policyId: string;
    oldValue: any;
    newValue: any;
  };

  // For member operations
  memberOp?: {
    operation: 'add' | 'remove';
    agentId: string;
    role?: string;
  };

  // For custom actions
  custom?: {
    actionType: string;
    data: any;
  };
}
```

### 5.2 Voting Process

```typescript
interface Vote {
  voteId: string;               // UUID
  proposalId: string;
  voterId: string;              // Agent ID
  decision: 'approve' | 'reject' | 'abstain';
  reason?: string;
  signature: string;            // Agent signs vote
  votedAt: string;
}
```

```
┌─────────────────────────────────────────────────────────────────┐
│                    Voting Process                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Proposal: Pay $50,000 USDC to supplier                        │
│   Group: Treasury (2-of-3)                                      │
│   Deadline: 24 hours                                            │
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  Votes:                                                  │   │
│   │                                                          │   │
│   │  Agent A (Proposer):  ✓ Approve (auto)                  │   │
│   │  Agent B:             ✓ Approve    ← Threshold reached! │   │
│   │  Agent C:             ○ Pending                          │   │
│   │                                                          │   │
│   │  Status: APPROVED (2/2 required approvals)              │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   Next: Begin signing ceremony                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Proposal System

### 6.1 Proposal Lifecycle

```
┌────────┐    ┌────────┐    ┌──────────┐    ┌──────────┐
│ Draft  │───►│Pending │───►│ Approved │───►│ Executed │
└────────┘    └────────┘    └──────────┘    └──────────┘
                  │              │
                  │              │ (signing fails)
                  ▼              ▼
             ┌────────┐    ┌──────────┐
             │Rejected│    │  Failed  │
             └────────┘    └──────────┘
                  │
                  ▼
             ┌────────┐
             │Expired │
             └────────┘
```

### 6.2 VES Events for Proposals

```typescript
// Event: Proposal.Created
interface ProposalCreatedPayload {
  proposal_id: string;
  group_id: string;
  type: string;
  title: string;
  action: ProposalAction;
  deadline: string;
  required_approvals: number;
}

// Event: Proposal.VoteCast
interface VoteCastPayload {
  proposal_id: string;
  voter_id: string;
  decision: 'approve' | 'reject' | 'abstain';
  reason?: string;
  votes_for: number;
  votes_against: number;
  threshold_reached: boolean;
}

// Event: Proposal.Approved
interface ProposalApprovedPayload {
  proposal_id: string;
  approved_by: string[];        // List of approving agents
  total_votes: number;
  approval_time: string;
}

// Event: Proposal.Executed
interface ProposalExecutedPayload {
  proposal_id: string;
  executor_agents: string[];    // Agents who signed
  execution_tx?: string;        // On-chain TX hash
  result: 'success' | 'failed';
  error?: string;
}
```

---

## 7. Signing Ceremonies

### 7.1 FROST Signing Protocol

```
┌─────────────────────────────────────────────────────────────────┐
│                    FROST Signing Ceremony                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Message to sign: SHA256(transaction_bytes)                     │
│  Participants: Agent A, Agent B (2-of-3 threshold)              │
│                                                                  │
│  ═══════════════════════════════════════════════════════════   │
│  ROUND 1: Nonce Commitment                                      │
│  ═══════════════════════════════════════════════════════════   │
│                                                                  │
│  Agent A:                        Agent B:                       │
│  • Generate nonce pair (d, e)    • Generate nonce pair (d, e)   │
│  • Compute D = d·G, E = e·G      • Compute D = d·G, E = e·G     │
│  • Broadcast (D, E)              • Broadcast (D, E)             │
│           │                              │                       │
│           └──────────────┬───────────────┘                      │
│                          ▼                                       │
│                    Coordinator                                   │
│                    collects all                                  │
│                    commitments                                   │
│                          │                                       │
│  ═══════════════════════════════════════════════════════════   │
│  ROUND 2: Signature Shares                                      │
│  ═══════════════════════════════════════════════════════════   │
│                          │                                       │
│           ┌──────────────┴───────────────┐                      │
│           ▼                              ▼                       │
│  Agent A:                        Agent B:                       │
│  • Receive all commitments       • Receive all commitments      │
│  • Compute binding factor ρ      • Compute binding factor ρ     │
│  • Compute group commitment R    • Compute group commitment R   │
│  • Compute challenge c           • Compute challenge c          │
│  • Compute signature share z_a   • Compute signature share z_b  │
│           │                              │                       │
│           └──────────────┬───────────────┘                      │
│                          ▼                                       │
│                    Combine shares:                              │
│                    z = z_a + z_b                                │
│                          │                                       │
│                          ▼                                       │
│              Final Signature: (R, z)                            │
│              (Standard Ed25519 format)                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 Signing Session State

```typescript
interface SigningSession {
  sessionId: string;            // UUID
  proposalId: string;           // What we're signing
  groupId: string;

  // Message
  messageHash: Uint8Array;      // SHA-256 of message
  messageType: 'transaction' | 'ves_event' | 'custom';

  // Participants (threshold subset)
  participants: SigningParticipant[];

  // Round 1 data
  commitments: Map<string, NonceCommitment>;  // agentId -> commitment
  round1Complete: boolean;

  // Round 2 data
  signatureShares: Map<string, Uint8Array>;   // agentId -> share
  round2Complete: boolean;

  // Final signature
  finalSignature?: Uint8Array;  // 64 bytes

  // Status
  status: 'collecting_commitments' | 'collecting_shares' | 'complete' | 'failed';
  startedAt: string;
  completedAt?: string;
  error?: string;
}

interface SigningParticipant {
  agentId: string;
  shareIndex: number;
  publicShare: Uint8Array;
  status: 'invited' | 'committed' | 'signed' | 'failed';
}

interface NonceCommitment {
  hidingNonce: Uint8Array;      // D = d·G
  bindingNonce: Uint8Array;     // E = e·G
  timestamp: string;
}
```

### 7.3 VES Events for Signing

```typescript
// Event: SigningSession.Started
interface SigningSessionStartedPayload {
  session_id: string;
  proposal_id: string;
  group_id: string;
  participants: string[];       // Agent IDs
  message_hash: string;         // Hex
  threshold: number;
}

// Event: SigningSession.CommitmentReceived
interface CommitmentReceivedPayload {
  session_id: string;
  agent_id: string;
  commitment_hash: string;      // Hash of (D, E)
  commitments_received: number;
  commitments_required: number;
}

// Event: SigningSession.ShareReceived
interface ShareReceivedPayload {
  session_id: string;
  agent_id: string;
  share_hash: string;           // Hash of share (for audit)
  shares_received: number;
  shares_required: number;
}

// Event: SigningSession.Completed
interface SigningSessionCompletedPayload {
  session_id: string;
  proposal_id: string;
  signature: string;            // Final signature hex
  signers: string[];            // Agents who participated
  duration_ms: number;
}
```

---

## 8. Agent Communication

### 8.1 Communication Channels

```
┌─────────────────────────────────────────────────────────────────┐
│                Agent Communication Channels                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  VES (Primary - Asynchronous)                            │   │
│  │                                                          │   │
│  │  • Proposals, votes, signatures                          │   │
│  │  • Permanent audit trail                                 │   │
│  │  • Eventually consistent                                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Direct P2P (Secondary - Synchronous)                    │   │
│  │                                                          │   │
│  │  • DKG protocol messages                                 │   │
│  │  • Signing ceremony coordination                         │   │
│  │  • Low-latency operations                                │   │
│  │  • Encrypted with agent keys                             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Encrypted Relay (Fallback)                              │   │
│  │                                                          │   │
│  │  • When direct P2P not available                         │   │
│  │  • End-to-end encrypted via VES                          │   │
│  │  • Higher latency but reliable                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Message Types

```typescript
type MultiAgentMessage =
  | DkgRound1Message
  | DkgRound2Message
  | SigningCommitmentMessage
  | SigningShareMessage
  | ProposalNotification
  | VoteNotification;

interface DkgRound1Message {
  type: 'dkg_round1';
  groupId: string;
  fromAgent: string;
  commitment: Uint8Array;       // Polynomial commitment
  proofOfKnowledge: Uint8Array;
  timestamp: string;
}

interface DkgRound2Message {
  type: 'dkg_round2';
  groupId: string;
  fromAgent: string;
  toAgent: string;              // Recipient-specific
  encryptedShare: Uint8Array;   // Encrypted to recipient
  timestamp: string;
}

interface SigningCommitmentMessage {
  type: 'signing_commitment';
  sessionId: string;
  fromAgent: string;
  hidingNonce: Uint8Array;
  bindingNonce: Uint8Array;
  timestamp: string;
  signature: Uint8Array;        // Signed by sender
}

interface SigningShareMessage {
  type: 'signing_share';
  sessionId: string;
  fromAgent: string;
  signatureShare: Uint8Array;
  timestamp: string;
  signature: Uint8Array;
}
```

---

## 9. Security Model

### 9.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Compromised agent | Threshold requires t agents; single compromise insufficient |
| Malicious coordinator | Agents verify all computations; coordinator cannot forge |
| Network attacks | Messages signed; replay protection via nonces |
| Key extraction | Shares stored in secure enclaves where possible |
| Collusion below threshold | t-1 colluding agents cannot sign |

### 9.2 Security Properties

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Properties                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  UNFORGEABILITY                                                 │
│  ─────────────                                                  │
│  No adversary controlling < t agents can forge a signature      │
│                                                                  │
│  ROBUSTNESS                                                     │
│  ──────────                                                     │
│  Malicious agents cannot prevent honest agents from signing     │
│  (with identifiable abort)                                      │
│                                                                  │
│  PRIVACY                                                        │
│  ───────                                                        │
│  Individual shares reveal nothing about other shares            │
│  or the group secret key                                        │
│                                                                  │
│  NON-REPUDIATION                                                │
│  ──────────────                                                 │
│  Signing participation recorded in VES;                         │
│  agents cannot deny participation                               │
│                                                                  │
│  FORWARD SECRECY                                                │
│  ──────────────                                                 │
│  Compromise of current shares doesn't affect past signatures    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 9.3 Key Rotation

```typescript
interface KeyRotationCeremony {
  rotationId: string;
  groupId: string;

  // Trigger
  reason: 'scheduled' | 'member_change' | 'suspected_compromise';

  // New parameters (optional changes)
  newThreshold?: number;
  newMembers?: string[];
  removedMembers?: string[];

  // DKG state
  dkgStatus: 'pending' | 'round1' | 'round2' | 'complete' | 'failed';

  // Old key handling
  oldGroupPublicKey: string;
  newGroupPublicKey?: string;

  // Fund migration
  migrationRequired: boolean;
  migrationTxHash?: string;

  // Timing
  initiatedAt: string;
  completedAt?: string;
}
```

---

## 10. Implementation

### 10.1 FROST Implementation (TypeScript)

```typescript
import { sha512 } from '@noble/hashes/sha512';
import * as ed from '@noble/ed25519';

// Configure ed25519 to use sha512
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

interface FrostKeyShare {
  index: number;
  secretShare: bigint;
  publicShare: Uint8Array;
  groupPublicKey: Uint8Array;
}

interface FrostNonce {
  hidingNonce: bigint;
  bindingNonce: bigint;
  hidingCommitment: Uint8Array;
  bindingCommitment: Uint8Array;
}

interface FrostSignatureShare {
  index: number;
  share: bigint;
}

class FrostSigner {
  private keyShare: FrostKeyShare;
  private nonces: Map<string, FrostNonce> = new Map();

  constructor(keyShare: FrostKeyShare) {
    this.keyShare = keyShare;
  }

  // Round 1: Generate and return nonce commitments
  generateNonceCommitment(sessionId: string): {
    hidingCommitment: Uint8Array;
    bindingCommitment: Uint8Array;
  } {
    // Generate random nonces
    const hidingNonce = ed.utils.randomPrivateKey();
    const bindingNonce = ed.utils.randomPrivateKey();

    const hidingNonceBigInt = bytesToBigInt(hidingNonce);
    const bindingNonceBigInt = bytesToBigInt(bindingNonce);

    // Compute commitments (public points)
    const hidingCommitment = ed.getPublicKey(hidingNonce);
    const bindingCommitment = ed.getPublicKey(bindingNonce);

    // Store for later use
    this.nonces.set(sessionId, {
      hidingNonce: hidingNonceBigInt,
      bindingNonce: bindingNonceBigInt,
      hidingCommitment,
      bindingCommitment,
    });

    return { hidingCommitment, bindingCommitment };
  }

  // Round 2: Compute signature share
  computeSignatureShare(
    sessionId: string,
    message: Uint8Array,
    allCommitments: Map<number, { hiding: Uint8Array; binding: Uint8Array }>,
    participantIndices: number[]
  ): FrostSignatureShare {
    const nonce = this.nonces.get(sessionId);
    if (!nonce) throw new Error('Nonce not found for session');

    // Compute binding factors for each participant
    const bindingFactors = this.computeBindingFactors(
      message,
      allCommitments,
      participantIndices
    );

    // Compute group commitment R
    const groupCommitment = this.computeGroupCommitment(
      allCommitments,
      bindingFactors,
      participantIndices
    );

    // Compute challenge c = H(R || Y || m)
    const challenge = this.computeChallenge(
      groupCommitment,
      this.keyShare.groupPublicKey,
      message
    );

    // Compute Lagrange coefficient for this participant
    const lambda = this.computeLagrangeCoefficient(
      this.keyShare.index,
      participantIndices
    );

    // Compute signature share
    // z_i = d_i + e_i * rho_i + lambda_i * s_i * c
    const myBindingFactor = bindingFactors.get(this.keyShare.index)!;

    const share = mod(
      nonce.hidingNonce +
      nonce.bindingNonce * myBindingFactor +
      lambda * this.keyShare.secretShare * challenge
    );

    // Clear nonce (single use)
    this.nonces.delete(sessionId);

    return {
      index: this.keyShare.index,
      share,
    };
  }

  private computeBindingFactors(
    message: Uint8Array,
    allCommitments: Map<number, { hiding: Uint8Array; binding: Uint8Array }>,
    participantIndices: number[]
  ): Map<number, bigint> {
    const factors = new Map<number, bigint>();

    for (const index of participantIndices) {
      const commitment = allCommitments.get(index)!;
      const input = concat(
        indexToBytes(index),
        message,
        commitment.hiding,
        commitment.binding
      );
      const hash = sha512(input);
      factors.set(index, bytesToBigInt(hash.slice(0, 32)) % ed.CURVE.n);
    }

    return factors;
  }

  private computeGroupCommitment(
    allCommitments: Map<number, { hiding: Uint8Array; binding: Uint8Array }>,
    bindingFactors: Map<number, bigint>,
    participantIndices: number[]
  ): Uint8Array {
    let result = ed.Point.ZERO;

    for (const index of participantIndices) {
      const commitment = allCommitments.get(index)!;
      const rho = bindingFactors.get(index)!;

      const D = ed.Point.fromHex(commitment.hiding);
      const E = ed.Point.fromHex(commitment.binding);

      // R_i = D_i + rho_i * E_i
      const Ri = D.add(E.multiply(rho));
      result = result.add(Ri);
    }

    return result.toRawBytes();
  }

  private computeChallenge(
    groupCommitment: Uint8Array,
    groupPublicKey: Uint8Array,
    message: Uint8Array
  ): bigint {
    const input = concat(groupCommitment, groupPublicKey, message);
    const hash = sha512(input);
    return bytesToBigInt(hash) % ed.CURVE.n;
  }

  private computeLagrangeCoefficient(
    myIndex: number,
    allIndices: number[]
  ): bigint {
    let numerator = 1n;
    let denominator = 1n;

    for (const j of allIndices) {
      if (j === myIndex) continue;
      numerator = mod(numerator * BigInt(-j));
      denominator = mod(denominator * BigInt(myIndex - j));
    }

    return mod(numerator * modInverse(denominator));
  }
}

// Combine signature shares into final signature
function combineSignatureShares(
  groupCommitment: Uint8Array,
  shares: FrostSignatureShare[]
): Uint8Array {
  // z = sum of all z_i
  let z = 0n;
  for (const share of shares) {
    z = mod(z + share.share);
  }

  // Signature is (R, z)
  const signature = new Uint8Array(64);
  signature.set(groupCommitment, 0);
  signature.set(bigIntToBytes(z, 32), 32);

  return signature;
}

// Utility functions
function mod(n: bigint): bigint {
  return ((n % ed.CURVE.n) + ed.CURVE.n) % ed.CURVE.n;
}

function modInverse(n: bigint): bigint {
  return ed.utils.mod(n, ed.CURVE.n);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function bigIntToBytes(n: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function indexToBytes(index: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, index, false);
  return bytes;
}
```

### 10.2 Multi-Sig Coordinator

```typescript
class MultiSigCoordinator {
  private vesClient: VesClient;
  private groups: Map<string, AgentGroup> = new Map();
  private activeSessions: Map<string, SigningSession> = new Map();

  constructor(vesClient: VesClient) {
    this.vesClient = vesClient;
  }

  // Create a new proposal
  async createProposal(
    groupId: string,
    proposerId: string,
    type: ProposalType,
    action: ProposalAction,
    title: string,
    description: string,
    deadlineHours: number = 24
  ): Promise<Proposal> {
    const group = this.groups.get(groupId);
    if (!group) throw new Error('Group not found');

    const proposalId = crypto.randomUUID();
    const deadline = new Date(Date.now() + deadlineHours * 60 * 60 * 1000);

    const proposal: Proposal = {
      proposalId,
      groupId,
      type,
      title,
      description,
      proposedBy: proposerId,
      proposedAt: new Date().toISOString(),
      action,
      votes: [{
        voteId: crypto.randomUUID(),
        proposalId,
        voterId: proposerId,
        decision: 'approve',  // Proposer auto-approves
        votedAt: new Date().toISOString(),
        signature: '',  // Filled by agent
      }],
      requiredApprovals: group.threshold,
      deadline: deadline.toISOString(),
      status: 'pending',
    };

    // Record in VES
    await this.vesClient.submitEvent({
      entityType: 'Proposal',
      entityId: proposalId,
      eventType: 'Created',
      payload: {
        proposal_id: proposalId,
        group_id: groupId,
        type,
        title,
        action,
        proposer: proposerId,
        deadline: proposal.deadline,
        required_approvals: group.threshold,
      },
    });

    return proposal;
  }

  // Cast a vote on a proposal
  async castVote(
    proposalId: string,
    voterId: string,
    decision: 'approve' | 'reject' | 'abstain',
    reason?: string,
    signature?: string
  ): Promise<void> {
    const proposal = await this.getProposal(proposalId);
    if (!proposal) throw new Error('Proposal not found');

    if (proposal.status !== 'pending') {
      throw new Error(`Cannot vote on ${proposal.status} proposal`);
    }

    // Check deadline
    if (new Date() > new Date(proposal.deadline)) {
      throw new Error('Proposal deadline passed');
    }

    // Check if already voted
    if (proposal.votes.some(v => v.voterId === voterId)) {
      throw new Error('Already voted');
    }

    const vote: Vote = {
      voteId: crypto.randomUUID(),
      proposalId,
      voterId,
      decision,
      reason,
      signature: signature || '',
      votedAt: new Date().toISOString(),
    };

    proposal.votes.push(vote);

    // Check if threshold reached
    const approvals = proposal.votes.filter(v => v.decision === 'approve').length;
    const thresholdReached = approvals >= proposal.requiredApprovals;

    // Record vote in VES
    await this.vesClient.submitEvent({
      entityType: 'Proposal',
      entityId: proposalId,
      eventType: 'VoteCast',
      payload: {
        proposal_id: proposalId,
        voter: voterId,
        decision,
        reason,
        votes_for: approvals,
        votes_against: proposal.votes.filter(v => v.decision === 'reject').length,
        threshold_reached: thresholdReached,
      },
    });

    // If threshold reached, mark as approved
    if (thresholdReached) {
      proposal.status = 'approved';

      await this.vesClient.submitEvent({
        entityType: 'Proposal',
        entityId: proposalId,
        eventType: 'Approved',
        payload: {
          proposal_id: proposalId,
          approved_by: proposal.votes
            .filter(v => v.decision === 'approve')
            .map(v => v.voterId),
          total_votes: proposal.votes.length,
        },
      });
    }
  }

  // Start a signing session for an approved proposal
  async startSigningSession(
    proposalId: string,
    participants: string[]
  ): Promise<SigningSession> {
    const proposal = await this.getProposal(proposalId);
    if (!proposal) throw new Error('Proposal not found');

    if (proposal.status !== 'approved') {
      throw new Error('Proposal not approved');
    }

    const group = this.groups.get(proposal.groupId);
    if (!group) throw new Error('Group not found');

    if (participants.length < group.threshold) {
      throw new Error(`Need at least ${group.threshold} participants`);
    }

    const sessionId = crypto.randomUUID();
    const messageHash = await this.computeMessageHash(proposal);

    const session: SigningSession = {
      sessionId,
      proposalId,
      groupId: proposal.groupId,
      messageHash,
      messageType: 'transaction',
      participants: participants.map((agentId, i) => ({
        agentId,
        shareIndex: this.getShareIndex(group, agentId),
        publicShare: new Uint8Array(32),
        status: 'invited',
      })),
      commitments: new Map(),
      round1Complete: false,
      signatureShares: new Map(),
      round2Complete: false,
      status: 'collecting_commitments',
      startedAt: new Date().toISOString(),
    };

    this.activeSessions.set(sessionId, session);

    // Record in VES
    await this.vesClient.submitEvent({
      entityType: 'SigningSession',
      entityId: sessionId,
      eventType: 'Started',
      payload: {
        session_id: sessionId,
        proposal_id: proposalId,
        group_id: proposal.groupId,
        participants,
        message_hash: Buffer.from(messageHash).toString('hex'),
        threshold: group.threshold,
      },
    });

    return session;
  }

  // Process a nonce commitment from a participant
  async receiveCommitment(
    sessionId: string,
    agentId: string,
    hidingCommitment: Uint8Array,
    bindingCommitment: Uint8Array
  ): Promise<void> {
    const session = this.activeSessions.get(sessionId);
    if (!session) throw new Error('Session not found');

    if (session.status !== 'collecting_commitments') {
      throw new Error('Not accepting commitments');
    }

    // Store commitment
    session.commitments.set(agentId, {
      hidingNonce: hidingCommitment,
      bindingNonce: bindingCommitment,
      timestamp: new Date().toISOString(),
    });

    // Update participant status
    const participant = session.participants.find(p => p.agentId === agentId);
    if (participant) {
      participant.status = 'committed';
    }

    // Record in VES
    await this.vesClient.submitEvent({
      entityType: 'SigningSession',
      entityId: sessionId,
      eventType: 'CommitmentReceived',
      payload: {
        session_id: sessionId,
        agent_id: agentId,
        commitments_received: session.commitments.size,
        commitments_required: session.participants.length,
      },
    });

    // Check if all commitments received
    if (session.commitments.size >= session.participants.length) {
      session.round1Complete = true;
      session.status = 'collecting_shares';
    }
  }

  // Process a signature share from a participant
  async receiveSignatureShare(
    sessionId: string,
    agentId: string,
    signatureShare: Uint8Array
  ): Promise<Uint8Array | null> {
    const session = this.activeSessions.get(sessionId);
    if (!session) throw new Error('Session not found');

    if (session.status !== 'collecting_shares') {
      throw new Error('Not accepting shares');
    }

    // Store share
    session.signatureShares.set(agentId, signatureShare);

    // Update participant status
    const participant = session.participants.find(p => p.agentId === agentId);
    if (participant) {
      participant.status = 'signed';
    }

    const group = this.groups.get(session.groupId);
    if (!group) throw new Error('Group not found');

    // Record in VES
    await this.vesClient.submitEvent({
      entityType: 'SigningSession',
      entityId: sessionId,
      eventType: 'ShareReceived',
      payload: {
        session_id: sessionId,
        agent_id: agentId,
        shares_received: session.signatureShares.size,
        shares_required: group.threshold,
      },
    });

    // Check if we have enough shares
    if (session.signatureShares.size >= group.threshold) {
      // Combine shares into final signature
      const finalSignature = await this.combineShares(session);
      session.finalSignature = finalSignature;
      session.round2Complete = true;
      session.status = 'complete';
      session.completedAt = new Date().toISOString();

      // Record completion in VES
      await this.vesClient.submitEvent({
        entityType: 'SigningSession',
        entityId: sessionId,
        eventType: 'Completed',
        payload: {
          session_id: sessionId,
          proposal_id: session.proposalId,
          signature: Buffer.from(finalSignature).toString('hex'),
          signers: Array.from(session.signatureShares.keys()),
          duration_ms: Date.now() - new Date(session.startedAt).getTime(),
        },
      });

      return finalSignature;
    }

    return null;
  }

  private async computeMessageHash(proposal: Proposal): Promise<Uint8Array> {
    // Hash the proposal action
    const actionJson = JSON.stringify(proposal.action);
    const encoder = new TextEncoder();
    const data = encoder.encode(actionJson);
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  }

  private getShareIndex(group: AgentGroup, agentId: string): number {
    const member = group.members.find(m => m.agentId === agentId);
    return member?.shareIndex || 0;
  }

  private async combineShares(session: SigningSession): Promise<Uint8Array> {
    // Compute group commitment from all individual commitments
    const groupCommitment = this.computeGroupCommitment(session);

    // Combine signature shares
    const shares: FrostSignatureShare[] = [];
    for (const [agentId, shareBytes] of session.signatureShares) {
      const participant = session.participants.find(p => p.agentId === agentId);
      if (participant) {
        shares.push({
          index: participant.shareIndex,
          share: bytesToBigInt(shareBytes),
        });
      }
    }

    return combineSignatureShares(groupCommitment, shares);
  }

  private computeGroupCommitment(session: SigningSession): Uint8Array {
    // Implementation of group commitment computation
    // (simplified - actual implementation needs binding factors)
    const commitments = Array.from(session.commitments.values());
    // ... compute R = sum of all D_i + rho_i * E_i
    return new Uint8Array(32);  // Placeholder
  }

  private async getProposal(proposalId: string): Promise<Proposal | null> {
    // Retrieve proposal from storage
    return null;  // Placeholder
  }
}
```

---

## 11. Use Cases

### 11.1 Treasury Management

```
┌─────────────────────────────────────────────────────────────────┐
│                    Treasury Multi-Sig                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Organization Treasury: 3-of-5 Multi-Sig                       │
│                                                                  │
│   Agents:                                                       │
│   • Finance Agent (CFO oversight)                               │
│   • Operations Agent (COO oversight)                            │
│   • Compliance Agent (Legal oversight)                          │
│   • CEO Agent (Executive oversight)                             │
│   • Board Agent (Board oversight)                               │
│                                                                  │
│   Payment Flow:                                                 │
│   1. Finance Agent proposes payment                             │
│   2. Operations Agent reviews & approves                        │
│   3. Compliance Agent verifies & approves                       │
│   4. 3 signatures combined → Payment executed                   │
│                                                                  │
│   Benefits:                                                     │
│   • No single person can move funds                             │
│   • All approvals recorded in VES                               │
│   • Automated compliance checking                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 11.2 Supply Chain Payments

```
┌─────────────────────────────────────────────────────────────────┐
│              Multi-Party Supply Chain Payment                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Buyer ←──→ Logistics ←──→ Supplier                           │
│     │           │              │                                │
│     ▼           ▼              ▼                                │
│  Agent A    Agent B        Agent C                              │
│                                                                  │
│   2-of-3 Multi-Sig Escrow:                                      │
│                                                                  │
│   1. Buyer Agent locks payment in escrow                        │
│   2. Supplier ships goods                                       │
│   3. Logistics Agent confirms delivery                          │
│   4. Buyer Agent confirms receipt                               │
│   5. Any 2 agents can release payment                          │
│                                                                  │
│   Dispute Resolution:                                           │
│   • If goods damaged: Logistics + Buyer → Refund               │
│   • If goods fine: Logistics + Supplier → Release              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 11.3 Autonomous Agent Fleet

```
┌─────────────────────────────────────────────────────────────────┐
│                Autonomous Agent Fleet Control                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Fleet of AI Agents with shared wallet:                        │
│                                                                  │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐          │
│   │ Agent 1 │  │ Agent 2 │  │ Agent 3 │  │ Agent 4 │          │
│   │ Region A│  │ Region B│  │ Region C│  │ Region D│          │
│   └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘          │
│        │           │           │           │                    │
│        └───────────┴───────────┴───────────┘                   │
│                          │                                      │
│                          ▼                                      │
│                  ┌───────────────┐                             │
│                  │ 2-of-4 Wallet │                             │
│                  │               │                             │
│                  │ Any 2 agents  │                             │
│                  │ can authorize │                             │
│                  │ payments      │                             │
│                  └───────────────┘                             │
│                                                                  │
│   Use case: Distributed purchasing agents that can             │
│   make payments when 2 agree on a vendor/price                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 12. Code Examples

### 12.1 Complete Multi-Sig Payment Flow

```typescript
import { MultiSigCoordinator, FrostSigner } from './multi-sig';

async function executeMultiSigPayment() {
  // Setup
  const coordinator = new MultiSigCoordinator(vesClient);

  // Agents load their key shares
  const agentA = new FrostSigner(keyShareA);
  const agentB = new FrostSigner(keyShareB);
  const agentC = new FrostSigner(keyShareC);

  // 1. Create proposal
  console.log('1. Creating payment proposal...');
  const proposal = await coordinator.createProposal(
    'treasury-group-123',
    'agent-a-id',
    'payment',
    {
      payment: {
        chain: 'solana',
        recipient: 'SupplierAddress123...',
        amount: '50000000000',  // 50,000 USDC
        currency: 'USDC',
        memo: 'Q4 Supplier Payment',
      },
    },
    'Q4 Supplier Payment - $50,000 USDC',
    'Quarterly payment to main supplier for inventory',
    24  // 24 hour deadline
  );

  console.log(`   Proposal ID: ${proposal.proposalId}`);

  // 2. Agents vote
  console.log('\n2. Agents voting...');

  // Agent B votes
  await coordinator.castVote(
    proposal.proposalId,
    'agent-b-id',
    'approve',
    'Verified invoice matches PO'
  );
  console.log('   Agent B: Approved');

  // Agent C votes (this reaches threshold for 2-of-3)
  await coordinator.castVote(
    proposal.proposalId,
    'agent-c-id',
    'approve',
    'Compliance check passed'
  );
  console.log('   Agent C: Approved');
  console.log('   ✓ Threshold reached!');

  // 3. Start signing session
  console.log('\n3. Starting signing session...');
  const session = await coordinator.startSigningSession(
    proposal.proposalId,
    ['agent-a-id', 'agent-b-id']  // Only need 2 for threshold
  );

  console.log(`   Session ID: ${session.sessionId}`);

  // 4. Round 1: Collect commitments
  console.log('\n4. Round 1: Collecting nonce commitments...');

  const commitmentA = agentA.generateNonceCommitment(session.sessionId);
  await coordinator.receiveCommitment(
    session.sessionId,
    'agent-a-id',
    commitmentA.hidingCommitment,
    commitmentA.bindingCommitment
  );
  console.log('   Agent A: Commitment received');

  const commitmentB = agentB.generateNonceCommitment(session.sessionId);
  await coordinator.receiveCommitment(
    session.sessionId,
    'agent-b-id',
    commitmentB.hidingCommitment,
    commitmentB.bindingCommitment
  );
  console.log('   Agent B: Commitment received');
  console.log('   ✓ Round 1 complete');

  // 5. Round 2: Collect signature shares
  console.log('\n5. Round 2: Collecting signature shares...');

  const allCommitments = new Map([
    [1, { hiding: commitmentA.hidingCommitment, binding: commitmentA.bindingCommitment }],
    [2, { hiding: commitmentB.hidingCommitment, binding: commitmentB.bindingCommitment }],
  ]);

  const shareA = agentA.computeSignatureShare(
    session.sessionId,
    session.messageHash,
    allCommitments,
    [1, 2]
  );
  await coordinator.receiveSignatureShare(
    session.sessionId,
    'agent-a-id',
    bigIntToBytes(shareA.share, 32)
  );
  console.log('   Agent A: Share received');

  const shareB = agentB.computeSignatureShare(
    session.sessionId,
    session.messageHash,
    allCommitments,
    [1, 2]
  );
  const finalSignature = await coordinator.receiveSignatureShare(
    session.sessionId,
    'agent-b-id',
    bigIntToBytes(shareB.share, 32)
  );
  console.log('   Agent B: Share received');
  console.log('   ✓ Round 2 complete');

  // 6. Execute transaction with threshold signature
  console.log('\n6. Executing transaction...');
  console.log(`   Signature: 0x${Buffer.from(finalSignature!).toString('hex').slice(0, 32)}...`);

  // Use signature to sign Solana transaction
  // const tx = await signAndSubmitTransaction(finalSignature, proposal.action.payment);

  console.log('\n✓ Multi-sig payment complete!');
}
```

---

## 13. Implementation Checklist

### 13.1 Core Components

- [ ] FROST key generation (DKG)
- [ ] FROST signing protocol
- [ ] Key share management
- [ ] Group management

### 13.2 Coordination

- [ ] Proposal creation & voting
- [ ] Signing session management
- [ ] Agent communication
- [ ] VES event recording

### 13.3 Security

- [ ] Share encryption at rest
- [ ] Secure key share backup
- [ ] Malicious signer detection
- [ ] Key rotation procedures

### 13.4 Integration

- [ ] Solana multi-sig wallet
- [ ] VES proof integration
- [ ] Policy enforcement
- [ ] Monitoring & alerts

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-22 | Initial specification |

---

*This specification extends VES-SIG-1 for multi-agent coordination. See [VES_SIG_1_SPECIFICATION.md](./VES_SIG_1_SPECIFICATION.md) for single-agent signatures.*
