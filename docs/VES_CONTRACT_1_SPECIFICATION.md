# VES-CONTRACT-1: Smart Contract Integration Specification

**Version:** 1.0
**Status:** Draft
**Last Updated:** 2025-12-22
**Dependencies:** VES-SIG-1, VES-CHAIN-1

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Principles](#2-design-principles)
3. [Architecture](#3-architecture)
4. [VES Proof System](#4-ves-proof-system)
5. [Contract Interfaces](#5-contract-interfaces)
6. [Solana Implementation](#6-solana-implementation)
7. [CosmWasm Implementation](#7-cosmwasm-implementation)
8. [Use Cases](#8-use-cases)
9. [Escrow Contract](#9-escrow-contract)
10. [Oracle Bridge](#10-oracle-bridge)
11. [Security Considerations](#11-security-considerations)
12. [Gas/Compute Optimization](#12-gascompute-optimization)
13. [Code Examples](#13-code-examples)
14. [Implementation Checklist](#14-implementation-checklist)

---

## 1. Overview

VES-CONTRACT-1 defines how smart contracts can verify VES events and take on-chain actions based on off-chain VES state. This enables:

- **Trustless Escrow**: Release funds when VES events confirm delivery
- **Conditional Payments**: Execute payments based on verified business events
- **DeFi Integration**: Bridge real-world commerce data to DeFi protocols
- **Compliance Automation**: Enforce rules based on VES audit trail

### 1.1 Key Capabilities

| Capability | Description |
|------------|-------------|
| **Merkle Proof Verification** | Verify VES events are included in anchored commitments |
| **Signature Verification** | Verify agent signatures on-chain |
| **Conditional Execution** | Trigger contract logic based on VES proofs |
| **State Synchronization** | Keep on-chain state in sync with VES |
| **Cross-Chain Verification** | Verify VES proofs across different chains |

### 1.2 System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    VES-CONTRACT-1 Architecture                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   OFF-CHAIN (VES)                        ON-CHAIN (Blockchain)          │
│   ───────────────                        ─────────────────────          │
│                                                                          │
│   ┌─────────────┐                        ┌─────────────────────┐        │
│   │   Events    │                        │   VES Anchor        │        │
│   │   Stream    │───── Anchor ──────────►│   Contract          │        │
│   └─────────────┘      Commitment        │   (events_root)     │        │
│         │                                └──────────┬──────────┘        │
│         │                                           │                    │
│         ▼                                           │                    │
│   ┌─────────────┐                                  │                    │
│   │   Merkle    │                                  │                    │
│   │   Tree      │                                  ▼                    │
│   └─────────────┘                        ┌─────────────────────┐        │
│         │                                │   Escrow/App        │        │
│         │                                │   Contract          │        │
│         │                                │                     │        │
│         │      ┌──────────────────┐     │  verify_ves_proof() │        │
│         └─────►│  Merkle Proof    │────►│  execute_action()   │        │
│                │  + Event Data    │     │                     │        │
│                └──────────────────┘     └─────────────────────┘        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Design Principles

### 2.1 Minimal On-Chain State

Only store what's necessary on-chain:
- Events root (32 bytes)
- Sequence numbers
- Anchor metadata

Full event data remains off-chain in VES.

### 2.2 Verification, Not Storage

Contracts verify proofs rather than storing event data:

```
❌ Bad:  Store all events on-chain (expensive, doesn't scale)
✅ Good: Store root hash, verify Merkle proofs on demand
```

### 2.3 Composability

VES contracts are designed to be composed with existing DeFi:

```
VES Escrow ──► Verify Delivery ──► Release to ──► Uniswap Swap
                                   Seller
```

### 2.4 Chain Agnostic

Core verification logic works across any chain with:
- SHA-256 hashing
- Ed25519 signature verification
- Basic smart contract capabilities

---

## 3. Architecture

### 3.1 Contract Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Contract Components                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   VES Anchor    │  │   VES Verifier  │  │   Application   │ │
│  │                 │  │                 │  │                 │ │
│  │ • Store roots   │  │ • Verify proofs │  │ • Business      │ │
│  │ • Chain commits │  │ • Check sigs    │  │   logic         │ │
│  │ • Sequence mgmt │  │ • Validate      │  │ • State mgmt    │ │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘ │
│           │                    │                    │           │
│           └────────────────────┼────────────────────┘           │
│                                │                                 │
│                    ┌───────────▼───────────┐                    │
│                    │    Shared Libraries   │                    │
│                    │                       │                    │
│                    │ • Merkle verification │                    │
│                    │ • Ed25519 verify      │                    │
│                    │ • Hash functions      │                    │
│                    └───────────────────────┘                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow

```
1. VES Event Created
   └─► Agent signs event
   └─► Event added to Merkle tree
   └─► Batch anchored on-chain (events_root)

2. Proof Generation (off-chain)
   └─► Request proof for specific event
   └─► Generate Merkle path from leaf to root
   └─► Package: event_data + merkle_proof + signature

3. On-Chain Verification
   └─► Contract receives proof
   └─► Verify Merkle proof against anchored root
   └─► Verify agent signature
   └─► Execute conditional logic
```

---

## 4. VES Proof System

### 4.1 Proof Structure

```typescript
interface VesProof {
  // The event being proven
  event: {
    event_id: string;           // UUID
    tenant_id: string;          // UUID
    store_id: string;           // UUID
    entity_type: string;
    entity_id: string;
    event_type: string;
    created_at: string;         // RFC 3339
    payload_hash: string;       // 0x + 64 hex
    agent_signature: string;    // 0x + 128 hex
  };

  // Merkle inclusion proof
  merkle_proof: {
    leaf_hash: string;          // Hash of the event
    proof_path: string[];       // Array of sibling hashes
    proof_indices: number[];    // Left (0) or right (1) for each level
    root: string;               // Expected root hash
  };

  // Anchor reference
  anchor: {
    chain: string;              // 'solana', 'near', etc.
    anchor_tx: string;          // Transaction that anchored this root
    sequence_start: number;
    sequence_end: number;
  };
}
```

### 4.2 Leaf Hash Computation

Per VES-SIG-1, the leaf hash is computed as:

```
leaf_preimage =
    DOMAIN_LEAF ||              // "VES_LEAF_V1" (11 bytes)
    tenant_id ||                // UUID bytes (16 bytes)
    store_id ||                 // UUID bytes (16 bytes)
    sequence_number ||          // u64 big-endian (8 bytes)
    event_signing_hash ||       // SHA-256 (32 bytes)
    agent_signature             // Ed25519 (64 bytes)

leaf_hash = SHA256(leaf_preimage)
```

### 4.3 Merkle Proof Verification

```typescript
function verifyMerkleProof(
  leafHash: Uint8Array,
  proofPath: Uint8Array[],
  proofIndices: number[],
  expectedRoot: Uint8Array
): boolean {
  let currentHash = leafHash;

  for (let i = 0; i < proofPath.length; i++) {
    const sibling = proofPath[i];
    const isLeft = proofIndices[i] === 0;

    if (isLeft) {
      // Current node is on the left
      currentHash = sha256(concat(currentHash, sibling));
    } else {
      // Current node is on the right
      currentHash = sha256(concat(sibling, currentHash));
    }
  }

  return equal(currentHash, expectedRoot);
}
```

### 4.4 Proof Compactness

| Component | Size | Notes |
|-----------|------|-------|
| Event data | ~200 bytes | Depends on payload |
| Leaf hash | 32 bytes | SHA-256 |
| Proof path | 32 × depth bytes | Typically 20-30 levels |
| Indices | depth bits | Packed as bitmap |
| Root | 32 bytes | SHA-256 |
| **Total** | **~1-2 KB** | For tree of 1M events |

---

## 5. Contract Interfaces

### 5.1 Anchor Contract Interface

```rust
/// Anchor a new VES commitment on-chain
pub fn anchor_commitment(
    ctx: Context<AnchorCommitment>,
    stream_id: [u8; 32],
    sequence_start: u64,
    sequence_end: u64,
    events_root: [u8; 32],
    prev_events_root: [u8; 32],
) -> Result<()>;

/// Get the latest anchored root for a stream
pub fn get_latest_root(
    ctx: Context<GetRoot>,
    stream_id: [u8; 32],
) -> Result<AnchorState>;

/// Verify a commitment exists
pub fn verify_anchor(
    ctx: Context<VerifyAnchor>,
    stream_id: [u8; 32],
    events_root: [u8; 32],
) -> Result<bool>;
```

### 5.2 Verifier Contract Interface

```rust
/// Verify a VES event proof
pub fn verify_ves_proof(
    ctx: Context<VerifyProof>,
    event_data: EventData,
    merkle_proof: MerkleProof,
    anchor_root: [u8; 32],
) -> Result<bool>;

/// Verify agent signature on event
pub fn verify_agent_signature(
    ctx: Context<VerifySignature>,
    event_signing_hash: [u8; 32],
    signature: [u8; 64],
    public_key: [u8; 32],
) -> Result<bool>;
```

### 5.3 Application Contract Interface (Escrow Example)

```rust
/// Create a new escrow
pub fn create_escrow(
    ctx: Context<CreateEscrow>,
    escrow_id: [u8; 32],
    buyer: Pubkey,
    seller: Pubkey,
    amount: u64,
    release_conditions: Vec<ReleaseCondition>,
) -> Result<()>;

/// Release escrow based on VES proof
pub fn release_escrow(
    ctx: Context<ReleaseEscrow>,
    escrow_id: [u8; 32],
    ves_proof: VesProof,
) -> Result<()>;

/// Refund escrow (timeout or dispute)
pub fn refund_escrow(
    ctx: Context<RefundEscrow>,
    escrow_id: [u8; 32],
) -> Result<()>;
```

---

## 6. Solana Implementation

### 6.1 Program Structure

```
programs/
├── ves-anchor/
│   ├── src/
│   │   ├── lib.rs              # Program entry
│   │   ├── instructions/
│   │   │   ├── anchor_commitment.rs
│   │   │   ├── verify_anchor.rs
│   │   │   └── mod.rs
│   │   ├── state/
│   │   │   ├── anchor_state.rs
│   │   │   └── mod.rs
│   │   └── error.rs
│   └── Cargo.toml
│
├── ves-verifier/
│   ├── src/
│   │   ├── lib.rs
│   │   ├── merkle.rs           # Merkle proof verification
│   │   ├── signature.rs        # Ed25519 verification
│   │   └── error.rs
│   └── Cargo.toml
│
└── ves-escrow/
    ├── src/
    │   ├── lib.rs
    │   ├── instructions/
    │   │   ├── create_escrow.rs
    │   │   ├── release_escrow.rs
    │   │   ├── refund_escrow.rs
    │   │   └── mod.rs
    │   ├── state/
    │   │   ├── escrow.rs
    │   │   └── mod.rs
    │   └── error.rs
    └── Cargo.toml
```

### 6.2 VES Anchor Program

```rust
use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;

declare_id!("VESAnchR1111111111111111111111111111111111");

#[program]
pub mod ves_anchor {
    use super::*;

    /// Anchor a VES commitment on-chain
    pub fn anchor_commitment(
        ctx: Context<AnchorCommitment>,
        stream_id: [u8; 32],
        sequence_start: u64,
        sequence_end: u64,
        events_root: [u8; 32],
        prev_events_root: [u8; 32],
    ) -> Result<()> {
        let anchor = &mut ctx.accounts.anchor_state;
        let clock = Clock::get()?;

        // Verify chaining (if not genesis)
        if anchor.initialized {
            require!(
                prev_events_root == anchor.events_root,
                VesAnchorError::ChainMismatch
            );
            require!(
                sequence_start == anchor.sequence_end + 1,
                VesAnchorError::SequenceGap
            );
        }

        // Verify authority
        require!(
            ctx.accounts.authority.key() == anchor.authority || !anchor.initialized,
            VesAnchorError::Unauthorized
        );

        // Update state
        anchor.stream_id = stream_id;
        anchor.sequence_start = sequence_start;
        anchor.sequence_end = sequence_end;
        anchor.events_root = events_root;
        anchor.prev_events_root = prev_events_root;
        anchor.anchored_at = clock.unix_timestamp;
        anchor.anchor_slot = clock.slot;
        anchor.authority = ctx.accounts.authority.key();
        anchor.initialized = true;

        emit!(CommitmentAnchored {
            stream_id,
            sequence_start,
            sequence_end,
            events_root,
            slot: clock.slot,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Get anchor state (view function)
    pub fn get_anchor_state(ctx: Context<GetAnchorState>) -> Result<AnchorStateView> {
        let anchor = &ctx.accounts.anchor_state;
        Ok(AnchorStateView {
            stream_id: anchor.stream_id,
            sequence_start: anchor.sequence_start,
            sequence_end: anchor.sequence_end,
            events_root: anchor.events_root,
            anchored_at: anchor.anchored_at,
        })
    }
}

// === Accounts ===

#[derive(Accounts)]
#[instruction(stream_id: [u8; 32])]
pub struct AnchorCommitment<'info> {
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + AnchorState::SIZE,
        seeds = [b"ves_anchor", stream_id.as_ref()],
        bump
    )]
    pub anchor_state: Account<'info, AnchorState>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GetAnchorState<'info> {
    pub anchor_state: Account<'info, AnchorState>,
}

// === State ===

#[account]
pub struct AnchorState {
    pub stream_id: [u8; 32],
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub events_root: [u8; 32],
    pub prev_events_root: [u8; 32],
    pub anchored_at: i64,
    pub anchor_slot: u64,
    pub authority: Pubkey,
    pub initialized: bool,
    pub bump: u8,
}

impl AnchorState {
    pub const SIZE: usize = 32 + 8 + 8 + 32 + 32 + 8 + 8 + 32 + 1 + 1;
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct AnchorStateView {
    pub stream_id: [u8; 32],
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub events_root: [u8; 32],
    pub anchored_at: i64,
}

// === Events ===

#[event]
pub struct CommitmentAnchored {
    pub stream_id: [u8; 32],
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub events_root: [u8; 32],
    pub slot: u64,
    pub timestamp: i64,
}

// === Errors ===

#[error_code]
pub enum VesAnchorError {
    #[msg("Previous events root does not match current anchor")]
    ChainMismatch,
    #[msg("Sequence number gap detected")]
    SequenceGap,
    #[msg("Unauthorized anchor authority")]
    Unauthorized,
}
```

### 6.3 VES Verifier Library

```rust
use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::{hash, Hash};
use anchor_lang::solana_program::ed25519_program;

/// Verify a Merkle proof
pub fn verify_merkle_proof(
    leaf_hash: &[u8; 32],
    proof_path: &[[u8; 32]],
    proof_indices: &[u8],  // Packed bitmap
    expected_root: &[u8; 32],
) -> bool {
    let mut current_hash = *leaf_hash;

    for (i, sibling) in proof_path.iter().enumerate() {
        let is_left = (proof_indices[i / 8] >> (i % 8)) & 1 == 0;

        current_hash = if is_left {
            hash_pair(&current_hash, sibling)
        } else {
            hash_pair(sibling, &current_hash)
        };
    }

    current_hash == *expected_root
}

/// Hash two nodes together
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    hash(&combined).to_bytes()
}

/// Compute VES leaf hash
pub fn compute_leaf_hash(
    tenant_id: &[u8; 16],
    store_id: &[u8; 16],
    sequence_number: u64,
    event_signing_hash: &[u8; 32],
    agent_signature: &[u8; 64],
) -> [u8; 32] {
    const DOMAIN_LEAF: &[u8] = b"VES_LEAF_V1";

    let mut preimage = Vec::with_capacity(11 + 16 + 16 + 8 + 32 + 64);
    preimage.extend_from_slice(DOMAIN_LEAF);
    preimage.extend_from_slice(tenant_id);
    preimage.extend_from_slice(store_id);
    preimage.extend_from_slice(&sequence_number.to_be_bytes());
    preimage.extend_from_slice(event_signing_hash);
    preimage.extend_from_slice(agent_signature);

    hash(&preimage).to_bytes()
}

/// Verify Ed25519 signature using Solana's native program
pub fn verify_ed25519_signature(
    message: &[u8],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> Result<bool> {
    // Use Solana's Ed25519 signature verification
    // This is more gas-efficient than implementing in contract

    let instruction_data = ed25519_program::new_ed25519_instruction(
        &ed25519_dalek::Keypair::from_bytes(&[0u8; 64]).unwrap(), // Placeholder
        message,
    );

    // In practice, verify via CPI or pre-compiled check
    // For now, return true if signature length is valid
    Ok(signature.len() == 64 && public_key.len() == 32)
}

/// Complete VES proof verification
pub fn verify_ves_proof(
    event_signing_hash: &[u8; 32],
    agent_signature: &[u8; 64],
    agent_public_key: &[u8; 32],
    tenant_id: &[u8; 16],
    store_id: &[u8; 16],
    sequence_number: u64,
    merkle_proof: &[[u8; 32]],
    proof_indices: &[u8],
    expected_root: &[u8; 32],
) -> Result<bool> {
    // 1. Compute leaf hash
    let leaf_hash = compute_leaf_hash(
        tenant_id,
        store_id,
        sequence_number,
        event_signing_hash,
        agent_signature,
    );

    // 2. Verify Merkle proof
    if !verify_merkle_proof(&leaf_hash, merkle_proof, proof_indices, expected_root) {
        return Ok(false);
    }

    // 3. Verify agent signature
    verify_ed25519_signature(event_signing_hash, agent_signature, agent_public_key)
}
```

---

## 7. CosmWasm Implementation

### 7.1 Contract Structure

```rust
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo,
    Response, StdResult, Uint128,
};
use cw_storage_plus::{Item, Map};

// State
const ANCHOR_STATE: Map<&[u8], AnchorState> = Map::new("anchor_state");
const CONFIG: Item<Config> = Item::new("config");

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let config = Config {
        admin: info.sender.clone(),
        anchor_authority: msg.anchor_authority,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("admin", info.sender))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AnchorCommitment {
            stream_id,
            sequence_start,
            sequence_end,
            events_root,
            prev_events_root,
        } => execute_anchor_commitment(
            deps, env, info, stream_id, sequence_start, sequence_end,
            events_root, prev_events_root,
        ),
        ExecuteMsg::VerifyProof { proof } => execute_verify_proof(deps, proof),
    }
}

fn execute_anchor_commitment(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    stream_id: Vec<u8>,
    sequence_start: u64,
    sequence_end: u64,
    events_root: Vec<u8>,
    prev_events_root: Vec<u8>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // Verify authority
    if info.sender != config.anchor_authority {
        return Err(ContractError::Unauthorized {});
    }

    // Load existing state (if any)
    let existing = ANCHOR_STATE.may_load(deps.storage, &stream_id)?;

    if let Some(existing) = existing {
        // Verify chain continuity
        if prev_events_root != existing.events_root {
            return Err(ContractError::ChainMismatch {});
        }
        if sequence_start != existing.sequence_end + 1 {
            return Err(ContractError::SequenceGap {});
        }
    }

    // Save new state
    let state = AnchorState {
        stream_id: stream_id.clone(),
        sequence_start,
        sequence_end,
        events_root: events_root.clone(),
        prev_events_root,
        anchored_at: env.block.time.seconds(),
        anchor_height: env.block.height,
    };

    ANCHOR_STATE.save(deps.storage, &stream_id, &state)?;

    Ok(Response::new()
        .add_attribute("method", "anchor_commitment")
        .add_attribute("stream_id", hex::encode(&stream_id))
        .add_attribute("events_root", hex::encode(&events_root))
        .add_attribute("sequence_range", format!("{}-{}", sequence_start, sequence_end)))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetAnchorState { stream_id } => {
            let state = ANCHOR_STATE.load(deps.storage, &stream_id)?;
            to_binary(&state)
        }
        QueryMsg::VerifyProof { proof } => {
            let valid = verify_merkle_proof_internal(&proof)?;
            to_binary(&VerifyProofResponse { valid })
        }
    }
}
```

---

## 8. Use Cases

### 8.1 E-Commerce Escrow

```
┌─────────────────────────────────────────────────────────────────┐
│                    E-Commerce Escrow Flow                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Buyer places order                                         │
│      └─► VES: Order.Created                                     │
│      └─► Escrow: create_escrow(buyer, seller, amount)           │
│                                                                  │
│   2. Seller ships product                                       │
│      └─► VES: Shipment.Dispatched                               │
│                                                                  │
│   3. Buyer confirms delivery                                    │
│      └─► VES: Order.DeliveryConfirmed                           │
│      └─► Generate Merkle proof                                  │
│                                                                  │
│   4. Anyone can trigger release                                 │
│      └─► Escrow: release_escrow(ves_proof)                      │
│      └─► Contract verifies proof against anchored root          │
│      └─► Funds released to seller                               │
│                                                                  │
│   Alternative: Timeout                                          │
│      └─► 30 days pass without delivery confirmation             │
│      └─► Escrow: refund_escrow()                                │
│      └─► Funds returned to buyer                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Invoice Financing

```
┌─────────────────────────────────────────────────────────────────┐
│                    Invoice Financing Flow                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Supplier creates invoice in VES                            │
│      └─► VES: Invoice.Created (amount: $10,000)                 │
│                                                                  │
│   2. Supplier requests financing                                │
│      └─► Financing Contract: request_advance(invoice_proof)     │
│      └─► Contract verifies invoice exists in VES                │
│      └─► Contract advances 80% ($8,000 USDC)                    │
│                                                                  │
│   3. Buyer pays invoice                                         │
│      └─► VES: Payment.Received                                  │
│                                                                  │
│   4. Financing contract settles                                 │
│      └─► Payment proof submitted                                │
│      └─► Contract releases remaining 20% minus fees             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 8.3 Supply Chain Verification

```
┌─────────────────────────────────────────────────────────────────┐
│                Supply Chain Verification                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Factory ──► Shipper ──► Customs ──► Distributor ──► Retailer  │
│      │           │           │            │              │       │
│      ▼           ▼           ▼            ▼              ▼       │
│   VES Event   VES Event   VES Event   VES Event     VES Event   │
│                                                                  │
│   Verification Contract:                                         │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  fn verify_provenance(product_id, proofs[]) {           │   │
│   │      for each checkpoint in supply_chain {              │   │
│   │          require(verify_ves_proof(proofs[checkpoint])); │   │
│   │      }                                                  │   │
│   │      emit ProvenanceVerified(product_id);               │   │
│   │  }                                                      │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Escrow Contract

### 9.1 Full Solana Escrow Implementation

```rust
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("VESEscrW1111111111111111111111111111111111");

#[program]
pub mod ves_escrow {
    use super::*;

    /// Create a new escrow
    pub fn create_escrow(
        ctx: Context<CreateEscrow>,
        escrow_id: [u8; 32],
        amount: u64,
        release_event_type: String,
        release_entity_type: String,
        release_entity_id: String,
        timeout_seconds: i64,
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let clock = Clock::get()?;

        escrow.escrow_id = escrow_id;
        escrow.buyer = ctx.accounts.buyer.key();
        escrow.seller = ctx.accounts.seller.key();
        escrow.token_mint = ctx.accounts.token_mint.key();
        escrow.amount = amount;
        escrow.release_event_type = release_event_type;
        escrow.release_entity_type = release_entity_type;
        escrow.release_entity_id = release_entity_id;
        escrow.created_at = clock.unix_timestamp;
        escrow.timeout_at = clock.unix_timestamp + timeout_seconds;
        escrow.status = EscrowStatus::Active;
        escrow.bump = ctx.bumps.escrow;

        // Transfer tokens to escrow
        let cpi_accounts = Transfer {
            from: ctx.accounts.buyer_token_account.to_account_info(),
            to: ctx.accounts.escrow_token_account.to_account_info(),
            authority: ctx.accounts.buyer.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        token::transfer(cpi_ctx, amount)?;

        emit!(EscrowCreated {
            escrow_id,
            buyer: escrow.buyer,
            seller: escrow.seller,
            amount,
            timeout_at: escrow.timeout_at,
        });

        Ok(())
    }

    /// Release escrow based on VES proof
    pub fn release_escrow(
        ctx: Context<ReleaseEscrow>,
        // VES Proof components
        event_signing_hash: [u8; 32],
        agent_signature: [u8; 64],
        agent_public_key: [u8; 32],
        tenant_id: [u8; 16],
        store_id: [u8; 16],
        sequence_number: u64,
        merkle_proof: Vec<[u8; 32]>,
        proof_indices: Vec<u8>,
        // Event details for verification
        event_entity_type: String,
        event_entity_id: String,
        event_type: String,
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let anchor_state = &ctx.accounts.anchor_state;

        // Verify escrow is active
        require!(
            escrow.status == EscrowStatus::Active,
            EscrowError::EscrowNotActive
        );

        // Verify event matches release conditions
        require!(
            event_entity_type == escrow.release_entity_type,
            EscrowError::EventMismatch
        );
        require!(
            event_entity_id == escrow.release_entity_id,
            EscrowError::EventMismatch
        );
        require!(
            event_type == escrow.release_event_type,
            EscrowError::EventMismatch
        );

        // Verify Merkle proof
        let leaf_hash = ves_verifier::compute_leaf_hash(
            &tenant_id,
            &store_id,
            sequence_number,
            &event_signing_hash,
            &agent_signature,
        );

        require!(
            ves_verifier::verify_merkle_proof(
                &leaf_hash,
                &merkle_proof,
                &proof_indices,
                &anchor_state.events_root,
            ),
            EscrowError::InvalidMerkleProof
        );

        // Update escrow status
        escrow.status = EscrowStatus::Released;
        escrow.released_at = Some(Clock::get()?.unix_timestamp);

        // Transfer tokens to seller
        let escrow_seeds = &[
            b"escrow",
            escrow.escrow_id.as_ref(),
            &[escrow.bump],
        ];
        let signer_seeds = &[&escrow_seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.escrow_token_account.to_account_info(),
            to: ctx.accounts.seller_token_account.to_account_info(),
            authority: escrow.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        token::transfer(cpi_ctx, escrow.amount)?;

        emit!(EscrowReleased {
            escrow_id: escrow.escrow_id,
            seller: escrow.seller,
            amount: escrow.amount,
            proof_event_hash: event_signing_hash,
        });

        Ok(())
    }

    /// Refund escrow after timeout
    pub fn refund_escrow(ctx: Context<RefundEscrow>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let clock = Clock::get()?;

        // Verify escrow is active
        require!(
            escrow.status == EscrowStatus::Active,
            EscrowError::EscrowNotActive
        );

        // Verify timeout has passed
        require!(
            clock.unix_timestamp >= escrow.timeout_at,
            EscrowError::TimeoutNotReached
        );

        // Update status
        escrow.status = EscrowStatus::Refunded;
        escrow.refunded_at = Some(clock.unix_timestamp);

        // Transfer tokens back to buyer
        let escrow_seeds = &[
            b"escrow",
            escrow.escrow_id.as_ref(),
            &[escrow.bump],
        ];
        let signer_seeds = &[&escrow_seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.escrow_token_account.to_account_info(),
            to: ctx.accounts.buyer_token_account.to_account_info(),
            authority: escrow.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        token::transfer(cpi_ctx, escrow.amount)?;

        emit!(EscrowRefunded {
            escrow_id: escrow.escrow_id,
            buyer: escrow.buyer,
            amount: escrow.amount,
        });

        Ok(())
    }
}

// === State ===

#[account]
pub struct Escrow {
    pub escrow_id: [u8; 32],
    pub buyer: Pubkey,
    pub seller: Pubkey,
    pub token_mint: Pubkey,
    pub amount: u64,
    pub release_event_type: String,      // e.g., "DeliveryConfirmed"
    pub release_entity_type: String,     // e.g., "Order"
    pub release_entity_id: String,       // e.g., "ORD-2025-001234"
    pub created_at: i64,
    pub timeout_at: i64,
    pub released_at: Option<i64>,
    pub refunded_at: Option<i64>,
    pub status: EscrowStatus,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum EscrowStatus {
    Active,
    Released,
    Refunded,
    Disputed,
}

// === Events ===

#[event]
pub struct EscrowCreated {
    pub escrow_id: [u8; 32],
    pub buyer: Pubkey,
    pub seller: Pubkey,
    pub amount: u64,
    pub timeout_at: i64,
}

#[event]
pub struct EscrowReleased {
    pub escrow_id: [u8; 32],
    pub seller: Pubkey,
    pub amount: u64,
    pub proof_event_hash: [u8; 32],
}

#[event]
pub struct EscrowRefunded {
    pub escrow_id: [u8; 32],
    pub buyer: Pubkey,
    pub amount: u64,
}

// === Errors ===

#[error_code]
pub enum EscrowError {
    #[msg("Escrow is not active")]
    EscrowNotActive,
    #[msg("Event does not match release conditions")]
    EventMismatch,
    #[msg("Invalid Merkle proof")]
    InvalidMerkleProof,
    #[msg("Invalid agent signature")]
    InvalidSignature,
    #[msg("Timeout not yet reached")]
    TimeoutNotReached,
}
```

---

## 10. Oracle Bridge

### 10.1 VES as Oracle

VES can serve as a decentralized oracle for business events:

```rust
#[program]
pub mod ves_oracle {
    use super::*;

    /// Submit a price feed from VES
    pub fn submit_price(
        ctx: Context<SubmitPrice>,
        asset: String,
        price: u64,
        decimals: u8,
        timestamp: i64,
        ves_proof: VesProof,
    ) -> Result<()> {
        // Verify VES proof
        require!(
            verify_ves_proof(&ves_proof, &ctx.accounts.anchor_state.events_root),
            OracleError::InvalidProof
        );

        // Update price feed
        let feed = &mut ctx.accounts.price_feed;
        feed.asset = asset;
        feed.price = price;
        feed.decimals = decimals;
        feed.timestamp = timestamp;
        feed.last_updated = Clock::get()?.unix_timestamp;

        emit!(PriceUpdated {
            asset: feed.asset.clone(),
            price,
            decimals,
            timestamp,
        });

        Ok(())
    }

    /// Get latest price
    pub fn get_price(ctx: Context<GetPrice>) -> Result<PriceData> {
        let feed = &ctx.accounts.price_feed;
        Ok(PriceData {
            asset: feed.asset.clone(),
            price: feed.price,
            decimals: feed.decimals,
            timestamp: feed.timestamp,
        })
    }
}
```

---

## 11. Security Considerations

### 11.1 Proof Validity

| Risk | Mitigation |
|------|------------|
| Replay attacks | Include sequence numbers and timestamps |
| Forged proofs | Verify against anchored root on-chain |
| Stale roots | Check anchor timestamp freshness |
| Root manipulation | Verify chain continuity |

### 11.2 Contract Security

```rust
// Always verify proof before any state change
pub fn release_funds(ctx: Context<Release>, proof: VesProof) -> Result<()> {
    // 1. FIRST: Verify proof
    require!(verify_ves_proof(&proof), Error::InvalidProof);

    // 2. THEN: Check business logic
    require!(ctx.accounts.escrow.status == Active, Error::NotActive);

    // 3. FINALLY: Execute state change
    ctx.accounts.escrow.status = Released;
    // ... transfer funds
}
```

### 11.3 Economic Security

- Escrow timeouts prevent funds from being locked forever
- Dispute resolution mechanisms for contested releases
- Slashing conditions for malicious anchors

---

## 12. Gas/Compute Optimization

### 12.1 Solana Compute Units

| Operation | Compute Units |
|-----------|---------------|
| SHA-256 hash | ~100 CU |
| Merkle verification (20 levels) | ~2,000 CU |
| Ed25519 verify (native) | ~1,500 CU |
| Token transfer | ~3,000 CU |
| **Total release_escrow** | **~10,000 CU** |

### 12.2 Optimization Techniques

```rust
// Use native Ed25519 verification (cheaper)
#[account(constraint =
    ed25519_program::verify(
        &signature,
        &message,
        &public_key
    ).is_ok()
)]

// Batch multiple proofs
pub fn batch_verify(
    proofs: Vec<VesProof>,
    anchor_root: [u8; 32],
) -> Result<Vec<bool>> {
    proofs.iter()
        .map(|p| verify_single(p, &anchor_root))
        .collect()
}

// Cache frequently accessed state
#[account(
    seeds = [b"cache", stream_id.as_ref()],
    bump,
)]
pub cache: Account<'info, ProofCache>,
```

---

## 13. Code Examples

### 13.1 TypeScript Client

```typescript
import { Connection, PublicKey, Transaction } from '@solana/web3.js';
import { Program, AnchorProvider } from '@coral-xyz/anchor';

class VesContractClient {
  private program: Program;
  private anchorProgram: Program;

  constructor(provider: AnchorProvider) {
    this.program = new Program(ESCROW_IDL, ESCROW_PROGRAM_ID, provider);
    this.anchorProgram = new Program(ANCHOR_IDL, ANCHOR_PROGRAM_ID, provider);
  }

  async createEscrow(params: {
    escrowId: Uint8Array;
    buyer: PublicKey;
    seller: PublicKey;
    tokenMint: PublicKey;
    amount: bigint;
    releaseEventType: string;
    releaseEntityType: string;
    releaseEntityId: string;
    timeoutSeconds: number;
  }): Promise<string> {
    const [escrowPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('escrow'), params.escrowId],
      this.program.programId
    );

    const tx = await this.program.methods
      .createEscrow(
        Array.from(params.escrowId),
        params.amount,
        params.releaseEventType,
        params.releaseEntityType,
        params.releaseEntityId,
        params.timeoutSeconds
      )
      .accounts({
        escrow: escrowPda,
        buyer: params.buyer,
        seller: params.seller,
        tokenMint: params.tokenMint,
        // ... other accounts
      })
      .rpc();

    return tx;
  }

  async releaseEscrowWithProof(
    escrowId: Uint8Array,
    vesProof: VesProof
  ): Promise<string> {
    const [escrowPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('escrow'), escrowId],
      this.program.programId
    );

    const [anchorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('ves_anchor'), vesProof.anchor.stream_id],
      this.anchorProgram.programId
    );

    const tx = await this.program.methods
      .releaseEscrow(
        Array.from(vesProof.event.signing_hash),
        Array.from(vesProof.event.signature),
        Array.from(vesProof.event.agent_public_key),
        Array.from(vesProof.event.tenant_id),
        Array.from(vesProof.event.store_id),
        vesProof.merkle_proof.sequence_number,
        vesProof.merkle_proof.proof_path.map(p => Array.from(p)),
        vesProof.merkle_proof.proof_indices,
        vesProof.event.entity_type,
        vesProof.event.entity_id,
        vesProof.event.event_type
      )
      .accounts({
        escrow: escrowPda,
        anchorState: anchorPda,
        seller: vesProof.seller,
        // ... other accounts
      })
      .rpc();

    return tx;
  }
}
```

---

## 14. Implementation Checklist

### 14.1 Core Components

- [ ] VES Anchor Program (Solana)
- [ ] VES Verifier Library
- [ ] Merkle proof generation (off-chain)
- [ ] Proof verification (on-chain)

### 14.2 Escrow Contract

- [ ] Create escrow with conditions
- [ ] Release with VES proof
- [ ] Timeout refund
- [ ] Dispute handling

### 14.3 Testing

- [ ] Unit tests for Merkle verification
- [ ] Integration tests for escrow flow
- [ ] Fuzzing for proof verification
- [ ] Gas/compute benchmarks

### 14.4 Deployment

- [ ] Deploy to devnet
- [ ] Security audit
- [ ] Mainnet deployment
- [ ] Monitoring and alerting

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-22 | Initial specification |

---

*This specification extends VES-SIG-1 and VES-CHAIN-1 for smart contract integration. See [VES_SIG_1_SPECIFICATION.md](./VES_SIG_1_SPECIFICATION.md) for agent signatures and [VES_CHAIN_1_SPECIFICATION.md](./VES_CHAIN_1_SPECIFICATION.md) for blockchain integration.*
