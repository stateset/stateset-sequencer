//! VES v1.0 commitment types.
//!
//! These commitments are computed over `ves_events` using VES domain-separated
//! leaf/node hashing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Hash256, StoreId, TenantId};

/// VES batch commitment containing Merkle root and sequencing metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VesBatchCommitment {
    /// Unique batch identifier.
    pub batch_id: Uuid,

    /// Tenant this batch belongs to.
    pub tenant_id: TenantId,

    /// Store this batch belongs to.
    pub store_id: StoreId,

    /// VES protocol version for this commitment.
    pub ves_version: u32,

    /// Merkle tree depth (log2(padded_leaf_count)).
    pub tree_depth: u32,

    /// Number of events in this batch (unpadded).
    pub leaf_count: u32,

    /// Number of leaves after padding to a power of two.
    pub padded_leaf_count: u32,

    /// Merkle root of VES leaves in this batch.
    pub merkle_root: Hash256,

    /// Commitment-chain state root before applying this batch.
    pub prev_state_root: Hash256,

    /// Commitment-chain state root after applying this batch.
    pub new_state_root: Hash256,

    /// Sequence range (inclusive).
    pub sequence_range: (u64, u64),

    /// When this commitment was created.
    pub committed_at: DateTime<Utc>,

    /// On-chain anchoring (optional).
    pub chain_id: Option<u32>,
    pub chain_tx_hash: Option<Hash256>,
    pub chain_block_number: Option<u64>,
    pub anchored_at: Option<DateTime<Utc>>,
}

/// Named parameters for [`VesBatchCommitment::new_with_state_roots`].
#[derive(Debug, Clone)]
pub struct VesBatchCommitmentParams {
    pub tenant_id: TenantId,
    pub store_id: StoreId,
    pub tree_depth: u32,
    pub leaf_count: u32,
    pub padded_leaf_count: u32,
    pub merkle_root: Hash256,
    pub prev_state_root: Hash256,
    pub new_state_root: Hash256,
    pub sequence_range: (u64, u64),
}

impl VesBatchCommitment {
    pub fn new(
        tenant_id: TenantId,
        store_id: StoreId,
        tree_depth: u32,
        leaf_count: u32,
        padded_leaf_count: u32,
        merkle_root: Hash256,
        sequence_range: (u64, u64),
    ) -> Self {
        Self::new_with_state_roots(VesBatchCommitmentParams {
            tenant_id,
            store_id,
            tree_depth,
            leaf_count,
            padded_leaf_count,
            merkle_root,
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            sequence_range,
        })
    }

    /// Parameters for [`Self::new_with_state_roots`].
    ///
    /// A struct (instead of positional arguments) because the three Merkle
    /// roots and the two counts are all the same types adjacently — named
    /// fields make a silent swap a compile error instead of a wrong proof.
    pub fn new_with_state_roots(params: VesBatchCommitmentParams) -> Self {
        Self {
            batch_id: Uuid::new_v4(),
            tenant_id: params.tenant_id,
            store_id: params.store_id,
            ves_version: super::VES_VERSION,
            tree_depth: params.tree_depth,
            leaf_count: params.leaf_count,
            padded_leaf_count: params.padded_leaf_count,
            merkle_root: params.merkle_root,
            prev_state_root: params.prev_state_root,
            new_state_root: params.new_state_root,
            sequence_range: params.sequence_range,
            committed_at: Utc::now(),
            chain_id: None,
            chain_tx_hash: None,
            chain_block_number: None,
            anchored_at: None,
        }
    }

    /// Returns `true` if this commitment has been submitted to L2 (tx hash recorded).
    pub fn is_submitted(&self) -> bool {
        self.chain_tx_hash.is_some()
    }

    /// Returns `true` if this commitment has been finalized on L2 (anchored_at set).
    pub fn is_anchored(&self) -> bool {
        self.anchored_at.is_some()
    }
}
