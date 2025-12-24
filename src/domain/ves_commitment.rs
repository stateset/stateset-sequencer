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
        Self::new_with_state_roots(
            tenant_id,
            store_id,
            tree_depth,
            leaf_count,
            padded_leaf_count,
            merkle_root,
            [0u8; 32],
            [0u8; 32],
            sequence_range,
        )
    }

    /// Create a new batch commitment with explicit state roots.
    ///
    /// Note: This function takes many parameters by design - each represents
    /// a distinct field in the VES commitment structure.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_state_roots(
        tenant_id: TenantId,
        store_id: StoreId,
        tree_depth: u32,
        leaf_count: u32,
        padded_leaf_count: u32,
        merkle_root: Hash256,
        prev_state_root: Hash256,
        new_state_root: Hash256,
        sequence_range: (u64, u64),
    ) -> Self {
        Self {
            batch_id: Uuid::new_v4(),
            tenant_id,
            store_id,
            ves_version: super::VES_VERSION,
            tree_depth,
            leaf_count,
            padded_leaf_count,
            merkle_root,
            prev_state_root,
            new_state_root,
            sequence_range,
            committed_at: Utc::now(),
            chain_id: None,
            chain_tx_hash: None,
            chain_block_number: None,
            anchored_at: None,
        }
    }

    pub fn is_anchored(&self) -> bool {
        self.chain_tx_hash.is_some()
    }
}
