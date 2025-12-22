//! Commitment types for Merkle roots and batch commitments

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Hash256, StoreId, TenantId};

/// Batch commitment containing state and event roots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCommitment {
    /// Unique batch identifier
    pub batch_id: Uuid,

    /// Tenant this batch belongs to
    pub tenant_id: TenantId,

    /// Store this batch belongs to
    pub store_id: StoreId,

    /// State root before applying this batch
    pub prev_state_root: Hash256,

    /// State root after applying this batch
    pub new_state_root: Hash256,

    /// Merkle root of events in this batch
    pub events_root: Hash256,

    /// Number of events in this batch
    pub event_count: u32,

    /// Sequence range (inclusive)
    pub sequence_range: (u64, u64),

    /// When this commitment was created
    pub committed_at: DateTime<Utc>,

    /// On-chain transaction hash (Phase 1+)
    pub chain_tx_hash: Option<Hash256>,
}

impl BatchCommitment {
    pub fn new(
        tenant_id: TenantId,
        store_id: StoreId,
        prev_state_root: Hash256,
        new_state_root: Hash256,
        events_root: Hash256,
        event_count: u32,
        sequence_range: (u64, u64),
    ) -> Self {
        Self {
            batch_id: Uuid::new_v4(),
            tenant_id,
            store_id,
            prev_state_root,
            new_state_root,
            events_root,
            event_count,
            sequence_range,
            committed_at: Utc::now(),
            chain_tx_hash: None,
        }
    }

    /// Set chain transaction hash after on-chain settlement
    pub fn with_chain_tx(mut self, tx_hash: Hash256) -> Self {
        self.chain_tx_hash = Some(tx_hash);
        self
    }

    /// Check if this commitment has been anchored on-chain
    pub fn is_anchored(&self) -> bool {
        self.chain_tx_hash.is_some()
    }

    /// Get the sequence start
    pub fn sequence_start(&self) -> u64 {
        self.sequence_range.0
    }

    /// Get the sequence end
    pub fn sequence_end(&self) -> u64 {
        self.sequence_range.1
    }
}

/// Merkle inclusion proof for a single event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Hash of the leaf (event payload_hash + metadata)
    pub leaf_hash: Hash256,

    /// Proof path (sibling hashes from leaf to root)
    pub proof_path: Vec<Hash256>,

    /// Index of the leaf in the tree
    pub leaf_index: usize,

    /// Direction indicators (true = current is left child, false = current is right child)
    pub directions: Vec<bool>,
}

impl MerkleProof {
    pub fn new(leaf_hash: Hash256, proof_path: Vec<Hash256>, leaf_index: usize) -> Self {
        // Compute directions from leaf index
        let mut directions = Vec::with_capacity(proof_path.len());
        let mut idx = leaf_index;
        for _ in 0..proof_path.len() {
            directions.push(idx % 2 == 0); // true if we're on the left
            idx /= 2;
        }

        Self {
            leaf_hash,
            proof_path,
            leaf_index,
            directions,
        }
    }
}

/// Request for inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofRequest {
    /// Batch to prove against
    pub batch_id: Uuid,

    /// Sequence number of event to prove
    pub sequence_number: u64,
}

/// Response with inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofResponse {
    /// The proof
    pub proof: MerkleProof,

    /// Events Merkle root for verification
    pub events_root: Hash256,

    /// Batch information
    pub batch_id: Uuid,
}

/// Projection result after applying events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionResult {
    /// Number of events successfully applied
    pub events_applied: u32,

    /// Events that failed to apply (emitted as rejection events)
    pub events_rejected: Vec<ProjectionFailure>,

    /// Checkpoint sequence number after projection
    pub checkpoint_sequence: u64,
}

/// Details of a projection failure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionFailure {
    /// Event that failed
    pub event_id: Uuid,

    /// Sequence number
    pub sequence_number: u64,

    /// Reason for failure
    pub reason: ProjectionFailureReason,

    /// Human-readable message
    pub message: String,
}

/// Reasons projection can fail
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionFailureReason {
    /// Version conflict (optimistic concurrency)
    VersionConflict { expected: u64, actual: u64 },

    /// Domain invariant violated
    InvariantViolation { invariant: String },

    /// Entity not found
    EntityNotFound,

    /// Invalid state transition
    InvalidStateTransition {
        from_state: String,
        to_state: String,
    },

    /// Other error
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_commitment_creation() {
        let commitment = BatchCommitment::new(
            TenantId::new(),
            StoreId::new(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            10,
            (1, 10),
        );

        assert_eq!(commitment.event_count, 10);
        assert_eq!(commitment.sequence_start(), 1);
        assert_eq!(commitment.sequence_end(), 10);
        assert!(!commitment.is_anchored());
    }

    #[test]
    fn test_batch_commitment_with_chain_tx() {
        let commitment = BatchCommitment::new(
            TenantId::new(),
            StoreId::new(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            5,
            (1, 5),
        )
        .with_chain_tx([3u8; 32]);

        assert!(commitment.is_anchored());
    }

    #[test]
    fn test_merkle_proof_directions() {
        let proof = MerkleProof::new([0u8; 32], vec![[1u8; 32], [2u8; 32]], 2);

        // Index 2: binary 10
        // First bit (LSB): 0 -> left child -> direction true
        // Second bit: 1 -> right child -> direction false
        assert_eq!(proof.directions.len(), 2);
        assert_eq!(proof.directions, vec![true, false]);
    }
}
