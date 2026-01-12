//! Commitment Engine implementation
//!
//! Provides Merkle tree construction and state root computation
//! for batch commitments.

use async_trait::async_trait;
use rs_merkle::{algorithms::Sha256, MerkleTree};
use sha2::{Digest, Sha256 as Sha256Hasher};
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

use crate::crypto::{compute_stream_id, legacy_commitment_leaf_hash};
use crate::domain::{BatchCommitment, Hash256, MerkleProof, StoreId, TenantId};
use crate::infra::{CommitmentEngine, PayloadEncryption, Result, SequencerError};

use super::postgres::{LeafInput, PgEventStore};

/// PostgreSQL-backed commitment engine
pub struct PgCommitmentEngine {
    pool: PgPool,
    event_store: PgEventStore,
}

impl PgCommitmentEngine {
    /// Create a new commitment engine
    pub fn new(pool: PgPool) -> Self {
        let event_store = PgEventStore::new(pool.clone(), Arc::new(PayloadEncryption::disabled()));
        Self { pool, event_store }
    }

    /// Build a Merkle tree from leaf hashes
    fn build_merkle_tree(&self, leaves: &[Hash256]) -> MerkleTree<Sha256> {
        let leaf_values: Vec<[u8; 32]> = leaves.to_vec();
        MerkleTree::<Sha256>::from_leaves(&leaf_values)
    }

    /// Get the last commitment for a tenant/store
    pub async fn get_last_commitment(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<Option<BatchCommitment>> {
        let row: Option<CommitmentRow> = sqlx::query_as(
            r#"
            SELECT batch_id, tenant_id, store_id,
                   prev_state_root, new_state_root, events_root,
                   sequence_start, sequence_end, event_count,
                   committed_at, chain_tx_hash
            FROM commitments
            WHERE tenant_id = $1 AND store_id = $2
            ORDER BY sequence_end DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_optional(&self.pool)
        .await?;

        row.map(BatchCommitment::try_from).transpose()
    }

    /// Get the commitment containing a specific sequence number.
    pub async fn get_commitment_by_sequence(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence: u64,
    ) -> Result<Option<BatchCommitment>> {
        let row: Option<CommitmentRow> = sqlx::query_as(
            r#"
            SELECT batch_id, tenant_id, store_id,
                   prev_state_root, new_state_root, events_root,
                   sequence_start, sequence_end, event_count,
                   committed_at, chain_tx_hash
            FROM commitments
            WHERE tenant_id = $1 AND store_id = $2
              AND sequence_start <= $3 AND sequence_end >= $3
            ORDER BY sequence_end DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(sequence as i64)
        .fetch_optional(&self.pool)
        .await?;

        row.map(BatchCommitment::try_from).transpose()
    }

    /// Initialize the commitments table
    pub async fn initialize(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS commitments (
                batch_id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                store_id UUID NOT NULL,
                prev_state_root BYTEA NOT NULL,
                new_state_root BYTEA NOT NULL,
                events_root BYTEA NOT NULL,
                sequence_start BIGINT NOT NULL,
                sequence_end BIGINT NOT NULL,
                event_count INT NOT NULL,
                committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                chain_tx_hash BYTEA,
                CONSTRAINT chk_sequence_range CHECK (sequence_end >= sequence_start)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_commitments_tenant_store_range ON commitments (tenant_id, store_id, sequence_start, sequence_end)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    fn stream_lock_key(tenant_id: &TenantId, store_id: &StoreId) -> i64 {
        let stream_id = compute_stream_id(&tenant_id.0, &store_id.0);
        let bytes: [u8; 8] = stream_id[..8]
            .try_into()
            .expect("stream_id is always 32 bytes");
        i64::from_be_bytes(bytes)
    }

    async fn fetch_leaf_inputs_tx(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<Vec<LeafInput>> {
        let rows: Vec<(i64, Vec<u8>, String, String)> = sqlx::query_as(
            r#"
            SELECT sequence_number, payload_hash, entity_type, entity_id
            FROM events
            WHERE tenant_id = $1 AND store_id = $2
              AND sequence_number >= $3 AND sequence_number <= $4
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(start as i64)
        .bind(end as i64)
        .fetch_all(&mut **tx)
        .await?;

        rows.into_iter()
            .map(|(seq, hash, entity_type, entity_id)| {
                let hash_arr: Hash256 = hash
                    .try_into()
                    .map_err(|_| SequencerError::Internal("Invalid hash length".to_string()))?;
                Ok(LeafInput {
                    sequence_number: seq as u64,
                    payload_hash: hash_arr,
                    entity_type,
                    entity_id,
                })
            })
            .collect()
    }

    pub async fn create_and_store_commitment(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence_range: (u64, u64),
    ) -> Result<BatchCommitment> {
        let (start, end) = sequence_range;
        if end < start {
            return Err(SequencerError::Internal(
                "Invalid sequence range".to_string(),
            ));
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(Self::stream_lock_key(tenant_id, store_id))
            .execute(&mut *tx)
            .await?;

        let last_row: Option<CommitmentRow> = sqlx::query_as(
            r#"
            SELECT batch_id, tenant_id, store_id,
                   prev_state_root, new_state_root, events_root,
                   sequence_start, sequence_end, event_count,
                   committed_at, chain_tx_hash
            FROM commitments
            WHERE tenant_id = $1 AND store_id = $2
            ORDER BY sequence_end DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_optional(&mut *tx)
        .await?;

        let prev_state_root = if let Some(row) = last_row {
            let last_commitment = BatchCommitment::try_from(row)?;
            let expected_start = last_commitment
                .sequence_range
                .1
                .checked_add(1)
                .ok_or_else(|| SequencerError::Internal("commitment sequence overflow".to_string()))?;
            if start != expected_start {
                return Err(SequencerError::Internal(format!(
                    "Commitment range must start at {} (next after last committed sequence {})",
                    expected_start, last_commitment.sequence_range.1
                )));
            }

            last_commitment.new_state_root
        } else {
            [0u8; 32]
        };

        let leaf_inputs =
            Self::fetch_leaf_inputs_tx(&mut tx, tenant_id, store_id, start, end).await?;

        if leaf_inputs.is_empty() {
            return Err(SequencerError::Internal(
                "No events in range for commitment".to_string(),
            ));
        }

        let expected_len = end
            .checked_sub(start)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| SequencerError::Internal("Invalid sequence range".to_string()))?;

        if leaf_inputs.len() as u64 != expected_len {
            return Err(SequencerError::Internal(format!(
                "Commitment range {}..={} contains {} events but expected {}",
                start,
                end,
                leaf_inputs.len(),
                expected_len
            )));
        }

        for (idx, input) in leaf_inputs.iter().enumerate() {
            let expected_seq = start + idx as u64;
            if input.sequence_number != expected_seq {
                return Err(SequencerError::Internal(format!(
                    "Non-contiguous sequence in commitment range: expected {}, found {}",
                    expected_seq, input.sequence_number
                )));
            }
        }

        let leaves: Vec<Hash256> = leaf_inputs
            .iter()
            .map(|input| {
                legacy_commitment_leaf_hash(
                    &tenant_id.0,
                    &store_id.0,
                    input.sequence_number,
                    &input.payload_hash,
                    &input.entity_type,
                    &input.entity_id,
                )
            })
            .collect();

        let events_root = self.compute_events_root(&leaves);
        let new_state_root = self.compute_state_root(tenant_id, store_id).await?;

        let commitment = BatchCommitment::new(
            tenant_id.clone(),
            store_id.clone(),
            prev_state_root,
            new_state_root,
            events_root,
            leaves.len() as u32,
            sequence_range,
        );

        sqlx::query(
            r#"
            INSERT INTO commitments (
                batch_id, tenant_id, store_id,
                prev_state_root, new_state_root, events_root,
                sequence_start, sequence_end, event_count,
                committed_at, chain_tx_hash
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(commitment.batch_id)
        .bind(commitment.tenant_id.0)
        .bind(commitment.store_id.0)
        .bind(&commitment.prev_state_root[..])
        .bind(&commitment.new_state_root[..])
        .bind(&commitment.events_root[..])
        .bind(commitment.sequence_range.0 as i64)
        .bind(commitment.sequence_range.1 as i64)
        .bind(commitment.event_count as i32)
        .bind(commitment.committed_at)
        .bind(commitment.chain_tx_hash.map(|h| h.to_vec()))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(commitment)
    }
}

#[async_trait]
impl CommitmentEngine for PgCommitmentEngine {
    fn compute_events_root(&self, leaves: &[Hash256]) -> Hash256 {
        if leaves.is_empty() {
            return [0u8; 32];
        }

        let tree = self.build_merkle_tree(leaves);
        tree.root()
            .map(|r| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&r);
                arr
            })
            .unwrap_or([0u8; 32])
    }

    async fn compute_state_root(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<Hash256> {
        // Get the latest entity versions and compute a deterministic state root
        // This is a simplified implementation - in production, you'd want a more
        // sophisticated state tree (e.g., sparse Merkle tree or Patricia trie)

        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            r#"
            SELECT entity_type, entity_id, version
            FROM entity_versions
            WHERE tenant_id = $1 AND store_id = $2
            ORDER BY entity_type, entity_id
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_all(&self.pool)
        .await?;

        let mut hasher = Sha256Hasher::new();
        hasher.update(tenant_id.0.as_bytes());
        hasher.update(store_id.0.as_bytes());

        for (entity_type, entity_id, version) in rows {
            hasher.update(entity_type.as_bytes());
            hasher.update(entity_id.as_bytes());
            hasher.update(version.to_le_bytes());
        }

        Ok(hasher.finalize().into())
    }

    async fn create_commitment(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence_range: (u64, u64),
    ) -> Result<BatchCommitment> {
        let (start, end) = sequence_range;
        if end < start {
            return Err(SequencerError::Internal(
                "Invalid sequence range".to_string(),
            ));
        }

        // Get the previous state root
        let prev_commitment = self.get_last_commitment(tenant_id, store_id).await?;
        if let Some(prev) = &prev_commitment {
            let expected_start = prev
                .sequence_range
                .1
                .checked_add(1)
                .ok_or_else(|| SequencerError::Internal("commitment sequence overflow".to_string()))?;
            if start != expected_start {
                return Err(SequencerError::Internal(format!(
                    "Commitment range must start at {} (next after last committed sequence {})",
                    expected_start, prev.sequence_range.1
                )));
            }
        }
        let prev_state_root = prev_commitment
            .map(|c| c.new_state_root)
            .unwrap_or([0u8; 32]);

        let leaf_inputs = self
            .event_store
            .get_leaf_inputs(tenant_id, store_id, start, end)
            .await?;

        if leaf_inputs.is_empty() {
            return Err(SequencerError::Internal(
                "No events in range for commitment".to_string(),
            ));
        }

        let expected_len = end
            .checked_sub(start)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| SequencerError::Internal("Invalid sequence range".to_string()))?;

        if leaf_inputs.len() as u64 != expected_len {
            return Err(SequencerError::Internal(format!(
                "Commitment range {}..={} contains {} events but expected {}",
                start,
                end,
                leaf_inputs.len(),
                expected_len
            )));
        }

        for (idx, input) in leaf_inputs.iter().enumerate() {
            let expected_seq = start + idx as u64;
            if input.sequence_number != expected_seq {
                return Err(SequencerError::Internal(format!(
                    "Non-contiguous sequence in commitment range: expected {}, found {}",
                    expected_seq, input.sequence_number
                )));
            }
        }

        // Build leaf hashes (payload_hash + metadata)
        let leaves: Vec<Hash256> = leaf_inputs
            .iter()
            .map(|input| {
                legacy_commitment_leaf_hash(
                    &tenant_id.0,
                    &store_id.0,
                    input.sequence_number,
                    &input.payload_hash,
                    &input.entity_type,
                    &input.entity_id,
                )
            })
            .collect();

        // Compute events root
        let events_root = self.compute_events_root(&leaves);

        // Compute new state root
        let new_state_root = self.compute_state_root(tenant_id, store_id).await?;

        Ok(BatchCommitment::new(
            tenant_id.clone(),
            store_id.clone(),
            prev_state_root,
            new_state_root,
            events_root,
            leaves.len() as u32,
            sequence_range,
        ))
    }

    async fn store_commitment(&self, commitment: &BatchCommitment) -> Result<()> {
        let (start, end) = commitment.sequence_range;
        if end < start {
            return Err(SequencerError::Internal(
                "Invalid sequence range".to_string(),
            ));
        }

        let expected_len = end
            .checked_sub(start)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| SequencerError::Internal("Invalid sequence range".to_string()))?;
        if commitment.event_count as u64 != expected_len {
            return Err(SequencerError::Internal(format!(
                "Commitment event_count {} does not match range length {}",
                commitment.event_count, expected_len
            )));
        }

        if let Some(last) = self
            .get_last_commitment(&commitment.tenant_id, &commitment.store_id)
            .await?
        {
            let expected_start = last
                .sequence_range
                .1
                .checked_add(1)
                .ok_or_else(|| SequencerError::Internal("commitment sequence overflow".to_string()))?;
            if start != expected_start {
                return Err(SequencerError::Internal(format!(
                    "Commitment range must start at {} (next after last committed sequence {})",
                    expected_start, last.sequence_range.1
                )));
            }
            if commitment.prev_state_root != last.new_state_root {
                return Err(SequencerError::Internal(
                    "Commitment prev_state_root does not match last new_state_root".to_string(),
                ));
            }
        }

        sqlx::query(
            r#"
            INSERT INTO commitments (
                batch_id, tenant_id, store_id,
                prev_state_root, new_state_root, events_root,
                sequence_start, sequence_end, event_count,
                committed_at, chain_tx_hash
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(commitment.batch_id)
        .bind(commitment.tenant_id.0)
        .bind(commitment.store_id.0)
        .bind(&commitment.prev_state_root[..])
        .bind(&commitment.new_state_root[..])
        .bind(&commitment.events_root[..])
        .bind(commitment.sequence_range.0 as i64)
        .bind(commitment.sequence_range.1 as i64)
        .bind(commitment.event_count as i32)
        .bind(commitment.committed_at)
        .bind(commitment.chain_tx_hash.map(|h| h.to_vec()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_commitment(&self, batch_id: Uuid) -> Result<Option<BatchCommitment>> {
        let row: Option<CommitmentRow> = sqlx::query_as(
            r#"
            SELECT batch_id, tenant_id, store_id,
                   prev_state_root, new_state_root, events_root,
                   sequence_start, sequence_end, event_count,
                   committed_at, chain_tx_hash
            FROM commitments
            WHERE batch_id = $1
            "#,
        )
        .bind(batch_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(BatchCommitment::try_from).transpose()
    }

    fn prove_inclusion(&self, leaf_index: usize, leaves: &[Hash256]) -> MerkleProof {
        let tree = self.build_merkle_tree(leaves);
        let proof = tree.proof(&[leaf_index]);
        let proof_hashes = proof.proof_hashes();

        let proof_path: Vec<Hash256> = proof_hashes
            .iter()
            .map(|h| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(h);
                arr
            })
            .collect();

        MerkleProof::new(leaves[leaf_index], proof_path, leaf_index)
    }

    fn verify_inclusion(&self, leaf: Hash256, proof: &MerkleProof, root: Hash256) -> bool {
        // Rebuild the root from leaf and proof path
        let mut current = leaf;

        for (i, sibling) in proof.proof_path.iter().enumerate() {
            let is_left = proof.directions.get(i).copied().unwrap_or(true);

            let mut hasher = Sha256Hasher::new();
            if is_left {
                hasher.update(current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(current);
            }
            current = hasher.finalize().into();
        }

        current == root
    }

    async fn list_unanchored(&self) -> Result<Vec<BatchCommitment>> {
        let rows: Vec<CommitmentRow> = sqlx::query_as(
            r#"
            SELECT batch_id, tenant_id, store_id,
                   prev_state_root, new_state_root, events_root,
                   sequence_start, sequence_end, event_count,
                   committed_at, chain_tx_hash
            FROM commitments
            WHERE chain_tx_hash IS NULL
            ORDER BY committed_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(BatchCommitment::try_from).collect()
    }

    async fn update_chain_tx(&self, batch_id: Uuid, tx_hash: Hash256) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE commitments
            SET chain_tx_hash = $1
            WHERE batch_id = $2
            "#,
        )
        .bind(&tx_hash[..])
        .bind(batch_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// Raw row from commitments table
#[derive(Debug, sqlx::FromRow)]
struct CommitmentRow {
    batch_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    prev_state_root: Vec<u8>,
    new_state_root: Vec<u8>,
    events_root: Vec<u8>,
    sequence_start: i64,
    sequence_end: i64,
    event_count: i32,
    committed_at: chrono::DateTime<chrono::Utc>,
    chain_tx_hash: Option<Vec<u8>>,
}

impl TryFrom<CommitmentRow> for BatchCommitment {
    type Error = SequencerError;

    fn try_from(row: CommitmentRow) -> Result<Self> {
        let prev_state_root: Hash256 = row
            .prev_state_root
            .try_into()
            .map_err(|_| SequencerError::Internal("Invalid prev_state_root".to_string()))?;

        let new_state_root: Hash256 = row
            .new_state_root
            .try_into()
            .map_err(|_| SequencerError::Internal("Invalid new_state_root".to_string()))?;

        let events_root: Hash256 = row
            .events_root
            .try_into()
            .map_err(|_| SequencerError::Internal("Invalid events_root".to_string()))?;

        let chain_tx_hash: Option<Hash256> = row
            .chain_tx_hash
            .map(|h| {
                h.try_into()
                    .map_err(|_| SequencerError::Internal("Invalid chain_tx_hash".to_string()))
            })
            .transpose()?;

        Ok(BatchCommitment {
            batch_id: row.batch_id,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            prev_state_root,
            new_state_root,
            events_root,
            event_count: row.event_count as u32,
            sequence_range: (row.sequence_start as u64, row.sequence_end as u64),
            committed_at: row.committed_at,
            chain_tx_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rs_merkle::{algorithms::Sha256, MerkleTree};

    /// Test Merkle tree root computation without needing database
    #[test]
    fn test_merkle_tree_construction() {
        let leaves: Vec<Hash256> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        // Build tree directly
        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = tree.root().expect("Tree should have root");

        assert_ne!(root, [0u8; 32]);
        assert_eq!(root.len(), 32);
    }

    /// Test empty leaves case
    #[test]
    fn test_empty_leaves() {
        let leaves: Vec<Hash256> = vec![];

        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);

        // Empty tree should not have a root
        assert!(tree.root().is_none());
    }

    /// Test Merkle proof verification
    #[test]
    fn test_merkle_proof_verification() {
        let leaves: Vec<Hash256> = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = tree.root().expect("Tree should have root");

        // Get proof for leaf 0
        let indices = vec![0];
        let proof = tree.proof(&indices);

        // Verify proof
        let verified = proof.verify(root, &indices, &[leaves[0]], leaves.len());
        assert!(verified);
    }

    /// Test that different leaves produce different roots
    #[test]
    fn test_different_leaves_different_roots() {
        let leaves1: Vec<Hash256> = vec![[1u8; 32], [2u8; 32]];
        let leaves2: Vec<Hash256> = vec![[3u8; 32], [4u8; 32]];

        let tree1 = MerkleTree::<Sha256>::from_leaves(&leaves1);
        let tree2 = MerkleTree::<Sha256>::from_leaves(&leaves2);

        let root1 = tree1.root().unwrap();
        let root2 = tree2.root().unwrap();

        assert_ne!(root1, root2);
    }
}
