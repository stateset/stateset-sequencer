//! VES commitment engine implementation.
//!
//! This engine computes Merkle commitments and inclusion proofs over `ves_events`
//! using VES v1.0 domain-separated leaf/node hashing.

use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::crypto::{
    compute_leaf_hash, compute_node_hash, compute_stream_id, compute_ves_state_root,
    next_power_of_two, pad_leaf, LeafHashParams,
};
use crate::domain::{Hash256, MerkleProof, StoreId, TenantId, VesBatchCommitment};
use crate::infra::{Result, SequencerError};

/// PostgreSQL-backed VES commitment engine.
pub struct PgVesCommitmentEngine {
    pool: PgPool,
}

impl PgVesCommitmentEngine {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn initialize(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ves_commitments (
                batch_id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                store_id UUID NOT NULL,
                ves_version INTEGER NOT NULL DEFAULT 1,
                tree_depth INTEGER NOT NULL,
                leaf_count INTEGER NOT NULL,
                padded_leaf_count INTEGER NOT NULL,
                merkle_root BYTEA NOT NULL,
                prev_state_root BYTEA NOT NULL,
                new_state_root BYTEA NOT NULL,
                sequence_start BIGINT NOT NULL,
                sequence_end BIGINT NOT NULL,
                committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                chain_id INTEGER,
                chain_tx_hash BYTEA,
                chain_block_number BIGINT,
                anchored_at TIMESTAMPTZ,
                CONSTRAINT chk_sequence_range CHECK (sequence_end >= sequence_start),
                CONSTRAINT chk_leaf_count CHECK (leaf_count = sequence_end - sequence_start + 1)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_ves_commitments_sequence ON ves_commitments (tenant_id, store_id, sequence_start, sequence_end)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_ves_commitments_pending ON ves_commitments (tenant_id, store_id) WHERE chain_tx_hash IS NULL",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn leaf_hashes_for_range(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<Vec<Hash256>> {
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT sequence_number, event_signing_hash, agent_signature
            FROM ves_events
            WHERE tenant_id = $1 AND store_id = $2
              AND sequence_number >= $3 AND sequence_number <= $4
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(start as i64)
        .bind(end as i64)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let expected_len = end
            .checked_sub(start)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| SequencerError::Internal("invalid sequence range".to_string()))?;

        if rows.len() as u64 != expected_len {
            return Err(SequencerError::Internal(format!(
                "VES commitment range {}..={} contains {} events but expected {}",
                start,
                end,
                rows.len(),
                expected_len
            )));
        }

        let mut leaves = Vec::with_capacity(rows.len());
        for (idx, (sequence_number, event_signing_hash, agent_signature)) in
            rows.into_iter().enumerate()
        {
            let expected_seq = start + idx as u64;
            if sequence_number as u64 != expected_seq {
                return Err(SequencerError::Internal(format!(
                    "non-contiguous sequence in VES commitment range: expected {}, found {}",
                    expected_seq, sequence_number
                )));
            }

            let event_signing_hash: Hash256 = event_signing_hash.try_into().map_err(|_| {
                SequencerError::Internal("invalid event_signing_hash length".to_string())
            })?;

            let agent_signature: [u8; 64] = agent_signature.try_into().map_err(|_| {
                SequencerError::Internal("invalid agent_signature length".to_string())
            })?;

            let params = LeafHashParams {
                tenant_id: &tenant_id.0,
                store_id: &store_id.0,
                sequence_number: sequence_number as u64,
                event_signing_hash: &event_signing_hash,
                agent_signature: &agent_signature,
            };

            leaves.push(compute_leaf_hash(&params));
        }

        Ok(leaves)
    }

    async fn leaf_hashes_for_range_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<Vec<Hash256>> {
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT sequence_number, event_signing_hash, agent_signature
            FROM ves_events
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

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let expected_len = end
            .checked_sub(start)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| SequencerError::Internal("invalid sequence range".to_string()))?;

        if rows.len() as u64 != expected_len {
            return Err(SequencerError::Internal(format!(
                "VES commitment range {}..={} contains {} events but expected {}",
                start,
                end,
                rows.len(),
                expected_len
            )));
        }

        let mut leaves = Vec::with_capacity(rows.len());
        for (idx, (sequence_number, event_signing_hash, agent_signature)) in
            rows.into_iter().enumerate()
        {
            let expected_seq = start + idx as u64;
            if sequence_number as u64 != expected_seq {
                return Err(SequencerError::Internal(format!(
                    "non-contiguous sequence in VES commitment range: expected {}, found {}",
                    expected_seq, sequence_number
                )));
            }

            let event_signing_hash: Hash256 = event_signing_hash.try_into().map_err(|_| {
                SequencerError::Internal("invalid event_signing_hash length".to_string())
            })?;

            let agent_signature: [u8; 64] = agent_signature.try_into().map_err(|_| {
                SequencerError::Internal("invalid agent_signature length".to_string())
            })?;

            let params = LeafHashParams {
                tenant_id: &tenant_id.0,
                store_id: &store_id.0,
                sequence_number: sequence_number as u64,
                event_signing_hash: &event_signing_hash,
                agent_signature: &agent_signature,
            };

            leaves.push(compute_leaf_hash(&params));
        }

        Ok(leaves)
    }

    fn stream_lock_key(tenant_id: &TenantId, store_id: &StoreId) -> i64 {
        let stream_id = compute_stream_id(&tenant_id.0, &store_id.0);
        let bytes: [u8; 8] = stream_id[..8]
            .try_into()
            .expect("stream_id is always 32 bytes");
        i64::from_be_bytes(bytes)
    }

    fn pad_leaves(&self, leaves: &[Hash256]) -> Vec<Hash256> {
        if leaves.is_empty() {
            return Vec::new();
        }

        let padded_len = next_power_of_two(leaves.len());
        let mut padded = Vec::with_capacity(padded_len);
        padded.extend_from_slice(leaves);
        padded.resize(padded_len, pad_leaf());
        padded
    }

    fn build_levels(&self, leaves: &[Hash256]) -> Vec<Vec<Hash256>> {
        let mut levels = Vec::new();
        if leaves.is_empty() {
            return levels;
        }

        levels.push(self.pad_leaves(leaves));

        while levels.last().map_or(0, Vec::len) > 1 {
            let current = levels.last().expect("levels is non-empty");
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks_exact(2) {
                next.push(compute_node_hash(&pair[0], &pair[1]));
            }
            levels.push(next);
        }

        levels
    }

    pub fn compute_merkle_root(&self, leaves: &[Hash256]) -> Hash256 {
        if leaves.is_empty() {
            return [0u8; 32];
        }

        let levels = self.build_levels(leaves);
        levels
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; 32])
    }

    pub fn prove_inclusion(&self, leaf_index: usize, leaves: &[Hash256]) -> Result<MerkleProof> {
        if leaves.is_empty() {
            return Err(SequencerError::Internal(
                "cannot prove inclusion for empty tree".to_string(),
            ));
        }
        if leaf_index >= leaves.len() {
            return Err(SequencerError::Internal(
                "leaf_index out of bounds".to_string(),
            ));
        }

        let levels = self.build_levels(leaves);
        let mut proof_path = Vec::with_capacity(levels.len().saturating_sub(1));

        let mut idx = leaf_index;
        for level in &levels[..levels.len().saturating_sub(1)] {
            let sibling_idx = idx ^ 1;
            let sibling = level
                .get(sibling_idx)
                .copied()
                .ok_or_else(|| SequencerError::Internal("invalid proof index".to_string()))?;
            proof_path.push(sibling);
            idx /= 2;
        }

        Ok(MerkleProof::new(leaves[leaf_index], proof_path, leaf_index))
    }

    pub fn verify_inclusion(&self, leaf: Hash256, proof: &MerkleProof, root: Hash256) -> bool {
        let mut current = leaf;

        for (i, sibling) in proof.proof_path.iter().enumerate() {
            let is_left = proof.directions.get(i).copied().unwrap_or(true);
            current = if is_left {
                compute_node_hash(&current, sibling)
            } else {
                compute_node_hash(sibling, &current)
            };
        }

        current == root
    }

    pub async fn create_commitment(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence_range: (u64, u64),
    ) -> Result<VesBatchCommitment> {
        let (start, end) = sequence_range;
        if end < start {
            return Err(SequencerError::Internal(
                "invalid sequence range".to_string(),
            ));
        }

        let last: Option<(i64, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT sequence_end, new_state_root
            FROM ves_commitments
            WHERE tenant_id = $1 AND store_id = $2
            ORDER BY sequence_end DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_optional(&self.pool)
        .await?;

        let prev_state_root = if let Some((last_end, last_root)) = last {
            let last_end: u64 = last_end.try_into().map_err(|_| {
                SequencerError::Internal("invalid commitment sequence_end".to_string())
            })?;
            let expected_start = last_end.checked_add(1).ok_or_else(|| {
                SequencerError::Internal("commitment sequence overflow".to_string())
            })?;
            if start != expected_start {
                return Err(SequencerError::Internal(format!(
                    "commitment range must start at {} (next after last committed sequence {})",
                    expected_start, last_end
                )));
            }

            last_root.try_into().map_err(|_| {
                SequencerError::Internal("invalid commitment new_state_root length".to_string())
            })?
        } else {
            [0u8; 32]
        };

        let leaves = self
            .leaf_hashes_for_range(tenant_id, store_id, start, end)
            .await?;

        if leaves.is_empty() {
            return Err(SequencerError::Internal(
                "no VES events in range for commitment".to_string(),
            ));
        }

        let padded_leaf_count = next_power_of_two(leaves.len());
        let tree_depth = (padded_leaf_count as u64).trailing_zeros();
        let merkle_root = self.compute_merkle_root(&leaves);

        let new_state_root = compute_ves_state_root(
            &tenant_id.0,
            &store_id.0,
            &prev_state_root,
            &merkle_root,
            start,
            end,
            leaves.len() as u32,
        );

        Ok(VesBatchCommitment::new_with_state_roots(
            tenant_id.clone(),
            store_id.clone(),
            tree_depth,
            leaves.len() as u32,
            padded_leaf_count as u32,
            merkle_root,
            prev_state_root,
            new_state_root,
            sequence_range,
        ))
    }

    pub async fn create_and_store_commitment(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence_range: (u64, u64),
    ) -> Result<VesBatchCommitment> {
        let (start, end) = sequence_range;
        if end < start {
            return Err(SequencerError::Internal(
                "invalid sequence range".to_string(),
            ));
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(Self::stream_lock_key(tenant_id, store_id))
            .execute(&mut *tx)
            .await?;

        let existing: Option<VesCommitmentRow> = sqlx::query_as(
            r#"
            SELECT
                batch_id,
                tenant_id,
                store_id,
                ves_version,
                tree_depth,
                leaf_count,
                padded_leaf_count,
                merkle_root,
                prev_state_root,
                new_state_root,
                sequence_start,
                sequence_end,
                committed_at,
                chain_id,
                chain_tx_hash,
                chain_block_number,
                anchored_at
            FROM ves_commitments
            WHERE tenant_id = $1 AND store_id = $2 AND sequence_start = $3
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(start as i64)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = existing {
            let commitment = VesBatchCommitment::try_from(row)?;
            if commitment.sequence_range.1 != end {
                return Err(SequencerError::Internal(format!(
                    "commitment already exists for start {} but ends at {} (requested {})",
                    start, commitment.sequence_range.1, end
                )));
            }
            tx.commit().await?;
            return Ok(commitment);
        }

        let last: Option<(i64, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT sequence_end, new_state_root
            FROM ves_commitments
            WHERE tenant_id = $1 AND store_id = $2
            ORDER BY sequence_end DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_optional(&mut *tx)
        .await?;

        let prev_state_root = if let Some((last_end, last_root)) = last {
            let last_end: u64 = last_end.try_into().map_err(|_| {
                SequencerError::Internal("invalid commitment sequence_end".to_string())
            })?;
            let expected_start = last_end.checked_add(1).ok_or_else(|| {
                SequencerError::Internal("commitment sequence overflow".to_string())
            })?;
            if start != expected_start {
                return Err(SequencerError::Internal(format!(
                    "commitment range must start at {} (next after last committed sequence {})",
                    expected_start, last_end
                )));
            }

            last_root.try_into().map_err(|_| {
                SequencerError::Internal("invalid commitment new_state_root length".to_string())
            })?
        } else {
            [0u8; 32]
        };

        let leaves = self
            .leaf_hashes_for_range_tx(&mut tx, tenant_id, store_id, start, end)
            .await?;

        if leaves.is_empty() {
            return Err(SequencerError::Internal(
                "no VES events in range for commitment".to_string(),
            ));
        }

        let padded_leaf_count = next_power_of_two(leaves.len());
        let tree_depth = (padded_leaf_count as u64).trailing_zeros();
        let merkle_root = self.compute_merkle_root(&leaves);

        let new_state_root = compute_ves_state_root(
            &tenant_id.0,
            &store_id.0,
            &prev_state_root,
            &merkle_root,
            start,
            end,
            leaves.len() as u32,
        );

        let commitment = VesBatchCommitment::new_with_state_roots(
            tenant_id.clone(),
            store_id.clone(),
            tree_depth,
            leaves.len() as u32,
            padded_leaf_count as u32,
            merkle_root,
            prev_state_root,
            new_state_root,
            sequence_range,
        );

        sqlx::query(
            r#"
            INSERT INTO ves_commitments (
                batch_id,
                tenant_id,
                store_id,
                ves_version,
                tree_depth,
                leaf_count,
                padded_leaf_count,
                merkle_root,
                prev_state_root,
                new_state_root,
                sequence_start,
                sequence_end,
                committed_at,
                chain_id,
                chain_tx_hash,
                chain_block_number,
                anchored_at
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17
            )
            "#,
        )
        .bind(commitment.batch_id)
        .bind(commitment.tenant_id.0)
        .bind(commitment.store_id.0)
        .bind(commitment.ves_version as i32)
        .bind(commitment.tree_depth as i32)
        .bind(commitment.leaf_count as i32)
        .bind(commitment.padded_leaf_count as i32)
        .bind(&commitment.merkle_root[..])
        .bind(&commitment.prev_state_root[..])
        .bind(&commitment.new_state_root[..])
        .bind(commitment.sequence_range.0 as i64)
        .bind(commitment.sequence_range.1 as i64)
        .bind(commitment.committed_at)
        .bind(commitment.chain_id.map(|v| v as i32))
        .bind(commitment.chain_tx_hash.map(|h| h.to_vec()))
        .bind(commitment.chain_block_number.map(|v| v as i64))
        .bind(commitment.anchored_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(commitment)
    }

    pub async fn store_commitment(&self, commitment: &VesBatchCommitment) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO ves_commitments (
                batch_id,
                tenant_id,
                store_id,
                ves_version,
                tree_depth,
                leaf_count,
                padded_leaf_count,
                merkle_root,
                prev_state_root,
                new_state_root,
                sequence_start,
                sequence_end,
                committed_at,
                chain_id,
                chain_tx_hash,
                chain_block_number,
                anchored_at
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17
            )
            "#,
        )
        .bind(commitment.batch_id)
        .bind(commitment.tenant_id.0)
        .bind(commitment.store_id.0)
        .bind(commitment.ves_version as i32)
        .bind(commitment.tree_depth as i32)
        .bind(commitment.leaf_count as i32)
        .bind(commitment.padded_leaf_count as i32)
        .bind(&commitment.merkle_root[..])
        .bind(&commitment.prev_state_root[..])
        .bind(&commitment.new_state_root[..])
        .bind(commitment.sequence_range.0 as i64)
        .bind(commitment.sequence_range.1 as i64)
        .bind(commitment.committed_at)
        .bind(commitment.chain_id.map(|v| v as i32))
        .bind(commitment.chain_tx_hash.map(|h| h.to_vec()))
        .bind(commitment.chain_block_number.map(|v| v as i64))
        .bind(commitment.anchored_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_chain_tx(
        &self,
        batch_id: Uuid,
        chain_id: u32,
        tx_hash: Hash256,
        chain_block_number: Option<u64>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE ves_commitments
            SET chain_id = $1,
                chain_tx_hash = $2,
                chain_block_number = $3,
                anchored_at = NOW()
            WHERE batch_id = $4
            "#,
        )
        .bind(chain_id as i32)
        .bind(&tx_hash[..])
        .bind(chain_block_number.map(|v| v as i64))
        .bind(batch_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_commitment(&self, batch_id: Uuid) -> Result<Option<VesBatchCommitment>> {
        let row: Option<VesCommitmentRow> = sqlx::query_as(
            r#"
            SELECT
                batch_id,
                tenant_id,
                store_id,
                ves_version,
                tree_depth,
                leaf_count,
                padded_leaf_count,
                merkle_root,
                prev_state_root,
                new_state_root,
                sequence_start,
                sequence_end,
                committed_at,
                chain_id,
                chain_tx_hash,
                chain_block_number,
                anchored_at
            FROM ves_commitments
            WHERE batch_id = $1
            "#,
        )
        .bind(batch_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(VesBatchCommitment::try_from).transpose()
    }

    pub async fn list_unanchored(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<Vec<VesBatchCommitment>> {
        let rows: Vec<VesCommitmentRow> = sqlx::query_as(
            r#"
            SELECT
                batch_id,
                tenant_id,
                store_id,
                ves_version,
                tree_depth,
                leaf_count,
                padded_leaf_count,
                merkle_root,
                prev_state_root,
                new_state_root,
                sequence_start,
                sequence_end,
                committed_at,
                chain_id,
                chain_tx_hash,
                chain_block_number,
                anchored_at
            FROM ves_commitments
            WHERE tenant_id = $1 AND store_id = $2
              AND chain_tx_hash IS NULL
            ORDER BY committed_at ASC
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(VesBatchCommitment::try_from).collect()
    }

    pub async fn list_unanchored_global(&self, limit: usize) -> Result<Vec<VesBatchCommitment>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let rows: Vec<VesCommitmentRow> = sqlx::query_as(
            r#"
            SELECT
                batch_id,
                tenant_id,
                store_id,
                ves_version,
                tree_depth,
                leaf_count,
                padded_leaf_count,
                merkle_root,
                prev_state_root,
                new_state_root,
                sequence_start,
                sequence_end,
                committed_at,
                chain_id,
                chain_tx_hash,
                chain_block_number,
                anchored_at
            FROM ves_commitments
            WHERE chain_tx_hash IS NULL
            ORDER BY committed_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(VesBatchCommitment::try_from).collect()
    }

    pub async fn leaf_hash_for_sequence(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence_number: u64,
    ) -> Result<Option<Hash256>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT event_signing_hash, agent_signature
            FROM ves_events
            WHERE tenant_id = $1 AND store_id = $2 AND sequence_number = $3
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(sequence_number as i64)
        .fetch_optional(&self.pool)
        .await?;

        let Some((event_signing_hash, agent_signature)) = row else {
            return Ok(None);
        };

        let event_signing_hash: Hash256 = event_signing_hash.try_into().map_err(|_| {
            SequencerError::Internal("invalid event_signing_hash length".to_string())
        })?;

        let agent_signature: [u8; 64] = agent_signature
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid agent_signature length".to_string()))?;

        let params = LeafHashParams {
            tenant_id: &tenant_id.0,
            store_id: &store_id.0,
            sequence_number,
            event_signing_hash: &event_signing_hash,
            agent_signature: &agent_signature,
        };

        Ok(Some(compute_leaf_hash(&params)))
    }

    pub async fn last_sequence_end(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<Option<u64>> {
        let row: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT sequence_end
            FROM ves_commitments
            WHERE tenant_id = $1 AND store_id = $2
            ORDER BY sequence_end DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(v,)| {
            v.try_into()
                .map_err(|_| SequencerError::Internal("invalid sequence_end".to_string()))
        })
        .transpose()
    }
}

#[derive(Debug, sqlx::FromRow)]
struct VesCommitmentRow {
    batch_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    ves_version: i32,
    tree_depth: i32,
    leaf_count: i32,
    padded_leaf_count: i32,
    merkle_root: Vec<u8>,
    prev_state_root: Vec<u8>,
    new_state_root: Vec<u8>,
    sequence_start: i64,
    sequence_end: i64,
    committed_at: DateTime<Utc>,
    chain_id: Option<i32>,
    chain_tx_hash: Option<Vec<u8>>,
    chain_block_number: Option<i64>,
    anchored_at: Option<DateTime<Utc>>,
}

impl TryFrom<VesCommitmentRow> for VesBatchCommitment {
    type Error = SequencerError;

    fn try_from(row: VesCommitmentRow) -> Result<Self> {
        let merkle_root: Hash256 = row
            .merkle_root
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid merkle_root".to_string()))?;
        let prev_state_root: Hash256 = row
            .prev_state_root
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid prev_state_root".to_string()))?;
        let new_state_root: Hash256 = row
            .new_state_root
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid new_state_root".to_string()))?;

        let chain_tx_hash: Option<Hash256> = row
            .chain_tx_hash
            .map(|h| {
                h.try_into()
                    .map_err(|_| SequencerError::Internal("invalid chain_tx_hash".to_string()))
            })
            .transpose()?;

        Ok(VesBatchCommitment {
            batch_id: row.batch_id,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            ves_version: row.ves_version as u32,
            tree_depth: row.tree_depth as u32,
            leaf_count: row.leaf_count as u32,
            padded_leaf_count: row.padded_leaf_count as u32,
            merkle_root,
            prev_state_root,
            new_state_root,
            sequence_range: (row.sequence_start as u64, row.sequence_end as u64),
            committed_at: row.committed_at,
            chain_id: row.chain_id.map(|v| v as u32),
            chain_tx_hash,
            chain_block_number: row.chain_block_number.map(|v| v as u64),
            anchored_at: row.anchored_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{compute_node_hash, pad_leaf};
    use sqlx::postgres::PgPoolOptions;

    fn engine() -> PgVesCommitmentEngine {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/stateset_sequencer")
            .expect("connect_lazy should not fail");
        PgVesCommitmentEngine::new(pool)
    }

    #[tokio::test]
    async fn merkle_root_empty_is_zero() {
        let engine = engine();
        assert_eq!(engine.compute_merkle_root(&[]), [0u8; 32]);
    }

    #[tokio::test]
    async fn merkle_root_pads_to_power_of_two() {
        let engine = engine();
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let leaves = vec![a, b, c];

        let expected = {
            let left = compute_node_hash(&a, &b);
            let right = compute_node_hash(&c, &pad_leaf());
            compute_node_hash(&left, &right)
        };

        assert_eq!(engine.compute_merkle_root(&leaves), expected);
    }

    #[tokio::test]
    async fn merkle_proof_verifies() {
        let engine = engine();
        let leaves: Vec<Hash256> = (0u8..8u8).map(|b| [b; 32]).collect();
        let root = engine.compute_merkle_root(&leaves);

        for idx in 0..leaves.len() {
            let proof = engine.prove_inclusion(idx, &leaves).unwrap();
            assert!(engine.verify_inclusion(leaves[idx], &proof, root));
        }
    }
}
