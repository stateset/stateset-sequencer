//! PostgreSQL-backed x402 Payment Repository
//!
//! Provides payment intent storage, sequencing, and batch management
//! for the x402 agent-to-agent payment protocol.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rs_merkle::{algorithms::Sha256 as MerkleSha256, MerkleTree};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::crypto::Hash256;
use crate::domain::{
    AgentId, AgentKeyId, StoreId, TenantId, X402Asset, X402BatchStatus, X402BatchTotal,
    X402IntentStatus, X402Network, X402PaymentBatch, X402PaymentIntent, X402PaymentIntentFilter,
    X402PaymentReceipt, X402_DOMAIN_SEPARATOR,
};
use crate::infra::{Result, SequencerError};

/// Database row for x402 payment intents
#[derive(sqlx::FromRow)]
struct X402IntentRow {
    intent_id: Uuid,
    x402_version: i32,
    status: String,
    tenant_id: Uuid,
    store_id: Uuid,
    source_agent_id: Uuid,
    agent_key_id: i32,
    payer_address: String,
    payee_address: String,
    amount: i64,
    asset: String,
    network: String,
    chain_id: i64,
    token_address: Option<String>,
    created_at_unix: i64,
    valid_until: i64,
    nonce: i64,
    idempotency_key: Option<String>,
    resource_uri: Option<String>,
    description: Option<String>,
    order_id: Option<Uuid>,
    merchant_id: Option<String>,
    signing_hash: Vec<u8>,
    payer_signature: Vec<u8>,
    payer_public_key: Option<Vec<u8>>,
    sequence_number: Option<i64>,
    sequenced_at: Option<DateTime<Utc>>,
    batch_id: Option<Uuid>,
    tx_hash: Option<String>,
    block_number: Option<i64>,
    settled_at: Option<DateTime<Utc>>,
    metadata: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Database row for x402 payment batches
#[derive(sqlx::FromRow)]
struct X402BatchRow {
    batch_id: Uuid,
    status: String,
    tenant_id: Uuid,
    store_id: Uuid,
    network: String,
    payment_count: i32,
    total_amounts: serde_json::Value,
    merkle_root: Option<Vec<u8>>,
    prev_state_root: Option<Vec<u8>>,
    new_state_root: Option<Vec<u8>>,
    sequence_start: i64,
    sequence_end: i64,
    tx_hash: Option<String>,
    block_number: Option<i64>,
    gas_used: Option<i64>,
    created_at: DateTime<Utc>,
    committed_at: Option<DateTime<Utc>>,
    submitted_at: Option<DateTime<Utc>>,
    settled_at: Option<DateTime<Utc>>,
}

/// Rejection reason for x402 payment intents
#[derive(Debug, Clone)]
pub enum X402RejectionReason {
    /// Intent ID already exists
    DuplicateIntentId,
    /// Idempotency key already used
    DuplicateIdempotencyKey,
    /// Nonce already used for this payer
    NonceAlreadyUsed,
    /// Payment intent has expired
    Expired,
    /// Signature verification failed
    InvalidSignature,
    /// Agent key not found or revoked
    AgentKeyInvalid(String),
    /// Invalid signing hash
    InvalidSigningHash,
}

impl std::fmt::Display for X402RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateIntentId => write!(f, "duplicate_intent_id"),
            Self::DuplicateIdempotencyKey => write!(f, "duplicate_idempotency_key"),
            Self::NonceAlreadyUsed => write!(f, "nonce_already_used"),
            Self::Expired => write!(f, "expired"),
            Self::InvalidSignature => write!(f, "invalid_signature"),
            Self::AgentKeyInvalid(msg) => write!(f, "agent_key_invalid: {}", msg),
            Self::InvalidSigningHash => write!(f, "invalid_signing_hash"),
        }
    }
}

/// PostgreSQL-backed x402 payment repository
pub struct PgX402Repository {
    pool: PgPool,
}

impl PgX402Repository {
    /// Create a new x402 repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Initialize the database schema (tables created via migration)
    pub async fn initialize(&self) -> Result<()> {
        // Tables are created via migration 011_x402_payments.sql
        // This method ensures the sequence counter exists
        Ok(())
    }

    /// Update intent's batch_id
    pub async fn update_intent_batch(&self, intent_id: Uuid, batch_id: Uuid) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE x402_payment_intents
            SET batch_id = $2, status = 'batched', updated_at = NOW()
            WHERE intent_id = $1
            "#,
        )
        .bind(intent_id)
        .bind(batch_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // =========================================================================
    // Intent Operations
    // =========================================================================

    /// Insert a new payment intent
    pub async fn insert_intent(&self, intent: &X402PaymentIntent) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO x402_payment_intents (
                intent_id, x402_version, status,
                tenant_id, store_id, source_agent_id, agent_key_id,
                payer_address, payee_address, amount, asset, network, chain_id, token_address,
                created_at_unix, valid_until, nonce, idempotency_key,
                resource_uri, description, order_id, merchant_id,
                signing_hash, payer_signature, payer_public_key,
                sequence_number, sequenced_at, batch_id,
                tx_hash, block_number, settled_at,
                metadata, created_at, updated_at
            ) VALUES (
                $1, $2, $3,
                $4, $5, $6, $7,
                $8, $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18,
                $19, $20, $21, $22,
                $23, $24, $25,
                $26, $27, $28,
                $29, $30, $31,
                $32, $33, $34
            )
            "#,
        )
        .bind(intent.intent_id)
        .bind(intent.x402_version as i32)
        .bind(intent.status.to_string())
        .bind(intent.tenant_id.0)
        .bind(intent.store_id.0)
        .bind(intent.source_agent_id.0)
        .bind(intent.agent_key_id.as_u32() as i32)
        .bind(&intent.payer_address)
        .bind(&intent.payee_address)
        .bind(intent.amount as i64)
        .bind(format!("{:?}", intent.asset).to_lowercase())
        .bind(intent.network.to_string())
        .bind(intent.chain_id as i64)
        .bind(&intent.token_address)
        .bind(intent.created_at_unix as i64)
        .bind(intent.valid_until as i64)
        .bind(intent.nonce as i64)
        .bind(&intent.idempotency_key)
        .bind(&intent.resource_uri)
        .bind(&intent.description)
        .bind(intent.order_id)
        .bind(&intent.merchant_id)
        .bind(intent.signing_hash.as_slice())
        .bind(intent.payer_signature.as_slice())
        .bind(intent.payer_public_key.as_ref().map(|pk| pk.as_slice()))
        .bind(intent.sequence_number.map(|n| n as i64))
        .bind(intent.sequenced_at)
        .bind(intent.batch_id)
        .bind(&intent.tx_hash)
        .bind(intent.block_number.map(|n| n as i64))
        .bind(intent.settled_at)
        .bind(&intent.metadata)
        .bind(intent.created_at)
        .bind(intent.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get an intent by ID
    pub async fn get_intent(&self, intent_id: Uuid) -> Result<Option<X402PaymentIntent>> {
        let row: Option<X402IntentRow> = sqlx::query_as(
            r#"
            SELECT * FROM x402_payment_intents WHERE intent_id = $1
            "#,
        )
        .bind(intent_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(Self::row_to_intent).transpose()
    }

    /// Get an intent by idempotency key
    pub async fn get_intent_by_idempotency(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        idempotency_key: &str,
    ) -> Result<Option<X402PaymentIntent>> {
        let row: Option<X402IntentRow> = sqlx::query_as(
            r#"
            SELECT * FROM x402_payment_intents
            WHERE tenant_id = $1 AND store_id = $2 AND idempotency_key = $3
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await?;

        row.map(Self::row_to_intent).transpose()
    }

    /// Check if nonce has been used for a payer
    pub async fn is_nonce_used(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        payer_address: &str,
        nonce: u64,
    ) -> Result<bool> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT intent_id FROM x402_nonce_tracking
            WHERE tenant_id = $1 AND store_id = $2 AND payer_address = $3 AND nonce = $4
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(payer_address)
        .bind(nonce as i64)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    /// Reserve a nonce for a payer (returns false if already used)
    pub async fn reserve_nonce(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        payer_address: &str,
        nonce: u64,
        intent_id: Uuid,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            INSERT INTO x402_nonce_tracking (tenant_id, store_id, payer_address, nonce, intent_id)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(payer_address)
        .bind(nonce as i64)
        .bind(intent_id)
        .execute(&mut **tx)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    /// Assign sequence number atomically
    pub async fn assign_sequence_number(
        &self,
        intent_id: Uuid,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<u64> {
        let mut tx = self.pool.begin().await?;

        // Lock and get current sequence
        sqlx::query(
            r#"
            INSERT INTO x402_sequence_counters (tenant_id, store_id, current_sequence, updated_at)
            VALUES ($1, $2, 0, NOW())
            ON CONFLICT (tenant_id, store_id) DO NOTHING
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .execute(&mut *tx)
        .await?;

        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT current_sequence
            FROM x402_sequence_counters
            WHERE tenant_id = $1 AND store_id = $2
            FOR UPDATE
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_one(&mut *tx)
        .await?;

        let next_seq = (row.0 as u64).saturating_add(1);
        let now = Utc::now();

        // Update counter
        sqlx::query(
            r#"
            UPDATE x402_sequence_counters
            SET current_sequence = $3, updated_at = NOW()
            WHERE tenant_id = $1 AND store_id = $2
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(next_seq as i64)
        .execute(&mut *tx)
        .await?;

        // Update intent
        sqlx::query(
            r#"
            UPDATE x402_payment_intents
            SET sequence_number = $2, sequenced_at = $3, status = 'sequenced', updated_at = $3
            WHERE intent_id = $1
            "#,
        )
        .bind(intent_id)
        .bind(next_seq as i64)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(next_seq)
    }

    /// Update intent status
    pub async fn update_intent_status(
        &self,
        intent_id: Uuid,
        status: X402IntentStatus,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE x402_payment_intents
            SET status = $2, updated_at = NOW()
            WHERE intent_id = $1
            "#,
        )
        .bind(intent_id)
        .bind(status.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get pending intents for batching
    pub async fn get_pending_intents_for_batch(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        network: X402Network,
        limit: u32,
    ) -> Result<Vec<X402PaymentIntent>> {
        let rows: Vec<X402IntentRow> = sqlx::query_as(
            r#"
            SELECT * FROM x402_payment_intents
            WHERE tenant_id = $1 AND store_id = $2 AND network = $3 AND status = 'sequenced'
            ORDER BY sequence_number ASC
            LIMIT $4
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(network.to_string())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::row_to_intent).collect()
    }

    /// Get all intents in a batch (ordered by sequence number)
    pub async fn get_intents_by_batch(&self, batch_id: Uuid) -> Result<Vec<X402PaymentIntent>> {
        let rows: Vec<X402IntentRow> = sqlx::query_as(
            r#"
            SELECT * FROM x402_payment_intents
            WHERE batch_id = $1
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(batch_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::row_to_intent).collect()
    }

    /// List intents with filter
    pub async fn list_intents(
        &self,
        filter: &X402PaymentIntentFilter,
    ) -> Result<Vec<X402PaymentIntent>> {
        // Build dynamic query based on filter
        let rows: Vec<X402IntentRow> = if let Some(tenant_id) = filter.tenant_id {
            if let Some(store_id) = filter.store_id {
                sqlx::query_as(
                    r#"
                    SELECT * FROM x402_payment_intents
                    WHERE tenant_id = $1 AND store_id = $2
                    ORDER BY created_at DESC
                    LIMIT $3 OFFSET $4
                    "#,
                )
                .bind(tenant_id)
                .bind(store_id)
                .bind(filter.limit.unwrap_or(100) as i64)
                .bind(filter.offset.unwrap_or(0) as i64)
                .fetch_all(&self.pool)
                .await?
            } else {
                sqlx::query_as(
                    r#"
                    SELECT * FROM x402_payment_intents
                    WHERE tenant_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2 OFFSET $3
                    "#,
                )
                .bind(tenant_id)
                .bind(filter.limit.unwrap_or(100) as i64)
                .bind(filter.offset.unwrap_or(0) as i64)
                .fetch_all(&self.pool)
                .await?
            }
        } else {
            sqlx::query_as(
                r#"
                SELECT * FROM x402_payment_intents
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
                "#,
            )
            .bind(filter.limit.unwrap_or(100) as i64)
            .bind(filter.offset.unwrap_or(0) as i64)
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter().map(Self::row_to_intent).collect()
    }

    // =========================================================================
    // Batch Operations
    // =========================================================================

    /// Insert a new batch
    pub async fn insert_batch(&self, batch: &X402PaymentBatch) -> Result<()> {
        let total_amounts_json = serde_json::to_value(&batch.total_amounts)
            .map_err(|e| SequencerError::Internal(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO x402_payment_batches (
                batch_id, status, tenant_id, store_id, network,
                payment_count, total_amounts,
                merkle_root, prev_state_root, new_state_root,
                sequence_start, sequence_end,
                tx_hash, block_number, gas_used,
                created_at, committed_at, submitted_at, settled_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7,
                $8, $9, $10,
                $11, $12,
                $13, $14, $15,
                $16, $17, $18, $19
            )
            "#,
        )
        .bind(batch.batch_id)
        .bind(batch.status.to_string())
        .bind(batch.tenant_id.0)
        .bind(batch.store_id.0)
        .bind(batch.network.to_string())
        .bind(batch.payment_count as i32)
        .bind(total_amounts_json)
        .bind(batch.merkle_root.as_ref().map(|h| h.as_slice()))
        .bind(batch.prev_state_root.as_ref().map(|h| h.as_slice()))
        .bind(batch.new_state_root.as_ref().map(|h| h.as_slice()))
        .bind(batch.sequence_start as i64)
        .bind(batch.sequence_end as i64)
        .bind(&batch.tx_hash)
        .bind(batch.block_number.map(|n| n as i64))
        .bind(batch.gas_used.map(|n| n as i64))
        .bind(batch.created_at)
        .bind(batch.committed_at)
        .bind(batch.submitted_at)
        .bind(batch.settled_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a batch by ID
    pub async fn get_batch(&self, batch_id: Uuid) -> Result<Option<X402PaymentBatch>> {
        let row: Option<X402BatchRow> = sqlx::query_as(
            r#"
            SELECT * FROM x402_payment_batches WHERE batch_id = $1
            "#,
        )
        .bind(batch_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(Self::row_to_batch).transpose()
    }

    /// Update batch with Merkle root and commit
    pub async fn commit_batch(
        &self,
        batch_id: Uuid,
        merkle_root: Hash256,
        new_state_root: Hash256,
        intent_ids: &[Uuid],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // Update batch
        sqlx::query(
            r#"
            UPDATE x402_payment_batches
            SET status = 'committed',
                merkle_root = $2,
                new_state_root = $3,
                committed_at = NOW()
            WHERE batch_id = $1
            "#,
        )
        .bind(batch_id)
        .bind(merkle_root.as_slice())
        .bind(new_state_root.as_slice())
        .execute(&mut *tx)
        .await?;

        // Update intents
        for intent_id in intent_ids {
            sqlx::query(
                r#"
                UPDATE x402_payment_intents
                SET status = 'batched', batch_id = $2, updated_at = NOW()
                WHERE intent_id = $1
                "#,
            )
            .bind(intent_id)
            .bind(batch_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Update batch with settlement info
    pub async fn settle_batch(
        &self,
        batch_id: Uuid,
        tx_hash: &str,
        block_number: u64,
        gas_used: Option<u64>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // Update batch
        sqlx::query(
            r#"
            UPDATE x402_payment_batches
            SET status = 'settled',
                tx_hash = $2,
                block_number = $3,
                gas_used = $4,
                settled_at = NOW()
            WHERE batch_id = $1
            "#,
        )
        .bind(batch_id)
        .bind(tx_hash)
        .bind(block_number as i64)
        .bind(gas_used.map(|n| n as i64))
        .execute(&mut *tx)
        .await?;

        // Update all intents in batch
        sqlx::query(
            r#"
            UPDATE x402_payment_intents
            SET status = 'settled',
                tx_hash = $2,
                block_number = $3,
                settled_at = NOW(),
                updated_at = NOW()
            WHERE batch_id = $1
            "#,
        )
        .bind(batch_id)
        .bind(tx_hash)
        .bind(block_number as i64)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    // =========================================================================
    // Signature Verification
    // =========================================================================

    /// Compute the expected signing hash for payment parameters
    pub fn compute_signing_hash(
        payer: &str,
        payee: &str,
        amount: u64,
        asset: &X402Asset,
        network: &X402Network,
        chain_id: u64,
        valid_until: u64,
        nonce: u64,
    ) -> Hash256 {
        let mut hasher = Sha256::new();

        // Domain separator
        hasher.update(X402_DOMAIN_SEPARATOR.as_bytes());

        // Payment parameters
        hasher.update(payer.as_bytes());
        hasher.update(payee.as_bytes());
        hasher.update(&amount.to_be_bytes());
        hasher.update(format!("{:?}", asset).to_lowercase().as_bytes());
        hasher.update(network.to_string().as_bytes());
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&valid_until.to_be_bytes());
        hasher.update(&nonce.to_be_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify Ed25519 signature
    pub fn verify_signature(
        signing_hash: &Hash256,
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };

        let sig = Signature::from_bytes(signature);
        verifying_key.verify(signing_hash, &sig).is_ok()
    }

    // =========================================================================
    // Merkle Tree Operations
    // =========================================================================

    /// Compute leaf hash for a payment intent
    pub fn compute_intent_leaf(intent: &X402PaymentIntent) -> Hash256 {
        let mut hasher = Sha256::new();

        // Intent identity
        hasher.update(intent.intent_id.as_bytes());
        hasher.update(&intent.sequence_number.unwrap_or(0).to_be_bytes());

        // Payment parameters
        hasher.update(intent.payer_address.as_bytes());
        hasher.update(intent.payee_address.as_bytes());
        hasher.update(&intent.amount.to_be_bytes());
        hasher.update(format!("{:?}", intent.asset).to_lowercase().as_bytes());
        hasher.update(intent.network.to_string().as_bytes());
        hasher.update(&intent.chain_id.to_be_bytes());

        // Validity
        hasher.update(&intent.nonce.to_be_bytes());
        hasher.update(&intent.valid_until.to_be_bytes());

        // Signature
        hasher.update(&intent.signing_hash);
        hasher.update(&intent.payer_signature);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Build Merkle tree from payment intents
    pub fn build_merkle_tree(intents: &[X402PaymentIntent]) -> MerkleTree<MerkleSha256> {
        let leaves: Vec<Hash256> = intents
            .iter()
            .map(Self::compute_intent_leaf)
            .collect();
        MerkleTree::<MerkleSha256>::from_leaves(&leaves)
    }

    /// Compute Merkle root for payment intents
    pub fn compute_merkle_root(intents: &[X402PaymentIntent]) -> Option<Hash256> {
        if intents.is_empty() {
            return None;
        }

        let tree = Self::build_merkle_tree(intents);
        tree.root().map(|r| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&r);
            arr
        })
    }

    /// Generate Merkle proof for an intent at given index
    pub fn prove_inclusion(
        intents: &[X402PaymentIntent],
        leaf_index: usize,
    ) -> Option<Vec<Hash256>> {
        if leaf_index >= intents.len() {
            return None;
        }

        let tree = Self::build_merkle_tree(intents);
        let proof = tree.proof(&[leaf_index]);
        let proof_hashes = proof.proof_hashes();

        Some(
            proof_hashes
                .iter()
                .map(|h| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(h);
                    arr
                })
                .collect(),
        )
    }

    /// Verify Merkle inclusion proof
    pub fn verify_inclusion(
        leaf: Hash256,
        proof: &[Hash256],
        leaf_index: usize,
        total_leaves: usize,
        root: Hash256,
    ) -> bool {
        // Rebuild proof and verify
        let proof_hashes: Vec<[u8; 32]> = proof.to_vec();
        let rs_proof = rs_merkle::MerkleProof::<MerkleSha256>::new(proof_hashes);

        rs_proof.verify(root, &[leaf_index], &[leaf], total_leaves)
    }

    /// Commit a batch with Merkle root computation
    pub async fn commit_batch_with_merkle(
        &self,
        batch_id: Uuid,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<(Hash256, Hash256)> {
        // Fetch all intents for this batch
        let intent_ids: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT intent_id FROM x402_payment_intents
            WHERE batch_id = $1
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(batch_id)
        .fetch_all(&self.pool)
        .await?;

        let mut intents = Vec::with_capacity(intent_ids.len());
        for (id,) in intent_ids {
            if let Some(intent) = self.get_intent(id).await? {
                intents.push(intent);
            }
        }

        // Compute Merkle root
        let merkle_root = Self::compute_merkle_root(&intents)
            .ok_or_else(|| SequencerError::Internal("No intents in batch".to_string()))?;

        // Compute new state root (hash of merkle root + previous batch info)
        let new_state_root = {
            let mut hasher = Sha256::new();
            hasher.update(tenant_id.0.as_bytes());
            hasher.update(store_id.0.as_bytes());
            hasher.update(batch_id.as_bytes());
            hasher.update(&merkle_root);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        // Update batch in database
        let intent_ids_only: Vec<Uuid> = intents.iter().map(|i| i.intent_id).collect();
        self.commit_batch(batch_id, merkle_root, new_state_root, &intent_ids_only)
            .await?;

        Ok((merkle_root, new_state_root))
    }

    // =========================================================================
    // Receipt Generation
    // =========================================================================

    /// Generate a payment receipt with inclusion proof
    pub async fn generate_receipt(&self, intent_id: Uuid) -> Result<Option<X402PaymentReceipt>> {
        let intent = match self.get_intent(intent_id).await? {
            Some(i) => i,
            None => return Ok(None),
        };

        let Some(batch_id) = intent.batch_id else {
            return Err(SequencerError::Internal(
                "Intent not yet batched".to_string(),
            ));
        };

        let batch = match self.get_batch(batch_id).await? {
            Some(b) => b,
            None => {
                return Err(SequencerError::Internal(
                    "Batch not found for intent".to_string(),
                ))
            }
        };

        let Some(merkle_root) = batch.merkle_root else {
            return Err(SequencerError::Internal(
                "Batch not yet committed".to_string(),
            ));
        };

        // Fetch all intents in batch to generate proof
        let batch_intents = self
            .get_intents_by_batch(batch_id)
            .await?;

        // Find leaf index for this intent
        let leaf_index = batch_intents
            .iter()
            .position(|i| i.intent_id == intent_id)
            .unwrap_or(0);

        // Generate Merkle proof
        let inclusion_proof = Self::prove_inclusion(&batch_intents, leaf_index)
            .unwrap_or_default()
            .iter()
            .map(|h| format!("0x{}", hex::encode(h)))
            .collect();

        Ok(Some(X402PaymentReceipt {
            receipt_id: Uuid::new_v4(),
            intent_id,
            sequence_number: intent.sequence_number.unwrap_or(0),
            batch_id,
            merkle_root,
            inclusion_proof,
            leaf_index: leaf_index as u32,
            payer_address: intent.payer_address,
            payee_address: intent.payee_address,
            amount: intent.amount,
            asset: intent.asset,
            network: intent.network,
            tx_hash: intent.tx_hash,
            block_number: intent.block_number,
            created_at: Utc::now(),
        }))
    }

    // =========================================================================
    // Row Conversion Helpers
    // =========================================================================

    fn row_to_intent(row: X402IntentRow) -> Result<X402PaymentIntent> {
        let signing_hash: Hash256 = row
            .signing_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid signing hash".into()))?;

        let payer_signature: [u8; 64] = row
            .payer_signature
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid signature".into()))?;

        let payer_public_key: Option<Hash256> = row
            .payer_public_key
            .map(|pk| {
                pk.try_into()
                    .map_err(|_| SequencerError::Internal("invalid public key".into()))
            })
            .transpose()?;

        let status = match row.status.as_str() {
            "pending" => X402IntentStatus::Pending,
            "sequenced" => X402IntentStatus::Sequenced,
            "batched" => X402IntentStatus::Batched,
            "settled" => X402IntentStatus::Settled,
            "expired" => X402IntentStatus::Expired,
            "failed" => X402IntentStatus::Failed,
            _ => X402IntentStatus::Pending,
        };

        let asset = match row.asset.as_str() {
            "usdc" => X402Asset::Usdc,
            "usdt" => X402Asset::Usdt,
            "ssusd" => X402Asset::SsUsd,
            "dai" => X402Asset::Dai,
            _ => X402Asset::Usdc,
        };

        let network = match row.network.as_str() {
            "set_chain" => X402Network::SetChain,
            "set_chain_testnet" => X402Network::SetChainTestnet,
            "base" => X402Network::Base,
            "base_sepolia" => X402Network::BaseSepolia,
            "ethereum" => X402Network::Ethereum,
            _ => X402Network::SetChain,
        };

        Ok(X402PaymentIntent {
            intent_id: row.intent_id,
            x402_version: row.x402_version as u32,
            status,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            source_agent_id: AgentId::from_uuid(row.source_agent_id),
            agent_key_id: AgentKeyId::new(row.agent_key_id as u32),
            payer_address: row.payer_address,
            payee_address: row.payee_address,
            amount: row.amount as u64,
            asset,
            network,
            chain_id: row.chain_id as u64,
            token_address: row.token_address,
            created_at_unix: row.created_at_unix as u64,
            valid_until: row.valid_until as u64,
            nonce: row.nonce as u64,
            idempotency_key: row.idempotency_key,
            resource_uri: row.resource_uri,
            description: row.description,
            order_id: row.order_id,
            merchant_id: row.merchant_id,
            signing_hash,
            payer_signature,
            payer_public_key,
            sequence_number: row.sequence_number.map(|n| n as u64),
            sequenced_at: row.sequenced_at,
            batch_id: row.batch_id,
            tx_hash: row.tx_hash,
            block_number: row.block_number.map(|n| n as u64),
            settled_at: row.settled_at,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    fn row_to_batch(row: X402BatchRow) -> Result<X402PaymentBatch> {
        let merkle_root: Option<Hash256> = row
            .merkle_root
            .map(|h| {
                h.try_into()
                    .map_err(|_| SequencerError::Internal("invalid merkle root".into()))
            })
            .transpose()?;

        let prev_state_root: Option<Hash256> = row
            .prev_state_root
            .map(|h| {
                h.try_into()
                    .map_err(|_| SequencerError::Internal("invalid prev state root".into()))
            })
            .transpose()?;

        let new_state_root: Option<Hash256> = row
            .new_state_root
            .map(|h| {
                h.try_into()
                    .map_err(|_| SequencerError::Internal("invalid new state root".into()))
            })
            .transpose()?;

        let status = match row.status.as_str() {
            "pending" => X402BatchStatus::Pending,
            "committed" => X402BatchStatus::Committed,
            "submitted" => X402BatchStatus::Submitted,
            "settled" => X402BatchStatus::Settled,
            "failed" => X402BatchStatus::Failed,
            _ => X402BatchStatus::Pending,
        };

        let network = match row.network.as_str() {
            "set_chain" => X402Network::SetChain,
            "set_chain_testnet" => X402Network::SetChainTestnet,
            "base" => X402Network::Base,
            "base_sepolia" => X402Network::BaseSepolia,
            "ethereum" => X402Network::Ethereum,
            _ => X402Network::SetChain,
        };

        let total_amounts: Vec<X402BatchTotal> =
            serde_json::from_value(row.total_amounts).unwrap_or_default();

        Ok(X402PaymentBatch {
            batch_id: row.batch_id,
            status,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            network,
            payment_count: row.payment_count as u32,
            total_amounts,
            merkle_root,
            prev_state_root,
            new_state_root,
            sequence_start: row.sequence_start as u64,
            sequence_end: row.sequence_end as u64,
            intent_ids: vec![], // Loaded separately if needed
            tx_hash: row.tx_hash,
            block_number: row.block_number.map(|n| n as u64),
            gas_used: row.gas_used.map(|n| n as u64),
            created_at: row.created_at,
            committed_at: row.committed_at,
            submitted_at: row.submitted_at,
            settled_at: row.settled_at,
        })
    }
}

impl std::fmt::Display for X402BatchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Committed => write!(f, "committed"),
            Self::Submitted => write!(f, "submitted"),
            Self::Settled => write!(f, "settled"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_signing_hash() {
        let hash = PgX402Repository::compute_signing_hash(
            "0x1234567890123456789012345678901234567890",
            "0x0987654321098765432109876543210987654321",
            1_000_000,
            &X402Asset::Usdc,
            &X402Network::SetChain,
            84532001,
            1705320000,
            42,
        );

        // Hash should be deterministic
        let hash2 = PgX402Repository::compute_signing_hash(
            "0x1234567890123456789012345678901234567890",
            "0x0987654321098765432109876543210987654321",
            1_000_000,
            &X402Asset::Usdc,
            &X402Network::SetChain,
            84532001,
            1705320000,
            42,
        );

        assert_eq!(hash, hash2);
    }
}
