//! On-chain anchoring module
//!
//! Submits batch commitments to the StateSetAnchor contract on Set Chain.

#![allow(clippy::too_many_arguments)]

use alloy::primitives::{Address, FixedBytes};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use tracing::info;

use crate::domain::{BatchCommitment, Hash256, TenantId, StoreId, VesBatchCommitment};
use crate::infra::{Result, SequencerError};

/// STARK batch proof commitment for on-chain anchoring
#[derive(Debug, Clone)]
pub struct StarkBatchProof {
    /// Batch ID this proof is for
    pub batch_id: uuid::Uuid,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Store ID
    pub store_id: StoreId,
    /// Events Merkle root
    pub events_root: Hash256,
    /// Previous state root (before this batch)
    pub prev_state_root: Hash256,
    /// New state root (after this batch)
    pub new_state_root: Hash256,
    /// First sequence number in batch
    pub sequence_start: u64,
    /// Last sequence number in batch
    pub sequence_end: u64,
    /// Number of events in batch
    pub event_count: u32,
    /// Hash of the STARK proof bytes (SHA-256)
    pub proof_hash: Hash256,
    /// Policy hash used in the proof
    pub policy_hash: Hash256,
    /// Policy limit/threshold
    pub policy_limit: u64,
    /// Whether all events passed compliance
    pub all_compliant: bool,
    /// Size of proof in bytes
    pub proof_size: u64,
    /// Time to generate proof in milliseconds
    pub proving_time_ms: u64,
}

// Generate contract bindings
sol! {
    #[sol(rpc)]
    interface IStateSetAnchor {
        function anchor(
            bytes32 batchId,
            bytes32 tenantId,
            bytes32 storeId,
            bytes32 eventsRoot,
            bytes32 stateRoot,
            uint64 sequenceStart,
            uint64 sequenceEnd,
            uint32 eventCount
        ) external;

        function isAnchored(bytes32 batchId) external view returns (bool);

        function getLatestSequence(bytes32 tenantId, bytes32 storeId) external view returns (uint64);

        function verifyEventsRoot(bytes32 batchId, bytes32 eventsRoot) external view returns (bool);

        // STARK proof functions
        function commitStarkProof(
            bytes32 batchId,
            bytes32 proofHash,
            bytes32 prevStateRoot,
            bytes32 newStateRoot,
            bytes32 policyHash,
            uint64 policyLimit,
            bool allCompliant,
            uint64 proofSize,
            uint64 provingTimeMs
        ) external;

        function commitBatchWithStarkProof(
            bytes32 batchId,
            bytes32 tenantId,
            bytes32 storeId,
            bytes32 eventsRoot,
            bytes32 prevStateRoot,
            bytes32 newStateRoot,
            uint64 sequenceStart,
            uint64 sequenceEnd,
            uint32 eventCount,
            bytes32 proofHash,
            bytes32 policyHash,
            uint64 policyLimit,
            bool allCompliant,
            uint64 proofSize,
            uint64 provingTimeMs
        ) external;

        function hasStarkProof(bytes32 batchId) external view returns (bool);

        function verifyStarkProofHash(bytes32 batchId, bytes32 proofHash) external view returns (bool);
    }
}

/// Anchor service configuration
#[derive(Debug, Clone)]
pub struct AnchorConfig {
    /// RPC URL for the L2 chain
    pub rpc_url: String,
    /// StateSetAnchor contract address
    pub registry_address: Address,
    /// Private key for signing transactions
    pub private_key: String,
    /// Chain ID
    pub chain_id: u64,
}

impl AnchorConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Option<Self> {
        let rpc_url = std::env::var("L2_RPC_URL").ok()?;
        let registry_address = std::env::var("SET_REGISTRY_ADDRESS")
            .ok()
            .and_then(|s| s.parse().ok())?;
        let private_key = std::env::var("SEQUENCER_PRIVATE_KEY").ok()?;
        let chain_id = std::env::var("L2_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(84532001);

        Some(Self {
            rpc_url,
            registry_address,
            private_key,
            chain_id,
        })
    }
}

/// On-chain anchor service
pub struct AnchorService {
    config: AnchorConfig,
}

impl AnchorService {
    /// Create a new anchor service
    pub fn new(config: AnchorConfig) -> Self {
        Self { config }
    }

    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Convert Hash256 to FixedBytes<32>
    fn to_bytes32(hash: &Hash256) -> FixedBytes<32> {
        FixedBytes::from_slice(hash)
    }

    /// Convert UUID to bytes32
    fn uuid_to_bytes32(uuid: uuid::Uuid) -> FixedBytes<32> {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(uuid.as_bytes());
        FixedBytes::from_slice(&bytes)
    }

    /// Anchor a commitment on-chain
    pub async fn anchor_commitment(&self, commitment: &BatchCommitment) -> Result<Hash256> {
        info!(
            "Anchoring commitment {} to chain (sequences {}-{})",
            commitment.batch_id, commitment.sequence_range.0, commitment.sequence_range.1
        );

        // Parse private key and create signer
        let signer: PrivateKeySigner = self
            .config
            .private_key
            .parse()
            .map_err(|e| SequencerError::Internal(format!("Invalid private key: {}", e)))?;

        // Create provider with signer and recommended fillers
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(alloy::network::EthereumWallet::from(signer))
            .on_http(
                self.config
                    .rpc_url
                    .parse()
                    .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
            );

        // Create contract instance
        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        // Convert commitment fields to contract types
        let batch_id = Self::uuid_to_bytes32(commitment.batch_id);
        let tenant_id = Self::uuid_to_bytes32(commitment.tenant_id.0);
        let store_id = Self::uuid_to_bytes32(commitment.store_id.0);
        let events_root = Self::to_bytes32(&commitment.events_root);
        let state_root = Self::to_bytes32(&commitment.new_state_root);

        // Build and send transaction
        let tx = contract.anchor(
            batch_id,
            tenant_id,
            store_id,
            events_root,
            state_root,
            commitment.sequence_range.0,
            commitment.sequence_range.1,
            commitment.event_count,
        );

        let pending = tx
            .send()
            .await
            .map_err(|e| SequencerError::Internal(format!("Failed to send transaction: {}", e)))?;

        info!("Transaction sent: {:?}", pending.tx_hash());

        // Wait for confirmation
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| SequencerError::Internal(format!("Failed to get receipt: {}", e)))?;

        let tx_hash: Hash256 = receipt.transaction_hash.0;

        info!(
            "Commitment {} anchored in tx {} (block {})",
            commitment.batch_id,
            hex::encode(tx_hash),
            receipt.block_number.unwrap_or(0)
        );

        Ok(tx_hash)
    }

    /// Anchor a VES commitment on-chain.
    pub async fn anchor_ves_commitment(
        &self,
        commitment: &VesBatchCommitment,
    ) -> Result<(Hash256, Option<u64>)> {
        info!(
            "Anchoring VES commitment {} to chain (sequences {}-{})",
            commitment.batch_id, commitment.sequence_range.0, commitment.sequence_range.1
        );

        let signer: PrivateKeySigner = self
            .config
            .private_key
            .parse()
            .map_err(|e| SequencerError::Internal(format!("Invalid private key: {}", e)))?;

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(alloy::network::EthereumWallet::from(signer))
            .on_http(
                self.config
                    .rpc_url
                    .parse()
                    .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
            );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        let batch_id = Self::uuid_to_bytes32(commitment.batch_id);
        let tenant_id = Self::uuid_to_bytes32(commitment.tenant_id.0);
        let store_id = Self::uuid_to_bytes32(commitment.store_id.0);
        let events_root = Self::to_bytes32(&commitment.merkle_root);
        let state_root = Self::to_bytes32(&commitment.new_state_root);

        let tx = contract.anchor(
            batch_id,
            tenant_id,
            store_id,
            events_root,
            state_root,
            commitment.sequence_range.0,
            commitment.sequence_range.1,
            commitment.leaf_count,
        );

        let pending = tx
            .send()
            .await
            .map_err(|e| SequencerError::Internal(format!("Failed to send transaction: {}", e)))?;

        info!("Transaction sent: {:?}", pending.tx_hash());

        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| SequencerError::Internal(format!("Failed to get receipt: {}", e)))?;

        let tx_hash: Hash256 = receipt.transaction_hash.0;
        let block_number = receipt.block_number;

        info!(
            "VES commitment {} anchored in tx {} (block {})",
            commitment.batch_id,
            hex::encode(tx_hash),
            block_number.unwrap_or(0)
        );

        Ok((tx_hash, block_number))
    }

    /// Verify a commitment is anchored on-chain
    pub async fn verify_anchored(&self, batch_id: uuid::Uuid) -> Result<bool> {
        let provider = ProviderBuilder::new().on_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
        );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        let batch_id_bytes = Self::uuid_to_bytes32(batch_id);
        let result = contract
            .isAnchored(batch_id_bytes)
            .call()
            .await
            .map_err(|e| SequencerError::Internal(format!("Contract call failed: {}", e)))?;

        Ok(result._0)
    }

    /// Get the on-chain head sequence for a tenant/store
    pub async fn get_chain_head(&self, tenant_id: uuid::Uuid, store_id: uuid::Uuid) -> Result<u64> {
        let provider = ProviderBuilder::new().on_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
        );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        let tenant_bytes = Self::uuid_to_bytes32(tenant_id);
        let store_bytes = Self::uuid_to_bytes32(store_id);

        let head = contract
            .getLatestSequence(tenant_bytes, store_bytes)
            .call()
            .await
            .map_err(|e| SequencerError::Internal(format!("Contract call failed: {}", e)))?;

        Ok(head._0)
    }

    /// Verify an events root against on-chain data
    pub async fn verify_events_root_onchain(
        &self,
        batch_id: uuid::Uuid,
        events_root: &Hash256,
    ) -> Result<bool> {
        let provider = ProviderBuilder::new().on_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
        );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        let batch_id_bytes = Self::uuid_to_bytes32(batch_id);
        let events_root_bytes = Self::to_bytes32(events_root);

        let valid = contract
            .verifyEventsRoot(batch_id_bytes, events_root_bytes)
            .call()
            .await
            .map_err(|e| SequencerError::Internal(format!("Contract call failed: {}", e)))?;

        Ok(valid._0)
    }

    /// Anchor a STARK batch proof on-chain (batch + proof in single transaction)
    pub async fn anchor_stark_batch_proof(
        &self,
        proof: &StarkBatchProof,
    ) -> Result<(Hash256, Option<u64>)> {
        info!(
            "Anchoring STARK batch proof {} to chain (sequences {}-{}, {} events, all_compliant={})",
            proof.batch_id,
            proof.sequence_start,
            proof.sequence_end,
            proof.event_count,
            proof.all_compliant
        );

        let signer: PrivateKeySigner = self
            .config
            .private_key
            .parse()
            .map_err(|e| SequencerError::Internal(format!("Invalid private key: {}", e)))?;

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(alloy::network::EthereumWallet::from(signer))
            .on_http(
                self.config
                    .rpc_url
                    .parse()
                    .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
            );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        // Convert all fields to contract types
        let batch_id = Self::uuid_to_bytes32(proof.batch_id);
        let tenant_id = Self::uuid_to_bytes32(proof.tenant_id.0);
        let store_id = Self::uuid_to_bytes32(proof.store_id.0);
        let events_root = Self::to_bytes32(&proof.events_root);
        let prev_state_root = Self::to_bytes32(&proof.prev_state_root);
        let new_state_root = Self::to_bytes32(&proof.new_state_root);
        let proof_hash = Self::to_bytes32(&proof.proof_hash);
        let policy_hash = Self::to_bytes32(&proof.policy_hash);

        // Call commitBatchWithStarkProof - single transaction for both batch and proof
        let tx = contract.commitBatchWithStarkProof(
            batch_id,
            tenant_id,
            store_id,
            events_root,
            prev_state_root,
            new_state_root,
            proof.sequence_start,
            proof.sequence_end,
            proof.event_count,
            proof_hash,
            policy_hash,
            proof.policy_limit,
            proof.all_compliant,
            proof.proof_size,
            proof.proving_time_ms,
        );

        let pending = tx
            .send()
            .await
            .map_err(|e| SequencerError::Internal(format!("Failed to send transaction: {}", e)))?;

        info!("STARK proof transaction sent: {:?}", pending.tx_hash());

        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| SequencerError::Internal(format!("Failed to get receipt: {}", e)))?;

        let tx_hash: Hash256 = receipt.transaction_hash.0;
        let block_number = receipt.block_number;

        info!(
            "STARK batch proof {} anchored in tx {} (block {})",
            proof.batch_id,
            hex::encode(tx_hash),
            block_number.unwrap_or(0)
        );

        Ok((tx_hash, block_number))
    }

    /// Check if a batch has a STARK proof on-chain
    pub async fn has_stark_proof_onchain(&self, batch_id: uuid::Uuid) -> Result<bool> {
        let provider = ProviderBuilder::new().on_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
        );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        let batch_id_bytes = Self::uuid_to_bytes32(batch_id);
        let result = contract
            .hasStarkProof(batch_id_bytes)
            .call()
            .await
            .map_err(|e| SequencerError::Internal(format!("Contract call failed: {}", e)))?;

        Ok(result._0)
    }

    /// Verify a STARK proof hash matches on-chain
    pub async fn verify_stark_proof_hash_onchain(
        &self,
        batch_id: uuid::Uuid,
        proof_hash: &Hash256,
    ) -> Result<bool> {
        let provider = ProviderBuilder::new().on_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
        );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        let batch_id_bytes = Self::uuid_to_bytes32(batch_id);
        let proof_hash_bytes = Self::to_bytes32(proof_hash);

        let valid = contract
            .verifyStarkProofHash(batch_id_bytes, proof_hash_bytes)
            .call()
            .await
            .map_err(|e| SequencerError::Internal(format!("Contract call failed: {}", e)))?;

        Ok(valid._0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_to_bytes32() {
        let uuid = uuid::Uuid::parse_str("d982e688-bc8e-4cb3-ba26-b7777a98c526").unwrap();
        let bytes = AnchorService::uuid_to_bytes32(uuid);
        assert_eq!(bytes.len(), 32);
        // First 16 bytes should be the UUID
        assert_eq!(&bytes[..16], uuid.as_bytes());
    }

    #[test]
    fn test_hash256_to_bytes32() {
        let hash: Hash256 = [1u8; 32];
        let bytes = AnchorService::to_bytes32(&hash);
        assert_eq!(bytes.0, hash);
    }
}
