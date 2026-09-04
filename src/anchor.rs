//! On-chain anchoring module
//!
//! Submits batch commitments to the StateSetAnchor contract on Set Chain.

#![allow(clippy::too_many_arguments)]

use alloy::primitives::{Address, FixedBytes};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use tracing::{info, warn};

use crate::domain::{BatchCommitment, Hash256, StoreId, TenantId, VesBatchCommitment};
use crate::infra::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, Result, Retry, RetryConfig,
    SequencerError,
};

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
    /// Binding for the deployed `SetRegistry` contract (set/contracts/SetRegistry.sol).
    ///
    /// The previous binding declared `anchor`, `isAnchored`, `getLatestSequence`
    /// and `verifyEventsRoot`, none of which exist on SetRegistry, so every
    /// anchor attempt in the shipped stack reverted on selector lookup. The
    /// functions below are the ones the contract actually exposes.
    interface IStateSetAnchor {
        struct BatchCommitment {
            bytes32 eventsRoot;
            bytes32 newStateRoot;
            uint64 sequenceStart;
            uint64 sequenceEnd;
            uint32 eventCount;
            uint64 timestamp;
        }

        function commitBatch(
            bytes32 batchId,
            bytes32 tenantId,
            bytes32 storeId,
            bytes32 eventsRoot,
            bytes32 prevStateRoot,
            bytes32 newStateRoot,
            uint64 sequenceStart,
            uint64 sequenceEnd,
            uint32 eventCount
        ) external;

        function batchExists(bytes32 batchId) external view returns (bool exists);

        function getHeadSequence(bytes32 tenantId, bytes32 storeId) external view returns (uint64 sequence);

        function getBatchCommitment(bytes32 batchId) external view returns (BatchCommitment memory commitment);

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
#[derive(Clone)]
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

impl std::fmt::Debug for AnchorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorConfig")
            .field("rpc_url", &"<redacted>")
            .field("registry_address", &self.registry_address)
            .field("private_key", &"<redacted>")
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

impl AnchorConfig {
    /// Load configuration from environment variables.
    ///
    /// Returns `Ok(None)` only when anchoring is entirely unconfigured. A
    /// partial or malformed configuration is an error so a requested anchor
    /// worker cannot silently remain disabled.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let rpc_url = std::env::var("L2_RPC_URL").ok();
        let registry_address = std::env::var("SET_REGISTRY_ADDRESS").ok();
        let private_key = std::env::var("SEQUENCER_PRIVATE_KEY").ok();

        if rpc_url.is_none() && registry_address.is_none() && private_key.is_none() {
            return Ok(None);
        }

        let rpc_url = rpc_url
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("L2_RPC_URL is required when anchoring is configured")
            })?;
        let registry_address = registry_address
            .ok_or_else(|| {
                anyhow::anyhow!("SET_REGISTRY_ADDRESS is required when anchoring is configured")
            })?
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid SET_REGISTRY_ADDRESS: {e}"))?;
        let private_key = private_key
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("SEQUENCER_PRIVATE_KEY is required when anchoring is configured")
            })?;
        let chain_id = match std::env::var("L2_CHAIN_ID") {
            Ok(raw) => raw
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid L2_CHAIN_ID: '{raw}'"))?,
            Err(_) => 84532001, // Default: Set Chain testnet
        };

        Ok(Some(Self {
            rpc_url,
            registry_address,
            private_key,
            chain_id,
        }))
    }
}

/// Transient vs terminal classification for anchor send errors.
/// See [`crate::infra::is_transient_chain_error`] for why reverts must be
/// recognised even when wrapped in a send failure.
fn is_retryable_anchor_error(err: &SequencerError) -> bool {
    crate::infra::is_transient_chain_error(err)
}

/// Transaction hash returned by [`AnchorService::anchor_ves_commitment`] when
/// the commitment was found already anchored on-chain and no transaction was
/// sent. Callers should confirm the anchor locally rather than wait for a
/// receipt that does not exist.
pub const ALREADY_ANCHORED_TX_HASH: Hash256 = [0u8; 32];

/// On-chain anchor service with retry and circuit breaker protection
pub struct AnchorService {
    config: AnchorConfig,
    circuit_breaker: CircuitBreaker,
    retry_config: RetryConfig,
}

impl AnchorService {
    /// Create a new anchor service with default retry and circuit breaker settings
    pub fn new(config: AnchorConfig) -> Self {
        let circuit_breaker = CircuitBreaker::with_config(
            "anchor",
            CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 2,
                open_timeout: std::time::Duration::from_secs(60),
                failure_window: std::time::Duration::from_secs(120),
                half_open_max_requests: 1,
                backoff_multiplier: 2.0,
                max_backoff: std::time::Duration::from_secs(300),
                jitter_factor: 0.1,
                slow_call_threshold: Some(std::time::Duration::from_secs(30)),
                slow_call_rate_threshold: None,
            },
        );
        Self {
            config,
            circuit_breaker,
            retry_config: RetryConfig::blockchain(),
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Get a reference to the circuit breaker for status monitoring
    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
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

    /// Anchor a commitment on-chain with retry and circuit breaker protection
    pub async fn anchor_commitment(&self, commitment: &BatchCommitment) -> Result<Hash256> {
        info!(
            "Anchoring commitment {} to chain (sequences {}-{})",
            commitment.batch_id, commitment.sequence_range.0, commitment.sequence_range.1
        );

        let config = &self.config;
        let registry_address = config.registry_address;
        let batch_id_uuid = commitment.batch_id;
        let retry_config = self.retry_config.clone();

        let (tx_hash, block_number) = self
            .circuit_breaker
            .call(async {
                let retry = Retry::new(retry_config);
                let result = retry.run_with_predicate(
                    || {
                        let private_key = config.private_key.clone();
                        let rpc_url = config.rpc_url.clone();
                        let batch_id = Self::uuid_to_bytes32(commitment.batch_id);
                        let tenant_id = Self::uuid_to_bytes32(commitment.tenant_id.0);
                        let store_id = Self::uuid_to_bytes32(commitment.store_id.0);
                        let events_root = Self::to_bytes32(&commitment.events_root);
                        let state_root = Self::to_bytes32(&commitment.new_state_root);
                        let prev_state_root = Self::to_bytes32(&commitment.prev_state_root);
                        let seq_start = commitment.sequence_range.0;
                        let seq_end = commitment.sequence_range.1;
                        let event_count = commitment.event_count;

                        async move {
                            let signer: PrivateKeySigner = private_key.parse()
                                .map_err(|e| SequencerError::Internal(format!("Invalid private key: {e}")))?;
                            let provider = ProviderBuilder::new()
                                .wallet(alloy::network::EthereumWallet::from(signer))
                                .connect_http(rpc_url.parse()
                                    .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {e}")))?);
                            let contract = IStateSetAnchor::new(registry_address, &provider);
                            let tx = contract.commitBatch(batch_id, tenant_id, store_id, events_root, prev_state_root, state_root, seq_start, seq_end, event_count);
                            let pending = tx.send().await
                                .map_err(|e| SequencerError::Internal(format!("Failed to send transaction: {e}")))?;
                            let receipt = pending.get_receipt().await
                                .map_err(|e| SequencerError::Internal(format!("Failed to get receipt: {e}")))?;
                            Ok::<_, SequencerError>((receipt.transaction_hash.0, receipt.block_number))
                        }
                    },
                    is_retryable_anchor_error,
                ).await;

                if result.attempts > 1 {
                    warn!(batch_id = %batch_id_uuid, attempts = result.attempts, "Anchor commitment succeeded after retries");
                }
                result.into_result()
            })
            .await
            .map_err(|e| match e {
                CircuitBreakerError::ServiceError(inner) => inner,
                CircuitBreakerError::CircuitOpen => SequencerError::Internal(
                    "Anchor circuit breaker is open — RPC endpoint unavailable".into(),
                ),
                CircuitBreakerError::Timeout => {
                    SequencerError::Internal("Anchor operation timed out".into())
                }
            })?;

        info!(
            "Commitment {} anchored in tx {} (block {})",
            batch_id_uuid,
            hex::encode(tx_hash),
            block_number.unwrap_or(0)
        );

        Ok(tx_hash)
    }

    /// Anchor a VES commitment on-chain with retry and circuit breaker protection.
    pub async fn anchor_ves_commitment(
        &self,
        commitment: &VesBatchCommitment,
    ) -> Result<(Hash256, Option<u64>)> {
        info!(
            "Anchoring VES commitment {} to chain (sequences {}-{})",
            commitment.batch_id, commitment.sequence_range.0, commitment.sequence_range.1
        );

        let config = &self.config;
        let registry_address = config.registry_address;
        let batch_id_uuid = commitment.batch_id;
        let retry_config = self.retry_config.clone();

        // Pre-check: a prior attempt may have anchored this commitment on-chain
        // and then failed to record it locally (crash, or a lost DB write).
        // The worker only reconciles commitments that already carry a tx hash,
        // so without this the same commitment would be re-sent every tick,
        // revert with BatchAlreadyCommitted, and stall the tick -- forever.
        if self.verify_anchored(batch_id_uuid).await.unwrap_or(false) {
            warn!(
                batch_id = %batch_id_uuid,
                "Commitment already anchored on-chain; reconciling local state without sending"
            );
            return Ok((ALREADY_ANCHORED_TX_HASH, None));
        }

        let (tx_hash, block_number) = self
            .circuit_breaker
            .call(async {
                let retry = Retry::new(retry_config);
                let result = retry.run_with_predicate(
                    || {
                        let private_key = config.private_key.clone();
                        let rpc_url = config.rpc_url.clone();
                        let batch_id = Self::uuid_to_bytes32(commitment.batch_id);
                        let tenant_id = Self::uuid_to_bytes32(commitment.tenant_id.0);
                        let store_id = Self::uuid_to_bytes32(commitment.store_id.0);
                        let events_root = Self::to_bytes32(&commitment.merkle_root);
                        let state_root = Self::to_bytes32(&commitment.new_state_root);
                        let prev_state_root = Self::to_bytes32(&commitment.prev_state_root);
                        let seq_start = commitment.sequence_range.0;
                        let seq_end = commitment.sequence_range.1;
                        let leaf_count = commitment.leaf_count;

                        async move {
                            let signer: PrivateKeySigner = private_key.parse()
                                .map_err(|e| SequencerError::Internal(format!("Invalid private key: {e}")))?;
                            let provider = ProviderBuilder::new()
                                .wallet(alloy::network::EthereumWallet::from(signer))
                                .connect_http(rpc_url.parse()
                                    .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {e}")))?);
                            let contract = IStateSetAnchor::new(registry_address, &provider);
                            let tx = contract.commitBatch(batch_id, tenant_id, store_id, events_root, prev_state_root, state_root, seq_start, seq_end, leaf_count);
                            let pending = tx.send().await
                                .map_err(|e| SequencerError::Internal(format!("Failed to send transaction: {e}")))?;
                            let receipt = pending.get_receipt().await
                                .map_err(|e| SequencerError::Internal(format!("Failed to get receipt: {e}")))?;
                            Ok::<_, SequencerError>((receipt.transaction_hash.0, receipt.block_number))
                        }
                    },
                    is_retryable_anchor_error,
                ).await;

                if result.attempts > 1 {
                    warn!(batch_id = %batch_id_uuid, attempts = result.attempts, "VES anchor succeeded after retries");
                }
                result.into_result()
            })
            .await
            .map_err(|e| match e {
                CircuitBreakerError::ServiceError(inner) => inner,
                CircuitBreakerError::CircuitOpen => SequencerError::Internal(
                    "Anchor circuit breaker is open — RPC endpoint unavailable".into(),
                ),
                CircuitBreakerError::Timeout => {
                    SequencerError::Internal("Anchor operation timed out".into())
                }
            })?;

        info!(
            "VES commitment {} anchored in tx {} (block {})",
            batch_id_uuid,
            hex::encode(tx_hash),
            block_number.unwrap_or(0)
        );

        Ok((tx_hash, block_number))
    }

    /// Verify a commitment is anchored on-chain
    pub async fn verify_anchored(&self, batch_id: uuid::Uuid) -> Result<bool> {
        let provider = ProviderBuilder::new().connect_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
        );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        let batch_id_bytes = Self::uuid_to_bytes32(batch_id);
        let result = contract
            .batchExists(batch_id_bytes)
            .call()
            .await
            .map_err(|e| SequencerError::Internal(format!("Contract call failed: {}", e)))?;

        Ok(result)
    }

    /// Get the on-chain head sequence for a tenant/store
    pub async fn get_chain_head(&self, tenant_id: uuid::Uuid, store_id: uuid::Uuid) -> Result<u64> {
        let provider = ProviderBuilder::new().connect_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
        );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        let tenant_bytes = Self::uuid_to_bytes32(tenant_id);
        let store_bytes = Self::uuid_to_bytes32(store_id);

        let head = contract
            .getHeadSequence(tenant_bytes, store_bytes)
            .call()
            .await
            .map_err(|e| SequencerError::Internal(format!("Contract call failed: {}", e)))?;

        Ok(head)
    }

    /// Verify an events root against on-chain data
    pub async fn verify_events_root_onchain(
        &self,
        batch_id: uuid::Uuid,
        events_root: &Hash256,
    ) -> Result<bool> {
        let provider = ProviderBuilder::new().connect_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {}", e)))?,
        );

        let contract = IStateSetAnchor::new(self.config.registry_address, &provider);

        let batch_id_bytes = Self::uuid_to_bytes32(batch_id);
        let events_root_bytes = Self::to_bytes32(events_root);

        let onchain = contract
            .getBatchCommitment(batch_id_bytes)
            .call()
            .await
            .map_err(|e| SequencerError::Internal(format!("Contract call failed: {}", e)))?;

        // SetRegistry has no verifyEventsRoot; compare against the stored commitment.
        let stored = onchain;
        Ok(stored.timestamp != 0 && stored.eventsRoot == events_root_bytes)
    }

    /// Anchor a STARK batch proof on-chain with retry and circuit breaker protection
    pub async fn anchor_stark_batch_proof(
        &self,
        proof: &StarkBatchProof,
    ) -> Result<(Hash256, Option<u64>)> {
        info!(
            "Anchoring STARK batch proof {} to chain (sequences {}-{}, {} events, all_compliant={})",
            proof.batch_id, proof.sequence_start, proof.sequence_end, proof.event_count, proof.all_compliant
        );

        let config = &self.config;
        let registry_address = config.registry_address;
        let batch_id_uuid = proof.batch_id;
        let retry_config = self.retry_config.clone();

        let (tx_hash, block_number) = self
            .circuit_breaker
            .call(async {
                let retry = Retry::new(retry_config);
                let result = retry.run_with_predicate(
                    || {
                        let private_key = config.private_key.clone();
                        let rpc_url = config.rpc_url.clone();
                        let batch_id = Self::uuid_to_bytes32(proof.batch_id);
                        let tenant_id = Self::uuid_to_bytes32(proof.tenant_id.0);
                        let store_id = Self::uuid_to_bytes32(proof.store_id.0);
                        let events_root = Self::to_bytes32(&proof.events_root);
                        let prev_state_root = Self::to_bytes32(&proof.prev_state_root);
                        let new_state_root = Self::to_bytes32(&proof.new_state_root);
                        let proof_hash = Self::to_bytes32(&proof.proof_hash);
                        let policy_hash = Self::to_bytes32(&proof.policy_hash);
                        let seq_start = proof.sequence_start;
                        let seq_end = proof.sequence_end;
                        let event_count = proof.event_count;
                        let policy_limit = proof.policy_limit;
                        let all_compliant = proof.all_compliant;
                        let proof_size = proof.proof_size;
                        let proving_time_ms = proof.proving_time_ms;

                        async move {
                            let signer: PrivateKeySigner = private_key.parse()
                                .map_err(|e| SequencerError::Internal(format!("Invalid private key: {e}")))?;
                            let provider = ProviderBuilder::new()
                                .wallet(alloy::network::EthereumWallet::from(signer))
                                .connect_http(rpc_url.parse()
                                    .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {e}")))?);
                            let contract = IStateSetAnchor::new(registry_address, &provider);
                            let tx = contract.commitBatchWithStarkProof(
                                batch_id, tenant_id, store_id, events_root,
                                prev_state_root, new_state_root,
                                seq_start, seq_end, event_count,
                                proof_hash, policy_hash, policy_limit,
                                all_compliant, proof_size, proving_time_ms,
                            );
                            let pending = tx.send().await
                                .map_err(|e| SequencerError::Internal(format!("Failed to send transaction: {e}")))?;
                            let receipt = pending.get_receipt().await
                                .map_err(|e| SequencerError::Internal(format!("Failed to get receipt: {e}")))?;
                            Ok::<_, SequencerError>((receipt.transaction_hash.0, receipt.block_number))
                        }
                    },
                    is_retryable_anchor_error,
                ).await;

                if result.attempts > 1 {
                    warn!(batch_id = %batch_id_uuid, attempts = result.attempts, "STARK anchor succeeded after retries");
                }
                result.into_result()
            })
            .await
            .map_err(|e| match e {
                CircuitBreakerError::ServiceError(inner) => inner,
                CircuitBreakerError::CircuitOpen => SequencerError::Internal(
                    "Anchor circuit breaker is open — RPC endpoint unavailable".into(),
                ),
                CircuitBreakerError::Timeout => {
                    SequencerError::Internal("Anchor operation timed out".into())
                }
            })?;

        info!(
            "STARK batch proof {} anchored in tx {} (block {})",
            batch_id_uuid,
            hex::encode(tx_hash),
            block_number.unwrap_or(0)
        );

        Ok((tx_hash, block_number))
    }

    /// Check if a batch has a STARK proof on-chain
    pub async fn has_stark_proof_onchain(&self, batch_id: uuid::Uuid) -> Result<bool> {
        let provider = ProviderBuilder::new().connect_http(
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

        Ok(result)
    }

    /// Verify a STARK proof hash matches on-chain
    pub async fn verify_stark_proof_hash_onchain(
        &self,
        batch_id: uuid::Uuid,
        proof_hash: &Hash256,
    ) -> Result<bool> {
        let provider = ProviderBuilder::new().connect_http(
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

        Ok(valid)
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

    #[test]
    fn anchor_config_debug_redacts_credentials() {
        let config = AnchorConfig {
            rpc_url: "https://user:rpc-secret@example.invalid/key?token=secret".to_string(),
            registry_address: Address::ZERO,
            private_key: "private-key-secret".to_string(),
            chain_id: 1,
        };

        let debug = format!("{config:?}");
        assert!(!debug.contains("rpc-secret"));
        assert!(!debug.contains("private-key-secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    #[serial_test::serial]
    fn anchor_config_rejects_partial_configuration() {
        for name in [
            "L2_RPC_URL",
            "SET_REGISTRY_ADDRESS",
            "SEQUENCER_PRIVATE_KEY",
        ] {
            std::env::remove_var(name);
        }
        std::env::set_var("L2_RPC_URL", "https://rpc.example.invalid");

        let err = AnchorConfig::from_env()
            .expect_err("partial anchoring configuration must not silently disable the worker");
        assert!(err.to_string().contains("SET_REGISTRY_ADDRESS"));

        std::env::remove_var("L2_RPC_URL");
    }
}
