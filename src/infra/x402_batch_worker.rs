//! x402 Batch Worker Service
//!
//! Background service that periodically batches pending x402 payment intents.
//! This service:
//!
//! 1. Polls for sequenced intents ready for batching
//! 2. Creates batches when threshold is reached or timeout expires
//! 3. Computes Merkle roots and commits batches
//! 4. Optionally triggers L2 settlement
//!
//! # Configuration
//!
//! - `X402_BATCH_INTERVAL_SECS` - How often to check for pending intents (default: 30)
//! - `X402_BATCH_MIN_SIZE` - Minimum intents before batching (default: 1)
//! - `X402_BATCH_MAX_SIZE` - Maximum intents per batch (default: 100)
//! - `X402_BATCH_MAX_WAIT_SECS` - Max time to wait before batching (default: 300)

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::domain::{StoreId, TenantId, X402Network, X402PaymentBatch};
use crate::infra::PgX402Repository;

/// Configuration for the x402 batch worker
#[derive(Debug, Clone)]
pub struct X402BatchWorkerConfig {
    /// How often to check for pending intents
    pub batch_interval: Duration,
    /// Minimum intents before creating a batch
    pub min_batch_size: usize,
    /// Maximum intents per batch
    pub max_batch_size: usize,
    /// Maximum time to wait before batching (even if below min_size)
    pub max_wait_time: Duration,
    /// Networks to process
    pub networks: Vec<X402Network>,
    /// Whether to auto-commit batches (compute Merkle root)
    pub auto_commit: bool,
}

impl Default for X402BatchWorkerConfig {
    fn default() -> Self {
        Self {
            batch_interval: Duration::from_secs(30),
            min_batch_size: 1,
            max_batch_size: 100,
            max_wait_time: Duration::from_secs(300),
            networks: vec![X402Network::SetChain],
            auto_commit: true,
        }
    }
}

impl X402BatchWorkerConfig {
    /// Load configuration from environment
    pub fn from_env() -> Self {
        let batch_interval = std::env::var("X402_BATCH_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));

        let min_batch_size = std::env::var("X402_BATCH_MIN_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let max_batch_size = std::env::var("X402_BATCH_MAX_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let max_wait_time = std::env::var("X402_BATCH_MAX_WAIT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(300));

        let auto_commit = std::env::var("X402_BATCH_AUTO_COMMIT")
            .ok()
            .map(|s| s == "true" || s == "1")
            .unwrap_or(true);

        Self {
            batch_interval,
            min_batch_size,
            max_batch_size,
            max_wait_time,
            networks: vec![X402Network::SetChain],
            auto_commit,
        }
    }
}

/// Message types for batch worker control
#[derive(Debug)]
pub enum BatchWorkerMessage {
    /// Force batch creation for a tenant/store
    ForceBatch {
        tenant_id: TenantId,
        store_id: StoreId,
        network: X402Network,
    },
    /// Shutdown the worker
    Shutdown,
}

/// Result of a batching operation
#[derive(Debug)]
pub struct BatchResult {
    pub batch_id: Uuid,
    pub payment_count: u32,
    pub merkle_root: Option<String>,
    pub committed: bool,
}

/// x402 Batch Worker
///
/// Runs as a background task to periodically batch payment intents.
pub struct X402BatchWorker {
    config: X402BatchWorkerConfig,
    repository: Arc<PgX402Repository>,
    control_tx: mpsc::Sender<BatchWorkerMessage>,
    control_rx: mpsc::Receiver<BatchWorkerMessage>,
}

impl X402BatchWorker {
    /// Create a new batch worker
    pub fn new(config: X402BatchWorkerConfig, repository: Arc<PgX402Repository>) -> Self {
        let (control_tx, control_rx) = mpsc::channel(16);
        Self {
            config,
            repository,
            control_tx,
            control_rx,
        }
    }

    /// Get a sender handle for controlling the worker
    pub fn control_handle(&self) -> mpsc::Sender<BatchWorkerMessage> {
        self.control_tx.clone()
    }

    /// Run the batch worker
    pub async fn run(mut self) {
        info!(
            interval_secs = ?self.config.batch_interval.as_secs(),
            min_size = self.config.min_batch_size,
            max_size = self.config.max_batch_size,
            "Starting x402 batch worker"
        );

        let mut ticker = interval(self.config.batch_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.process_pending_batches().await {
                        error!(error = ?e, "Error processing pending batches");
                    }
                }
                Some(msg) = self.control_rx.recv() => {
                    match msg {
                        BatchWorkerMessage::ForceBatch { tenant_id, store_id, network } => {
                            info!(
                                tenant_id = %tenant_id.0,
                                store_id = %store_id.0,
                                network = ?network,
                                "Forcing batch creation"
                            );
                            if let Err(e) = self.create_batch_for_tenant(&tenant_id, &store_id, network).await {
                                error!(error = ?e, "Error creating forced batch");
                            }
                        }
                        BatchWorkerMessage::Shutdown => {
                            info!("x402 batch worker shutting down");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Process all pending batches across tenants
    async fn process_pending_batches(&self) -> Result<(), String> {
        debug!("Checking for pending payment intents to batch");

        // Get list of tenant/store combinations with pending intents
        let pending_streams = self.get_pending_streams().await?;

        for (tenant_id, store_id, network) in pending_streams {
            if let Err(e) = self
                .create_batch_for_tenant(&tenant_id, &store_id, network)
                .await
            {
                warn!(
                    tenant_id = %tenant_id.0,
                    store_id = %store_id.0,
                    error = ?e,
                    "Failed to create batch"
                );
            }
        }

        Ok(())
    }

    /// Get list of tenant/store combinations with pending intents
    async fn get_pending_streams(
        &self,
    ) -> Result<Vec<(TenantId, StoreId, X402Network)>, String> {
        // Query database for distinct tenant/store/network with pending intents
        // For now, we'll need to query this from the database
        // This is a simplified version - in production you'd want a more efficient query

        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            r#"
            SELECT DISTINCT tenant_id, store_id, network
            FROM x402_payment_intents
            WHERE status = 'sequenced'
            "#,
        )
        .fetch_all(self.repository.pool())
        .await
        .map_err(|e| e.to_string())?;

        Ok(rows
            .into_iter()
            .filter_map(|(tenant_id, store_id, network)| {
                let network = match network.as_str() {
                    "set_chain" => X402Network::SetChain,
                    "set_chain_testnet" => X402Network::SetChainTestnet,
                    "arc" => X402Network::Arc,
                    "arc_testnet" => X402Network::ArcTestnet,
                    "base" => X402Network::Base,
                    "base_sepolia" => X402Network::BaseSepolia,
                    "ethereum" => X402Network::Ethereum,
                    "ethereum_sepolia" => X402Network::EthereumSepolia,
                    "arbitrum" => X402Network::Arbitrum,
                    "optimism" => X402Network::Optimism,
                    _ => return None,
                };
                Some((
                    TenantId::from_uuid(tenant_id),
                    StoreId::from_uuid(store_id),
                    network,
                ))
            })
            .collect())
    }

    /// Create a batch for a specific tenant/store/network
    async fn create_batch_for_tenant(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        network: X402Network,
    ) -> Result<Option<BatchResult>, String> {
        // Fetch pending intents
        let intents = self
            .repository
            .get_pending_intents_for_batch(
                tenant_id,
                store_id,
                network,
                self.config.max_batch_size as u32,
            )
            .await
            .map_err(|e| e.to_string())?;

        // Check if we have enough intents
        if intents.is_empty() {
            debug!(
                tenant_id = %tenant_id.0,
                store_id = %store_id.0,
                "No pending intents to batch"
            );
            return Ok(None);
        }

        // Check minimum batch size (unless we've waited too long)
        if intents.len() < self.config.min_batch_size {
            // Check if oldest intent has waited too long
            let oldest_created = intents
                .iter()
                .filter_map(|i| i.sequenced_at)
                .min();

            if let Some(oldest) = oldest_created {
                let wait_time = Utc::now().signed_duration_since(oldest);
                if wait_time.num_seconds() < self.config.max_wait_time.as_secs() as i64 {
                    debug!(
                        tenant_id = %tenant_id.0,
                        intent_count = intents.len(),
                        min_size = self.config.min_batch_size,
                        "Not enough intents for batch, waiting"
                    );
                    return Ok(None);
                }
            }
        }

        info!(
            tenant_id = %tenant_id.0,
            store_id = %store_id.0,
            network = ?network,
            intent_count = intents.len(),
            "Creating payment batch"
        );

        // Create batch
        let mut batch = X402PaymentBatch::new(tenant_id.clone(), store_id.clone(), network);

        for intent in &intents {
            batch.add_payment(intent);
        }

        // Persist batch
        self.repository
            .insert_batch(&batch)
            .await
            .map_err(|e| e.to_string())?;

        // Update intents to batched status
        let intent_ids: Vec<Uuid> = intents.iter().map(|i| i.intent_id).collect();
        for intent_id in &intent_ids {
            self.repository
                .update_intent_batch(*intent_id, batch.batch_id)
                .await
                .map_err(|e| e.to_string())?;
        }

        let mut result = BatchResult {
            batch_id: batch.batch_id,
            payment_count: batch.payment_count,
            merkle_root: None,
            committed: false,
        };

        // Auto-commit if enabled
        if self.config.auto_commit {
            match self
                .repository
                .commit_batch_with_merkle(batch.batch_id, tenant_id, store_id)
                .await
            {
                Ok((merkle_root, _state_root)) => {
                    result.merkle_root = Some(format!("0x{}", hex::encode(merkle_root)));
                    result.committed = true;
                    info!(
                        batch_id = %batch.batch_id,
                        merkle_root = %result.merkle_root.as_ref().unwrap(),
                        "Batch committed with Merkle root"
                    );
                }
                Err(e) => {
                    warn!(
                        batch_id = %batch.batch_id,
                        error = ?e,
                        "Failed to commit batch"
                    );
                }
            }
        }

        Ok(Some(result))
    }
}


/// Spawn the batch worker as a background task
pub fn spawn_batch_worker(
    config: X402BatchWorkerConfig,
    repository: Arc<PgX402Repository>,
) -> (
    tokio::task::JoinHandle<()>,
    mpsc::Sender<BatchWorkerMessage>,
) {
    let worker = X402BatchWorker::new(config, repository);
    let control_handle = worker.control_handle();
    let handle = tokio::spawn(worker.run());
    (handle, control_handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = X402BatchWorkerConfig::default();
        assert_eq!(config.batch_interval, Duration::from_secs(30));
        assert_eq!(config.min_batch_size, 1);
        assert_eq!(config.max_batch_size, 100);
        assert!(config.auto_commit);
    }
}
