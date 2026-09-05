//! Background x402 Settlement Worker
//!
//! Autonomously settles committed x402 payment batches on-chain via the
//! `SetPaymentBatch` contract. This is the default settlement path when a
//! [`SettlementService`] is configured; `POST /api/v1/x402/batches/settle`
//! remains available as the manual / override path.
//!
//! The worker:
//!
//! 1. Polls for committed batches that carry at least one on-chain-authorized
//!    payment ([`PgX402Repository::list_settleable_batches`]).
//! 2. Filters to batches whose `network` matches the chain the settler's wallet
//!    and contract are bound to.
//! 3. Loads each batch's payments, builds `PaymentIntent[]` calldata (including
//!    `validAfter` + the payer EIP-712 authorization), and calls `settleBatch`.
//! 4. Records the REAL tx hash + block number and marks the batch settled,
//!    marking any payment the chain reported as `PaymentFailed` as `failed`.
//!
//! It is leader-elected via the shared advisory-lock election (see
//! `server.rs` / [`crate::infra::spawn_elected_worker`]) to coordinate workers
//! during normal operation, and it is config-gated OFF BY DEFAULT (only runs when
//! [`crate::settlement::SettlementConfig::from_env`] returns `Ok(Some(_))`).
//!
//! ## Crash & double-settle safety
//!
//! A batch must never settle twice. The destination contract and reconciliation
//! provide duplicate protection; leader election alone is not fencing:
//!
//! - **Leader election** — reduces concurrent work, but a partitioned former
//!   leader may still reach the chain before detecting loss of its database lease.
//! - **On-chain contract** — `settleBatch` reverts `BatchAlreadySettled` for a
//!   `batchId` whose `settledAt != 0`, and `settledIntents[intentId]` blocks any
//!   individual payment from moving funds twice (even across batches).
//! - **Idempotent local recording** — the batch only transitions
//!   `committed`/`submitted` → `settled`; a crash between sending the tx and
//!   recording it leaves the batch `committed`, so it is re-selected next tick,
//!   and [`SettlementService::settle_batch`] detects the existing on-chain
//!   settlement (`getBatch`) and reconciles instead of re-sending.
//!
//! # Configuration
//!
//! - `SETTLEMENT_INTERVAL_SECS` — how often to poll for settleable batches (default: 60)
//! - `SETTLEMENT_BATCH_THRESHOLD` — max batches to settle per tick (default: 10)

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::infra::PgX402Repository;
use crate::settlement::SettlementService;

const SETTLEMENT_DEFAULT_INTERVAL_SECS: u64 = 60;
const SETTLEMENT_DEFAULT_BATCH_THRESHOLD: i64 = 10;
const SETTLEMENT_MIN_INTERVAL_SECS: u64 = 5;

/// Configuration for the settlement worker.
#[derive(Debug, Clone)]
pub struct SettlementWorkerConfig {
    /// How often to check for settleable batches.
    pub settle_interval: Duration,
    /// Max batches to settle per tick.
    pub batch_threshold: i64,
}

impl Default for SettlementWorkerConfig {
    fn default() -> Self {
        Self {
            settle_interval: Duration::from_secs(SETTLEMENT_DEFAULT_INTERVAL_SECS),
            batch_threshold: SETTLEMENT_DEFAULT_BATCH_THRESHOLD,
        }
    }
}

impl SettlementWorkerConfig {
    /// Load configuration from environment.
    pub fn from_env() -> Self {
        let settle_interval = std::env::var("SETTLEMENT_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|secs| secs.max(SETTLEMENT_MIN_INTERVAL_SECS))
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(SETTLEMENT_DEFAULT_INTERVAL_SECS));

        let batch_threshold = std::env::var("SETTLEMENT_BATCH_THRESHOLD")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(SETTLEMENT_DEFAULT_BATCH_THRESHOLD);

        Self {
            settle_interval,
            batch_threshold,
        }
    }
}

/// Control messages for the settlement worker.
#[derive(Debug)]
pub enum SettlementWorkerMessage {
    /// Force a settlement sweep of all settleable batches.
    ForceSettle,
    /// Shutdown the worker.
    Shutdown,
}

/// Background settlement worker.
pub struct SettlementWorker {
    config: SettlementWorkerConfig,
    settlement_service: Arc<SettlementService>,
    repository: Arc<PgX402Repository>,
    control_tx: mpsc::Sender<SettlementWorkerMessage>,
    control_rx: mpsc::Receiver<SettlementWorkerMessage>,
}

impl SettlementWorker {
    /// Create a new settlement worker.
    pub fn new(
        config: SettlementWorkerConfig,
        settlement_service: Arc<SettlementService>,
        repository: Arc<PgX402Repository>,
    ) -> Self {
        let (control_tx, control_rx) = mpsc::channel(16);
        Self {
            config,
            settlement_service,
            repository,
            control_tx,
            control_rx,
        }
    }

    /// Get a sender handle for controlling the worker.
    pub fn control_handle(&self) -> mpsc::Sender<SettlementWorkerMessage> {
        self.control_tx.clone()
    }

    /// Run the settlement worker main loop.
    pub async fn run(mut self) {
        info!(
            settle_interval_secs = self.config.settle_interval.as_secs(),
            batch_threshold = self.config.batch_threshold,
            chain_id = self.settlement_service.chain_id(),
            "Starting x402 settlement worker"
        );

        let mut ticker = interval(self.config.settle_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.process_pending_settlements().await {
                        error!(error = %e, "Error processing pending settlements");
                    }
                }
                Some(msg) = self.control_rx.recv() => {
                    match msg {
                        SettlementWorkerMessage::ForceSettle => {
                            info!("Force-settling committed batches");
                            if let Err(e) = self.process_pending_settlements().await {
                                error!(error = %e, "Error during forced settlement");
                            }
                        }
                        SettlementWorkerMessage::Shutdown => {
                            info!("Settlement worker shutting down");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Settle all committed, on-chain-authorized batches for this chain.
    async fn process_pending_settlements(&self) -> Result<(), String> {
        debug!("Checking for settleable x402 batches");

        let batches = self
            .repository
            .list_settleable_batches(self.config.batch_threshold)
            .await
            .map_err(|e| format!("Failed to list settleable batches: {e}"))?;

        if batches.is_empty() {
            debug!("No settleable batches");
            return Ok(());
        }

        let target_chain = self.settlement_service.chain_id();

        for batch in &batches {
            // Only settle batches destined for the chain this settler is bound
            // to. Other-network committed batches are left for a settler
            // configured for their chain.
            if batch.network.chain_id() != target_chain {
                debug!(
                    batch_id = %batch.batch_id,
                    network = %batch.network,
                    "Skipping batch: network does not match settler chain"
                );
                continue;
            }

            let intents = match self.repository.get_intents_by_batch(batch.batch_id).await {
                Ok(intents) => intents,
                Err(e) => {
                    warn!(batch_id = %batch.batch_id, error = %e, "Failed to load batch intents");
                    continue;
                }
            };

            if intents.is_empty() {
                warn!(batch_id = %batch.batch_id, "Settleable batch has no intents; skipping");
                continue;
            }

            match self.settlement_service.settle_batch(batch, &intents).await {
                Ok(outcome) => {
                    let tx_hex = format!("0x{}", hex::encode(outcome.tx_hash));
                    let block = outcome.block_number.unwrap_or(0);

                    if let Err(e) = self
                        .repository
                        .settle_batch_with_results(
                            batch.batch_id,
                            &tx_hex,
                            block,
                            outcome.gas_used,
                            &outcome.failed_ids,
                        )
                        .await
                    {
                        error!(
                            batch_id = %batch.batch_id,
                            error = %e,
                            "Settled on-chain but failed to record settlement locally; will reconcile next tick"
                        );
                    } else {
                        info!(
                            batch_id = %batch.batch_id,
                            settled = outcome.settled_ids.len(),
                            failed = outcome.failed_ids.len(),
                            already_settled = outcome.already_settled,
                            block_number = block,
                            "x402 batch settlement recorded"
                        );
                    }
                }
                Err(e) => {
                    warn!(batch_id = %batch.batch_id, error = %e, "Failed to settle batch on-chain");
                }
            }
        }

        Ok(())
    }
}

/// Spawn the settlement worker as a background task.
pub fn spawn_settlement_worker(
    config: SettlementWorkerConfig,
    settlement_service: Arc<SettlementService>,
    repository: Arc<PgX402Repository>,
) -> (
    tokio::task::JoinHandle<()>,
    mpsc::Sender<SettlementWorkerMessage>,
) {
    let worker = SettlementWorker::new(config, settlement_service, repository);
    let control_handle = worker.control_handle();
    let handle = tokio::spawn(worker.run());
    (handle, control_handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = SettlementWorkerConfig::default();
        assert_eq!(config.settle_interval, Duration::from_secs(60));
        assert_eq!(config.batch_threshold, 10);
    }

    #[test]
    fn test_config_from_env_enforces_min_interval() {
        std::env::set_var("SETTLEMENT_INTERVAL_SECS", "1");
        let config = SettlementWorkerConfig::from_env();
        assert!(config.settle_interval >= Duration::from_secs(SETTLEMENT_MIN_INTERVAL_SECS));
        std::env::remove_var("SETTLEMENT_INTERVAL_SECS");
    }
}
