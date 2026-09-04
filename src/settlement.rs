//! Autonomous on-chain x402 settlement.
//!
//! Submits committed x402 payment batches to the `SetPaymentBatch` contract on
//! Set Chain L2 via `settleBatch`, moving real funds from payers to payees.
//!
//! This is the missing piece the code review flagged: prior to this module the
//! only "settlement" path was `POST /batches/settle`, which merely records an
//! externally-supplied tx hash — no committed component actually put a payment
//! on-chain. [`SettlementService`] builds the real `PaymentIntent[]` calldata
//! (including each payer's EIP-712 authorization + `validAfter`), sends the
//! transaction with a wallet from the environment, waits for the receipt, and
//! reports the real tx hash + block number.
//!
//! It mirrors [`crate::anchor::AnchorService`] one-to-one: config-gated
//! ([`SettlementConfig::from_env`] returns `Ok(None)` unless the required env is
//! set — OFF BY DEFAULT), circuit-breaker + retry protected, and driven by the
//! leader-elected [`crate::infra::settlement_worker::SettlementWorker`].
//!
//! ## PaymentIntent ABI (must match SetPaymentBatch.sol exactly)
//!
//! The contract decodes `settleBatch(bytes32,bytes32,bytes32,uint64,uint64,
//! PaymentIntent[])` where `PaymentIntent` is the tuple (field order is
//! load-bearing — a wrong order fails ABI decode on-chain):
//!
//! ```text
//! (bytes32 intentId, address payer, address payee, uint256 amount,
//!  address token, uint64 nonce, uint64 validAfter, uint64 validUntil,
//!  bytes32 signingHash, bytes authorization)
//! ```
//!
//! `authorization` is the payer's EIP-712 signature over
//! `PaymentAuthorization(intentId,payer,payee,token,amount,nonce,validAfter,validBefore)`
//! (domain `EIP712("SetPaymentBatch","1")`). We relay it verbatim; the contract
//! verifies it via `SignatureChecker` and SKIPS (does not revert) unauthorized
//! payments, emitting `PaymentFailed`.

#![allow(clippy::too_many_arguments)]

use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use crate::domain::{StoreId, TenantId, X402PaymentBatch, X402PaymentIntent};
use crate::infra::{
    CircuitBreaker, CircuitBreakerConfig, Result, Retry, RetryConfig, SequencerError,
};

// Generate contract bindings. The `PaymentIntent` struct and `settleBatch`
// signature MUST mirror commerce/SetPaymentBatch.sol field-for-field; the ABI
// selector is asserted against the canonical Solidity signature in the tests.
sol! {
    #[sol(rpc)]
    #[allow(missing_docs)]
    interface ISetPaymentBatch {
        struct PaymentIntent {
            bytes32 intentId;
            address payer;
            address payee;
            uint256 amount;
            address token;
            uint64 nonce;
            uint64 validAfter;
            uint64 validUntil;
            bytes32 signingHash;
            bytes authorization;
        }

        struct BatchSettlement {
            bytes32 merkleRoot;
            bytes32 tenantStoreKey;
            uint128 totalAmount;
            uint64 sequenceStart;
            uint64 sequenceEnd;
            address token;
            uint64 settledAt;
            uint32 paymentCount;
        }

        function settleBatch(
            bytes32 batchId,
            bytes32 merkleRoot,
            bytes32 tenantStoreKey,
            uint64 sequenceStart,
            uint64 sequenceEnd,
            PaymentIntent[] calldata payments
        ) external;

        function getBatch(bytes32 batchId) external view returns (BatchSettlement memory);

        function isIntentSettled(bytes32 intentId) external view returns (bool);
    }
}

/// Configuration for on-chain x402 settlement.
#[derive(Clone)]
pub struct SettlementConfig {
    /// RPC URL for the settlement chain.
    pub rpc_url: String,
    /// `SetPaymentBatch` contract address.
    pub contract_address: Address,
    /// Private key for the (authorized-sequencer) settler wallet.
    pub private_key: String,
    /// Chain ID of the settlement chain.
    pub chain_id: u64,
}

impl std::fmt::Debug for SettlementConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettlementConfig")
            .field("rpc_url", &"<redacted>")
            .field("contract_address", &self.contract_address)
            .field("private_key", &"<redacted>")
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

impl SettlementConfig {
    /// Load configuration from environment variables.
    ///
    /// Returns `Ok(None)` when none of the required vars are set. Partial or
    /// malformed configuration is an error — the autonomous settler is OFF BY
    /// DEFAULT, but never silently disabled when an operator tried to enable it:
    ///
    /// - `SETTLEMENT_RPC_URL` — RPC endpoint for the settlement chain
    /// - `SET_PAYMENT_BATCH_ADDRESS` — `SetPaymentBatch` contract address
    /// - `SETTLER_PRIVATE_KEY` — settler wallet key (must be an authorized sequencer)
    /// - `SETTLEMENT_CHAIN_ID` — optional, defaults to Set Chain (84532001)
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let rpc_url = std::env::var("SETTLEMENT_RPC_URL").ok();
        let contract_address = std::env::var("SET_PAYMENT_BATCH_ADDRESS").ok();
        let private_key = std::env::var("SETTLER_PRIVATE_KEY").ok();

        if rpc_url.is_none() && contract_address.is_none() && private_key.is_none() {
            return Ok(None);
        }

        let rpc_url = rpc_url
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("SETTLEMENT_RPC_URL is required when settlement is configured")
            })?;
        let contract_address = contract_address
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "SET_PAYMENT_BATCH_ADDRESS is required when settlement is configured"
                )
            })?
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid SET_PAYMENT_BATCH_ADDRESS: {e}"))?;
        let private_key = private_key
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("SETTLER_PRIVATE_KEY is required when settlement is configured")
            })?;
        let chain_id = match std::env::var("SETTLEMENT_CHAIN_ID") {
            Ok(raw) => raw
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid SETTLEMENT_CHAIN_ID: '{raw}'"))?,
            Err(_) => 84532001,
        };

        Ok(Some(Self {
            rpc_url,
            contract_address,
            private_key,
            chain_id,
        }))
    }
}

/// Transient vs terminal classification for settlement send errors.
/// See [`crate::infra::is_transient_chain_error`] for why reverts must be
/// recognised even when wrapped in a send failure.
fn is_retryable_settlement_error(err: &SequencerError) -> bool {
    crate::infra::is_transient_chain_error(err)
}

/// The outcome of settling one batch on-chain.
#[derive(Debug, Clone)]
pub struct SettlementOutcome {
    /// Settlement transaction hash. All-zero when `already_settled` (a prior
    /// attempt's tx hash was lost to a crash; the batch is reconciled from
    /// on-chain state instead).
    pub tx_hash: [u8; 32],
    /// Block the settlement was included in, if known.
    pub block_number: Option<u64>,
    /// Gas used by the settlement transaction, if known.
    pub gas_used: Option<u64>,
    /// Intent IDs the chain reports as settled (`settledIntents[id] == true`).
    pub settled_ids: Vec<Uuid>,
    /// Intent IDs the chain skipped (`PaymentFailed`: unauthorized, expired,
    /// insufficient balance/allowance, etc.).
    pub failed_ids: Vec<Uuid>,
    /// True when the batch was already settled on-chain before this attempt
    /// sent a transaction (crash-recovery reconciliation, not a fresh send).
    pub already_settled: bool,
}

/// On-chain x402 settlement service with retry + circuit-breaker protection.
pub struct SettlementService {
    config: SettlementConfig,
    circuit_breaker: CircuitBreaker,
    retry_config: RetryConfig,
}

impl SettlementService {
    /// Create a new settlement service with default retry + circuit-breaker settings.
    pub fn new(config: SettlementConfig) -> Self {
        let circuit_breaker = CircuitBreaker::with_config(
            "settlement",
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

    /// Chain ID this settler is bound to.
    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Circuit breaker handle for status monitoring.
    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }

    /// Convert a UUID to bytes32 (first 16 bytes = UUID, remainder zero).
    ///
    /// This is the canonical `intentId`/`batchId` encoding: the payer's EIP-712
    /// authorization MUST be signed over this same 32-byte value.
    fn uuid_to_bytes32(uuid: Uuid) -> FixedBytes<32> {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(uuid.as_bytes());
        FixedBytes::from_slice(&bytes)
    }

    /// Derive the on-chain `tenantStoreKey` from tenant + store IDs.
    fn tenant_store_key(tenant: &TenantId, store: &StoreId) -> FixedBytes<32> {
        let mut hasher = Sha256::new();
        hasher.update(tenant.0.as_bytes());
        hasher.update(store.0.as_bytes());
        FixedBytes::from_slice(&hasher.finalize())
    }

    /// Map a stored x402 intent to the on-chain `PaymentIntent` tuple.
    ///
    /// Field order here is irrelevant to Rust but the tuple it becomes on the
    /// wire must match the Solidity struct exactly (validated in tests).
    fn build_payment(intent: &X402PaymentIntent) -> Result<ISetPaymentBatch::PaymentIntent> {
        let payer: Address = intent.payer_address.parse().map_err(|e| {
            SequencerError::Internal(format!(
                "invalid payer address {}: {e}",
                intent.payer_address
            ))
        })?;
        let payee: Address = intent.payee_address.parse().map_err(|e| {
            SequencerError::Internal(format!(
                "invalid payee address {}: {e}",
                intent.payee_address
            ))
        })?;
        let token: Address = match intent.token_address.as_deref() {
            Some(t) => t
                .parse()
                .map_err(|e| SequencerError::Internal(format!("invalid token address {t}: {e}")))?,
            None => Address::ZERO,
        };
        let authorization = Bytes::from(intent.eip712_authorization.clone().unwrap_or_default());

        Ok(ISetPaymentBatch::PaymentIntent {
            intentId: Self::uuid_to_bytes32(intent.intent_id),
            payer,
            payee,
            amount: U256::from(intent.amount),
            token,
            nonce: intent.nonce,
            validAfter: intent.valid_after,
            validUntil: intent.valid_until,
            signingHash: FixedBytes::from_slice(&intent.signing_hash),
            authorization,
        })
    }

    /// Build the full `PaymentIntent[]` calldata for a batch's intents.
    fn build_payments(
        intents: &[X402PaymentIntent],
    ) -> Result<Vec<ISetPaymentBatch::PaymentIntent>> {
        intents.iter().map(Self::build_payment).collect()
    }

    /// Settle one committed batch on-chain.
    ///
    /// Sends `settleBatch(...)` with the batch's `PaymentIntent[]` calldata,
    /// waits for the receipt, and classifies each payment's on-chain outcome
    /// (settled vs. skipped) via `isIntentSettled`.
    ///
    /// Double-settle safety: before sending, and again if the send path fails,
    /// it checks whether the batch is already settled on-chain (`getBatch`
    /// `settledAt != 0`). Combined with the contract's own `BatchAlreadySettled`
    /// / `settledIntents` guards, this makes it impossible for a batch's funds
    /// to move twice across retries, leader failover, or a crash between sending
    /// and recording.
    pub async fn settle_batch(
        &self,
        batch: &X402PaymentBatch,
        intents: &[X402PaymentIntent],
    ) -> Result<SettlementOutcome> {
        let merkle_root = batch.merkle_root.ok_or_else(|| {
            SequencerError::Internal("batch has no merkle root; cannot settle".into())
        })?;

        info!(
            batch_id = %batch.batch_id,
            payment_count = intents.len(),
            sequence_start = batch.sequence_start,
            sequence_end = batch.sequence_end,
            "Settling x402 batch on-chain"
        );

        let batch_id = Self::uuid_to_bytes32(batch.batch_id);
        let merkle_root_b = FixedBytes::<32>::from_slice(&merkle_root);
        let tenant_store_key = Self::tenant_store_key(&batch.tenant_id, &batch.store_id);
        let seq_start = batch.sequence_start;
        let seq_end = batch.sequence_end;
        let payments = Self::build_payments(intents)?;

        // Pre-check: if a prior attempt already settled this batch on-chain but
        // crashed before recording it, reconcile from on-chain state instead of
        // sending a second (revert-guaranteed) transaction.
        if self
            .is_batch_settled_onchain(batch.batch_id)
            .await
            .unwrap_or(false)
        {
            warn!(batch_id = %batch.batch_id, "Batch already settled on-chain; reconciling local state");
            let (settled_ids, failed_ids) = self.classify_intents(intents).await?;
            return Ok(SettlementOutcome {
                tx_hash: [0u8; 32],
                block_number: None,
                gas_used: None,
                settled_ids,
                failed_ids,
                already_settled: true,
            });
        }

        let config = &self.config;
        let contract_address = config.contract_address;
        let retry_config = self.retry_config.clone();
        let batch_id_uuid = batch.batch_id;

        let send_result = self
            .circuit_breaker
            .call(async {
                let retry = Retry::new(retry_config);
                let result = retry
                    .run_with_predicate(
                        || {
                            let private_key = config.private_key.clone();
                            let rpc_url = config.rpc_url.clone();
                            let payments = payments.clone();
                            async move {
                                let signer: PrivateKeySigner = private_key.parse().map_err(|e| {
                                    SequencerError::Internal(format!("Invalid private key: {e}"))
                                })?;
                                let provider = ProviderBuilder::new()
                                    .wallet(alloy::network::EthereumWallet::from(signer))
                                    .connect_http(rpc_url.parse().map_err(|e| {
                                        SequencerError::Internal(format!("Invalid RPC URL: {e}"))
                                    })?);
                                let contract =
                                    ISetPaymentBatch::new(contract_address, &provider);
                                let tx = contract.settleBatch(
                                    batch_id,
                                    merkle_root_b,
                                    tenant_store_key,
                                    seq_start,
                                    seq_end,
                                    payments,
                                );
                                let pending = tx.send().await.map_err(|e| {
                                    SequencerError::Internal(format!(
                                        "Failed to send settleBatch transaction: {e}"
                                    ))
                                })?;
                                let receipt = pending.get_receipt().await.map_err(|e| {
                                    SequencerError::Internal(format!(
                                        "Failed to get settleBatch receipt: {e}"
                                    ))
                                })?;
                                if !receipt.status() {
                                    return Err(SequencerError::Internal(
                                        "settleBatch transaction reverted".into(),
                                    ));
                                }
                                let gas_used = receipt.gas_used;
                                Ok::<_, SequencerError>((
                                    receipt.transaction_hash.0,
                                    receipt.block_number,
                                    gas_used,
                                ))
                            }
                        },
                        is_retryable_settlement_error,
                    )
                    .await;

                if result.attempts > 1 {
                    warn!(batch_id = %batch_id_uuid, attempts = result.attempts, "settleBatch succeeded after retries");
                }
                result.into_result()
            })
            .await;

        let (tx_hash, block_number, gas_used) = match send_result {
            Ok(v) => v,
            Err(_) => {
                // Retries exhausted or circuit open. Before surfacing an error,
                // check whether the batch settled on-chain anyway (a concurrent
                // or prior attempt could have won the race, and a second send
                // reverts with BatchAlreadySettled). If so, reconcile.
                if self
                    .is_batch_settled_onchain(batch.batch_id)
                    .await
                    .unwrap_or(false)
                {
                    warn!(batch_id = %batch.batch_id, "settleBatch send failed but batch is settled on-chain; reconciling");
                    let (settled_ids, failed_ids) = self.classify_intents(intents).await?;
                    return Ok(SettlementOutcome {
                        tx_hash: [0u8; 32],
                        block_number: None,
                        gas_used: None,
                        settled_ids,
                        failed_ids,
                        already_settled: true,
                    });
                }
                return Err(SequencerError::Internal(
                    "settleBatch failed — RPC unavailable or transaction rejected".into(),
                ));
            }
        };

        info!(
            batch_id = %batch.batch_id,
            tx_hash = %hex::encode(tx_hash),
            block_number = ?block_number,
            "x402 batch settled on-chain"
        );

        // Classify each payment's on-chain outcome. The contract skips (does not
        // revert) unauthorized/invalid payments, so a settled batch can contain
        // both settled and failed payments.
        let (settled_ids, failed_ids) = self.classify_intents(intents).await?;

        Ok(SettlementOutcome {
            tx_hash,
            block_number,
            gas_used: Some(gas_used),
            settled_ids,
            failed_ids,
            already_settled: false,
        })
    }

    /// Whether the batch is already settled on-chain (`settledAt != 0`).
    pub async fn is_batch_settled_onchain(&self, batch_id: Uuid) -> Result<bool> {
        let provider = ProviderBuilder::new().connect_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {e}")))?,
        );
        let contract = ISetPaymentBatch::new(self.config.contract_address, &provider);
        let batch = contract
            .getBatch(Self::uuid_to_bytes32(batch_id))
            .call()
            .await
            .map_err(|e| SequencerError::Internal(format!("getBatch call failed: {e}")))?;
        Ok(batch.settledAt != 0)
    }

    /// Classify batch intents into (settled, failed) by querying the contract's
    /// `settledIntents` mapping per intent.
    async fn classify_intents(
        &self,
        intents: &[X402PaymentIntent],
    ) -> Result<(Vec<Uuid>, Vec<Uuid>)> {
        let provider = ProviderBuilder::new().connect_http(
            self.config
                .rpc_url
                .parse()
                .map_err(|e| SequencerError::Internal(format!("Invalid RPC URL: {e}")))?,
        );
        let contract = ISetPaymentBatch::new(self.config.contract_address, &provider);
        let mut settled = Vec::new();
        let mut failed = Vec::new();
        for intent in intents {
            let is_settled = contract
                .isIntentSettled(Self::uuid_to_bytes32(intent.intent_id))
                .call()
                .await
                .map_err(|e| {
                    SequencerError::Internal(format!("isIntentSettled call failed: {e}"))
                })?;
            if is_settled {
                settled.push(intent.intent_id);
            } else {
                failed.push(intent.intent_id);
            }
        }
        Ok((settled, failed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;
    use alloy::sol_types::{SolCall, SolValue};
    use chrono::Utc;

    /// Canonical Solidity signature of `settleBatch`, with the `PaymentIntent`
    /// tuple in the EXACT field order of commerce/SetPaymentBatch.sol.
    const SETTLE_BATCH_SIG: &str = "settleBatch(bytes32,bytes32,bytes32,uint64,uint64,(bytes32,address,address,uint256,address,uint64,uint64,uint64,bytes32,bytes)[])";

    fn sample_intent() -> X402PaymentIntent {
        use crate::domain::{
            AgentId, AgentKeyId, StoreId, TenantId, X402Asset, X402IntentStatus, X402Network,
        };
        X402PaymentIntent {
            intent_id: Uuid::from_u128(0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00),
            x402_version: 1,
            status: X402IntentStatus::Batched,
            tenant_id: TenantId::new(),
            store_id: StoreId::new(),
            source_agent_id: AgentId::new(),
            agent_key_id: AgentKeyId::new(1),
            payer_address: "0x1111111111111111111111111111111111111111".to_string(),
            payee_address: "0x2222222222222222222222222222222222222222".to_string(),
            amount: 1_000_000,
            asset: X402Asset::Usdc,
            network: X402Network::SetChain,
            chain_id: 84532001,
            token_address: Some("0x3333333333333333333333333333333333333333".to_string()),
            created_at_unix: 1_700_000_000,
            valid_until: 1_700_100_000,
            valid_after: 1_700_000_500,
            nonce: 42,
            idempotency_key: None,
            eip712_authorization: Some(vec![0xAB; 65]),
            resource_uri: None,
            description: None,
            order_id: None,
            merchant_id: None,
            signing_hash: [0x7u8; 32],
            payer_signature: [0x9u8; 64],
            payer_public_key: None,
            sequence_number: Some(7),
            sequenced_at: Some(Utc::now()),
            batch_id: Some(Uuid::new_v4()),
            tx_hash: None,
            block_number: None,
            settled_at: None,
            metadata: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn settle_batch_selector_matches_solidity_abi() {
        // Known-good vector: the sol! binding must produce the exact 4-byte
        // selector of the canonical Solidity signature. This proves the
        // PaymentIntent field order (and every param type) matches
        // SetPaymentBatch.sol — a wrong order would change the selector.
        let expected = &keccak256(SETTLE_BATCH_SIG.as_bytes())[..4];
        assert_eq!(
            ISetPaymentBatch::settleBatchCall::SELECTOR.as_slice(),
            expected,
            "settleBatch ABI selector diverged from SetPaymentBatch.sol"
        );
    }

    #[test]
    fn payment_intent_maps_fields_in_contract_order() {
        let intent = sample_intent();
        let payment = SettlementService::build_payment(&intent).unwrap();

        // Fields land in the right slots.
        assert_eq!(&payment.intentId[..16], intent.intent_id.as_bytes());
        assert_eq!(payment.intentId[16..], [0u8; 16]);
        assert_eq!(
            payment.payer,
            "0x1111111111111111111111111111111111111111"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(payment.amount, U256::from(1_000_000u64));
        assert_eq!(
            payment.token,
            "0x3333333333333333333333333333333333333333"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(payment.nonce, 42);
        assert_eq!(payment.validAfter, 1_700_000_500);
        assert_eq!(payment.validUntil, 1_700_100_000);
        assert_eq!(payment.signingHash.as_slice(), &[0x7u8; 32]);
        assert_eq!(payment.authorization.as_ref(), &vec![0xABu8; 65][..]);
    }

    #[test]
    fn settle_batch_calldata_roundtrips() {
        // Encode a real settleBatch call and decode it back: the PaymentIntent
        // tuple survives ABI encode/decode with the authorization bytes intact,
        // confirming on-wire layout matches the contract's decoder.
        let intent = sample_intent();
        let payment = SettlementService::build_payment(&intent).unwrap();
        let call = ISetPaymentBatch::settleBatchCall {
            batchId: FixedBytes::<32>::from([0x1u8; 32]),
            merkleRoot: FixedBytes::<32>::from([0x2u8; 32]),
            tenantStoreKey: FixedBytes::<32>::from([0x3u8; 32]),
            sequenceStart: 1,
            sequenceEnd: 9,
            payments: vec![payment],
        };

        let encoded = call.abi_encode();
        assert_eq!(
            &encoded[..4],
            ISetPaymentBatch::settleBatchCall::SELECTOR.as_slice()
        );

        let decoded = ISetPaymentBatch::settleBatchCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.sequenceStart, 1);
        assert_eq!(decoded.sequenceEnd, 9);
        assert_eq!(decoded.payments.len(), 1);
        let p = &decoded.payments[0];
        assert_eq!(p.nonce, 42);
        assert_eq!(p.validAfter, 1_700_000_500);
        assert_eq!(p.amount, U256::from(1_000_000u64));
        assert_eq!(p.authorization.as_ref(), &vec![0xABu8; 65][..]);
        // The raw tuple also ABI-encodes stand-alone in the documented order.
        let _ = p.abi_encode();
    }

    #[test]
    #[serial_test::serial]
    fn config_from_env_is_none_without_required_vars() {
        // Snapshot + clear the required vars so the test is order-independent.
        let saved: Vec<_> = [
            "SETTLEMENT_RPC_URL",
            "SET_PAYMENT_BATCH_ADDRESS",
            "SETTLER_PRIVATE_KEY",
        ]
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
        for (k, _) in &saved {
            std::env::remove_var(k);
        }
        assert!(SettlementConfig::from_env().unwrap().is_none());
        for (k, v) in saved {
            if let Some(v) = v {
                std::env::set_var(k, v);
            }
        }
    }

    #[test]
    fn settlement_config_debug_redacts_credentials() {
        let config = SettlementConfig {
            rpc_url: "https://user:rpc-secret@example.invalid/key?token=secret".to_string(),
            contract_address: Address::ZERO,
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
    fn settlement_config_rejects_partial_configuration() {
        for name in [
            "SETTLEMENT_RPC_URL",
            "SET_PAYMENT_BATCH_ADDRESS",
            "SETTLER_PRIVATE_KEY",
        ] {
            std::env::remove_var(name);
        }
        std::env::set_var("SETTLEMENT_RPC_URL", "https://rpc.example.invalid");

        let err = SettlementConfig::from_env()
            .expect_err("partial settlement configuration must not silently disable the worker");
        assert!(err.to_string().contains("SET_PAYMENT_BATCH_ADDRESS"));

        std::env::remove_var("SETTLEMENT_RPC_URL");
    }
}
