//! Optional in-process STARK compliance proof generation.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::api::handlers::ves::ves_compliance_public_inputs;
use crate::crypto::compute_ves_compliance_policy_hash;
use crate::domain::Hash256;
use crate::infra::{PgVesComplianceProofStore, SequencerError, VesComplianceEventInputs};

const PROOF_TYPE: &str = "stark-compliance";

#[derive(Debug, Clone)]
pub struct ProofWorkerConfig {
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub batch_size: usize,
    pub poll_interval: Duration,
    pub prove_timeout: Duration,
    pub max_attempts: u32,
    pub retry_delay: Duration,
}

impl ProofWorkerConfig {
    pub fn from_env() -> Result<Self, SequencerError> {
        let policy_id = std::env::var("VES_PROOF_POLICY_ID")
            .map_err(|_| config_error("VES_PROOF_POLICY_ID is required"))?;
        if policy_id.trim().is_empty() || policy_id.len() > 64 {
            return Err(config_error(
                "VES_PROOF_POLICY_ID must contain 1 to 64 characters",
            ));
        }
        let raw_params = std::env::var("VES_PROOF_POLICY_PARAMS")
            .map_err(|_| config_error("VES_PROOF_POLICY_PARAMS is required"))?;
        let policy_params: serde_json::Value = serde_json::from_str(&raw_params)
            .map_err(|e| config_error(&format!("VES_PROOF_POLICY_PARAMS must be JSON: {e}")))?;
        if !policy_params.is_object() {
            return Err(config_error(
                "VES_PROOF_POLICY_PARAMS must be a JSON object",
            ));
        }

        let params = serde_json::from_value(policy_params.clone())
            .map_err(|e| config_error(&format!("invalid proof policy parameters: {e}")))?;
        ves_stark_prover::Policy::from_public_inputs(policy_id.trim(), &params)
            .map_err(|e| config_error(&format!("invalid proof policy: {e}")))?;

        Ok(Self {
            policy_id: policy_id.trim().to_string(),
            policy_params,
            batch_size: usize::try_from(positive_env("VES_PROOF_BATCH_SIZE", 4)?)
                .map_err(|_| config_error("VES_PROOF_BATCH_SIZE does not fit usize"))?,
            poll_interval: Duration::from_millis(positive_env(
                "VES_PROOF_POLL_INTERVAL_MS",
                5_000,
            )?),
            prove_timeout: Duration::from_secs(positive_env("VES_PROOF_TIMEOUT_SECS", 60)?),
            max_attempts: u32::try_from(positive_env("VES_PROOF_MAX_ATTEMPTS", 3)?)
                .map_err(|_| config_error("VES_PROOF_MAX_ATTEMPTS does not fit u32"))?,
            retry_delay: Duration::from_secs(positive_env("VES_PROOF_RETRY_DELAY_SECS", 30)?),
        })
    }
}

fn config_error(message: &str) -> SequencerError {
    SequencerError::Configuration(message.to_string())
}

fn positive_env(name: &str, default: u64) -> Result<u64, SequencerError> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| config_error(&format!("{name} must be a positive integer"))),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(config_error(&format!("{name} is not valid Unicode: {e}"))),
    }
}

#[derive(Debug)]
pub enum ProofWorkerMessage {
    Shutdown,
}

struct GeneratedProof {
    bytes: Vec<u8>,
    witness_commitment: Hash256,
    public_inputs: serde_json::Value,
}

pub fn spawn_proof_worker(
    config: ProofWorkerConfig,
    store: Arc<PgVesComplianceProofStore>,
) -> (JoinHandle<()>, mpsc::Sender<ProofWorkerMessage>) {
    let (control_tx, mut control_rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        let policy_hash =
            compute_ves_compliance_policy_hash(&config.policy_id, &config.policy_params);
        let mut interval = tokio::time::interval(config.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let candidates = match store
                        .list_unproved_plaintext_events(
                            PROOF_TYPE,
                            ves_stark_verifier::PROOF_VERSION,
                            &policy_hash,
                            config.batch_size,
                        )
                        .await
                    {
                        Ok(events) => events,
                        Err(e) => {
                            error!(error = %e, "proof worker could not fetch candidates");
                            continue;
                        }
                    };

                    for event in candidates {
                        if let Err(e) = process_event(&config, &store, &policy_hash, event).await {
                            error!(error = %e, "proof worker could not persist job outcome");
                        }
                    }
                }
                message = control_rx.recv() => {
                    if matches!(message, Some(ProofWorkerMessage::Shutdown) | None) {
                        info!("proof worker stopped");
                        return;
                    }
                }
            }
        }
    });
    (task, control_tx)
}

async fn process_event(
    config: &ProofWorkerConfig,
    store: &PgVesComplianceProofStore,
    policy_hash: &Hash256,
    event: VesComplianceEventInputs,
) -> Result<(), SequencerError> {
    let event_id = event.event_id;
    let Some(payload) = event.payload.as_ref() else {
        return store
            .record_worker_skipped(event_id, policy_hash, "plaintext event has no payload")
            .await;
    };
    let amount = match ves_stark_primitives::extract_payload_amount(&event.event_type, payload) {
        Ok(amount) => amount,
        Err(e) => {
            warn!(%event_id, reason = %e, "event is not applicable to the configured proof policy");
            return store
                .record_worker_skipped(event_id, policy_hash, &e.to_string())
                .await;
        }
    };

    let policy_params = serde_json::from_value(config.policy_params.clone())
        .map_err(|e| config_error(&format!("invalid configured policy params: {e}")))?;
    let policy = ves_stark_prover::Policy::from_public_inputs(&config.policy_id, &policy_params)
        .map_err(|e| config_error(&format!("invalid configured policy: {e}")))?;
    if !policy.validate_amount(amount) {
        let reason = format!(
            "amount {amount} does not satisfy {} with limit {}",
            policy.policy_id(),
            policy.limit()
        );
        warn!(%event_id, %reason, "event is not compliant; no proof generated");
        return store
            .record_worker_not_compliant(event_id, policy_hash, &reason)
            .await;
    }

    let canonical_inputs = ves_compliance_public_inputs(
        &event,
        &config.policy_id,
        &config.policy_params,
        policy_hash,
    );
    let prove_inputs = canonical_inputs.clone();
    let prove = tokio::task::spawn_blocking(move || -> Result<GeneratedProof, String> {
        let public_inputs = serde_json::from_value(prove_inputs.clone())
            .map_err(|e| format!("construct public inputs: {e}"))?;
        let witness = ves_stark_prover::ComplianceWitness::try_new_salted(amount, public_inputs)
            .map_err(|e| format!("construct witness: {e}"))?;
        let proof = ves_stark_prover::ComplianceProver::with_policy(policy)
            .prove(&witness)
            .map_err(|e| format!("generate proof: {e}"))?;
        let verification_inputs = serde_json::from_value(prove_inputs.clone())
            .map_err(|e| format!("construct verification inputs: {e}"))?;
        let verification = ves_stark_verifier::verify_compliance_proof_auto(
            &proof.proof_bytes,
            &verification_inputs,
            &proof.witness_commitment,
        )
        .map_err(|e| format!("verify generated proof: {e}"))?;
        if !verification.valid {
            return Err(format!(
                "generated proof failed self-verification: {}",
                verification
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            ));
        }
        let mut commitment = [0u8; 32];
        for (index, limb) in proof.witness_commitment.iter().enumerate() {
            commitment[index * 8..(index + 1) * 8].copy_from_slice(&limb.to_be_bytes());
        }
        Ok(GeneratedProof {
            bytes: proof.proof_bytes,
            witness_commitment: commitment,
            public_inputs: prove_inputs,
        })
    });

    let generated = match tokio::time::timeout(config.prove_timeout, prove).await {
        Ok(Ok(Ok(proof))) => proof,
        Ok(Ok(Err(e))) => {
            store
                .record_worker_failure(
                    event_id,
                    policy_hash,
                    &e,
                    config.max_attempts,
                    config.retry_delay,
                )
                .await?;
            return Ok(());
        }
        Ok(Err(e)) => {
            store
                .record_worker_failure(
                    event_id,
                    policy_hash,
                    &format!("proof task failed: {e}"),
                    config.max_attempts,
                    config.retry_delay,
                )
                .await?;
            return Ok(());
        }
        Err(_) => {
            store
                .record_worker_failure(
                    event_id,
                    policy_hash,
                    &format!("proof generation exceeded {:?}", config.prove_timeout),
                    config.max_attempts,
                    config.retry_delay,
                )
                .await?;
            return Ok(());
        }
    };

    match store
        .submit_proof(
            &event.tenant_id,
            &event.store_id,
            event_id,
            PROOF_TYPE,
            ves_stark_verifier::PROOF_VERSION,
            &config.policy_id,
            config.policy_params.clone(),
            Some(generated.witness_commitment),
            generated.bytes,
            Some(generated.public_inputs),
        )
        .await
    {
        Ok(_) => {
            store.record_worker_proved(event_id, policy_hash).await?;
            info!(%event_id, policy_id = %config.policy_id, "compliance proof generated and stored");
        }
        Err(e) => {
            store
                .record_worker_failure(
                    event_id,
                    policy_hash,
                    &e.to_string(),
                    config.max_attempts,
                    config.retry_delay,
                )
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_type_is_stark_and_stable() {
        assert!(PROOF_TYPE.starts_with("stark"));
        assert_eq!(ves_stark_verifier::PROOF_VERSION, 2);
    }
}
