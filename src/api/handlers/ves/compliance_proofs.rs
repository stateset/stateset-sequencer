//! VES compliance proof handlers.
//!
//! Compliance proofs provide cryptographic attestation that an event satisfies
//! a compliance policy (e.g., GDPR data handling, AML checks, trade sanctions).
//!
//! # Proof Workflow
//!
//! 1. Client retrieves canonical public inputs for an event via `/inputs`
//! 2. Client generates STARK proof off-chain using the inputs
//! 3. Client submits proof via `/submit` with policy ID and parameters
//! 4. Sequencer verifies the proof hash matches inputs
//! 5. Proof is encrypted at rest and stored with the event
//!
//! # Policy Hashing
//!
//! The policy is identified by a deterministic hash of:
//! - `policy_id`: Unique policy identifier string
//! - `policy_params`: JSON object of policy parameters
//!
//! This allows the same policy logic to be applied with different parameters.
//!
//! # Security
//!
//! - Proofs are encrypted at rest with AES-GCM
//! - AAD includes event_id, proof_id, and policy_hash to prevent substitution
//! - Proof hash is stored separately for verification without decryption

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::instrument;
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_read, ensure_write};
use crate::api::handlers::ves::ves_compliance_public_inputs;
use crate::api::types::{
    SubmitVesComplianceProofRequest, VesComplianceInputsRequest, WitnessCommitment,
};
use crate::api::utils::{decode_base64_any, internal_error};
use crate::auth::AuthContextExt;
use crate::crypto::{
    canonical_json_hash, compute_ves_compliance_policy_hash, compute_ves_compliance_proof_hash,
};
use crate::server::AppState;

const MAX_COMPLIANCE_PROOF_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const STARK_VERIFY_TIMEOUT: Duration = Duration::from_secs(15);
const STARK_VERIFY_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

const STARK_VERIFY_ON_SUBMIT_ENV: &str = "VES_STARK_VERIFY_ON_SUBMIT";
const STARK_VERIFY_CONCURRENCY_ENV: &str = "VES_STARK_VERIFY_CONCURRENCY";

fn stark_verify_on_submit_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var(STARK_VERIFY_ON_SUBMIT_ENV)
            .ok()
            .map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "" | "0" | "false" | "off"
                )
            })
            .unwrap_or(true)
    })
}

fn stark_verify_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| {
        let default = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .min(4);
        let limit = std::env::var(STARK_VERIFY_CONCURRENCY_ENV)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(default)
            .max(1);
        Semaphore::new(limit)
    })
}

fn parse_witness_commitment(input: &WitnessCommitment) -> Result<[u8; 32], (StatusCode, String)> {
    match input {
        WitnessCommitment::Hex(hex_str) => {
            let mut s = hex_str.trim();
            if let Some(stripped) = s.strip_prefix("0x") {
                s = stripped;
            }
            if s.len() != 64 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "witnessCommitment must be 64 lowercase hex characters (32 bytes)".to_string(),
                ));
            }
            if !s
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "witnessCommitment must be lowercase hex".to_string(),
                ));
            }

            let mut out = [0u8; 32];
            hex::decode_to_slice(s, &mut out).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid witnessCommitment hex: {e}"),
                )
            })?;
            Ok(out)
        }
        WitnessCommitment::U64(limbs) => {
            let mut out = [0u8; 32];
            for (i, v) in limbs.iter().enumerate() {
                let offset = i * 8;
                out[offset..offset + 8].copy_from_slice(&v.to_be_bytes());
            }
            Ok(out)
        }
    }
}

fn witness_commitment_bytes_to_u64(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, v) in out.iter_mut().enumerate() {
        let offset = i * 8;
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[offset..offset + 8]);
        *v = u64::from_be_bytes(limb);
    }
    out
}

/// POST /api/v1/ves/compliance/:event_id/inputs - Get compliance public inputs.
#[instrument(skip(state, auth, request), fields(event_id = %event_id))]
pub async fn get_ves_compliance_public_inputs(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(event_id): Path<Uuid>,
    Json(request): Json<VesComplianceInputsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(event_id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    ensure_read(&auth, inputs.tenant_id.0, inputs.store_id.0)?;

    let policy_id = request.policy_id.trim();
    if policy_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "policyId must not be empty".to_string(),
        ));
    }
    if policy_id.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "policyId must be <= 64 characters".to_string(),
        ));
    }

    let policy_hash = compute_ves_compliance_policy_hash(policy_id, &request.policy_params);
    let public_inputs =
        ves_compliance_public_inputs(&inputs, policy_id, &request.policy_params, &policy_hash);
    let public_inputs_hash = canonical_json_hash(&public_inputs);

    Ok(Json(serde_json::json!({
        "event_id": inputs.event_id,
        "public_inputs": public_inputs,
        "public_inputs_hash": hex::encode(public_inputs_hash),
    })))
}

/// POST /api/v1/ves/compliance/:event_id/proofs - Submit a compliance proof.
#[instrument(skip(state, auth, request), fields(event_id = %event_id))]
pub async fn submit_ves_compliance_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(event_id): Path<Uuid>,
    Json(request): Json<SubmitVesComplianceProofRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(event_id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    ensure_write(&auth, inputs.tenant_id.0, inputs.store_id.0)?;

    let proof_type = request.proof_type.trim();
    if proof_type.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofType must not be empty".to_string(),
        ));
    }
    if proof_type.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofType must be <= 32 characters".to_string(),
        ));
    }
    if request.proof_version < 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofVersion must be >= 1".to_string(),
        ));
    }

    let policy_id = request.policy_id.trim();
    if policy_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "policyId must not be empty".to_string(),
        ));
    }
    if policy_id.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "policyId must be <= 64 characters".to_string(),
        ));
    }

    let proof = decode_base64_any(&request.proof_b64)?;
    if proof.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofB64 must not be empty".to_string(),
        ));
    }
    if proof.len() > MAX_COMPLIANCE_PROOF_BYTES {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "proofB64 decoded bytes must be <= {} (got {})",
                MAX_COMPLIANCE_PROOF_BYTES,
                proof.len()
            ),
        ));
    }

    let is_stark = proof_type.to_ascii_lowercase().starts_with("stark");
    if is_stark && request.proof_version != ves_stark_verifier::PROOF_VERSION {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Unsupported proofVersion {} (expected {}) for STARK proofs",
                request.proof_version,
                ves_stark_verifier::PROOF_VERSION
            ),
        ));
    }

    let witness_commitment = request
        .witness_commitment
        .as_ref()
        .map(parse_witness_commitment)
        .transpose()?;
    if is_stark && witness_commitment.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "witnessCommitment is required for STARK compliance proofs".to_string(),
        ));
    }

    let policy_hash = compute_ves_compliance_policy_hash(policy_id, &request.policy_params);
    let canonical_inputs =
        ves_compliance_public_inputs(&inputs, policy_id, &request.policy_params, &policy_hash);

    let public_inputs = match request.public_inputs {
        Some(v) if v != canonical_inputs => {
            return Err((
                StatusCode::BAD_REQUEST,
                "publicInputs must match the sequencer's canonical inputs for this event and policy"
                    .to_string(),
            ));
        }
        Some(v) => Some(v),
        None => Some(canonical_inputs.clone()),
    };

    // Optional: reject invalid STARK proofs at submission time.
    if is_stark && stark_verify_on_submit_enabled() {
        let public_inputs: ves_stark_primitives::public_inputs::CompliancePublicInputs =
            serde_json::from_value(canonical_inputs.clone()).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid canonical public inputs (bug): {e}"),
                )
            })?;
        let commitment_u64 =
            witness_commitment_bytes_to_u64(&witness_commitment.expect("checked above for STARK"));
        let proof_bytes = proof.clone();

        let _permit = tokio::time::timeout(
            STARK_VERIFY_ACQUIRE_TIMEOUT,
            stark_verify_semaphore().acquire(),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "STARK verifier is busy, try again later".to_string(),
            )
        })?
        .map_err(|e| internal_error(e))?;

        let verify_res = tokio::time::timeout(
            STARK_VERIFY_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                ves_stark_verifier::verify_compliance_proof_auto(
                    &proof_bytes,
                    &public_inputs,
                    &commitment_u64,
                )
            }),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "STARK proof verification timed out".to_string(),
            )
        })?
        .map_err(|e| internal_error(e))?;

        match verify_res {
            Ok(result) if result.valid => {}
            Ok(result) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Invalid STARK proof: {}",
                        result
                            .error
                            .unwrap_or_else(|| "verification_failed".to_string())
                    ),
                ));
            }
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("STARK proof verification error: {e}"),
                ));
            }
        }
    }

    let summary = state
        .ves_compliance_proof_store
        .submit_proof(
            &inputs.tenant_id,
            &inputs.store_id,
            event_id,
            proof_type,
            request.proof_version,
            policy_id,
            request.policy_params,
            witness_commitment,
            proof,
            public_inputs,
        )
        .await
        .map_err(|e| match e {
            crate::infra::SequencerError::EventNotFound(_) => {
                (StatusCode::NOT_FOUND, e.to_string())
            }
            crate::infra::SequencerError::Unauthorized(_) => (StatusCode::FORBIDDEN, e.to_string()),
            crate::infra::SequencerError::InvariantViolation { .. } => {
                (StatusCode::CONFLICT, e.to_string())
            }
            crate::infra::SequencerError::Encryption(_) => internal_error(e),
            crate::infra::SequencerError::Database(_) => internal_error(e),
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        })?;

    let witness_commitment_u64 = summary
        .witness_commitment
        .as_ref()
        .map(witness_commitment_bytes_to_u64);
    let witness_commitment_hex = summary.witness_commitment.as_ref().map(hex::encode);

    Ok(Json(serde_json::json!({
        "proof_id": summary.proof_id,
        "event_id": summary.event_id,
        "tenant_id": summary.tenant_id.0,
        "store_id": summary.store_id.0,
        "proof_type": summary.proof_type,
        "proof_version": summary.proof_version,
        "policy_id": summary.policy_id,
        "policy_params": summary.policy_params,
        "policy_hash": hex::encode(summary.policy_hash),
        "proof_hash": hex::encode(summary.proof_hash),
        "witness_commitment": witness_commitment_u64,
        "witness_commitment_hex": witness_commitment_hex,
        "public_inputs": summary.public_inputs,
        "submitted_at": summary.submitted_at,
    })))
}

/// GET /api/v1/ves/compliance/:event_id/proofs - List compliance proofs for an event.
#[instrument(skip(state, auth), fields(event_id = %event_id))]
pub async fn list_ves_compliance_proofs(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(event_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(event_id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    ensure_read(&auth, inputs.tenant_id.0, inputs.store_id.0)?;

    let proofs = state
        .ves_compliance_proof_store
        .list_proofs_for_event(event_id)
        .await
        .map_err(internal_error)?;

    let proofs: Vec<serde_json::Value> = proofs
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "proof_id": p.proof_id,
                "event_id": p.event_id,
                "tenant_id": p.tenant_id.0,
                "store_id": p.store_id.0,
                "proof_type": p.proof_type,
                "proof_version": p.proof_version,
                "policy_id": p.policy_id,
                "policy_params": p.policy_params,
                "policy_hash": hex::encode(p.policy_hash),
                "proof_hash": hex::encode(p.proof_hash),
                "witness_commitment": p.witness_commitment.as_ref().map(witness_commitment_bytes_to_u64),
                "witness_commitment_hex": p.witness_commitment.as_ref().map(hex::encode),
                "public_inputs": p.public_inputs,
                "submitted_at": p.submitted_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "event_id": event_id,
        "proofs": proofs,
        "count": proofs.len(),
    })))
}

/// GET /api/v1/ves/compliance/proofs/:proof_id - Get a compliance proof by ID.
#[instrument(skip(state, auth), fields(proof_id = %proof_id))]
pub async fn get_ves_compliance_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_compliance_proof_store
        .get_proof(proof_id)
        .await
        .map_err(internal_error)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Compliance proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    Ok(Json(serde_json::json!({
        "proof_id": proof.proof_id,
        "event_id": proof.event_id,
        "tenant_id": proof.tenant_id.0,
        "store_id": proof.store_id.0,
        "proof_type": proof.proof_type,
        "proof_version": proof.proof_version,
        "policy_id": proof.policy_id,
        "policy_params": proof.policy_params,
        "policy_hash": hex::encode(proof.policy_hash),
        "proof_hash": hex::encode(proof.proof_hash),
        "witness_commitment": proof.witness_commitment.as_ref().map(witness_commitment_bytes_to_u64),
        "witness_commitment_hex": proof.witness_commitment.as_ref().map(hex::encode),
        "proof_b64": base64::engine::general_purpose::STANDARD.encode(proof.proof),
        "public_inputs": proof.public_inputs,
        "submitted_at": proof.submitted_at,
    })))
}

/// GET /api/v1/ves/compliance/proofs/:proof_id/verify - Verify a compliance proof.
#[instrument(skip(state, auth), fields(proof_id = %proof_id))]
pub async fn verify_ves_compliance_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_compliance_proof_store
        .get_proof(proof_id)
        .await
        .map_err(internal_error)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Compliance proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(proof.event_id)
        .await
        .map_err(internal_error)?
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Event not found for compliance proof".to_string(),
        ))?;

    if inputs.tenant_id.0 != proof.tenant_id.0 || inputs.store_id.0 != proof.store_id.0 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Compliance proof stream does not match event".to_string(),
        ));
    }

    let computed_policy_hash =
        compute_ves_compliance_policy_hash(&proof.policy_id, &proof.policy_params);

    let canonical_public_inputs = ves_compliance_public_inputs(
        &inputs,
        &proof.policy_id,
        &proof.policy_params,
        &computed_policy_hash,
    );
    let canonical_public_inputs_hash = canonical_json_hash(&canonical_public_inputs);

    let proof_hash_match = compute_ves_compliance_proof_hash(&proof.proof) == proof.proof_hash;

    let stored_policy_hash_ok = proof.policy_hash == computed_policy_hash;

    let stored_public_inputs_hash = proof.public_inputs.as_ref().map(canonical_json_hash);
    let public_inputs_match = stored_public_inputs_hash
        .as_ref()
        .is_some_and(|hash| *hash == canonical_public_inputs_hash);
    let public_inputs_hash = stored_public_inputs_hash.map(hex::encode);

    let (base_valid, reason) = if !proof_hash_match {
        (false, Some("proof_hash_mismatch"))
    } else if !stored_policy_hash_ok {
        (false, Some("policy_hash_mismatch"))
    } else if proof.public_inputs.is_none() {
        (false, Some("missing_public_inputs"))
    } else if !public_inputs_match {
        (false, Some("public_inputs_mismatch"))
    } else {
        (true, None)
    };

    let is_stark = proof.proof_type.to_ascii_lowercase().starts_with("stark");
    let witness_commitment_u64 = proof
        .witness_commitment
        .as_ref()
        .map(witness_commitment_bytes_to_u64);
    let witness_commitment_hex = proof.witness_commitment.as_ref().map(hex::encode);

    let mut stark_valid: Option<bool> = None;
    let mut stark_error: Option<String> = None;
    let mut stark_verification_time_ms: Option<u64> = None;

    if is_stark && base_valid {
        if proof.proof_version != ves_stark_verifier::PROOF_VERSION {
            stark_valid = Some(false);
            stark_error = Some(format!(
                "unsupported proofVersion {} (expected {})",
                proof.proof_version,
                ves_stark_verifier::PROOF_VERSION
            ));
        } else if proof.witness_commitment.is_none() {
            stark_valid = Some(false);
            stark_error = Some("missing witnessCommitment".to_string());
        } else {
            let public_inputs: ves_stark_primitives::public_inputs::CompliancePublicInputs =
                serde_json::from_value(canonical_public_inputs.clone())
                    .map_err(|e| internal_error(format!("invalid canonical public inputs: {e}")))?;
            let commitment_u64 = witness_commitment_u64.expect("checked witness_commitment above");
            let proof_bytes = proof.proof.clone();

            let permit_res = tokio::time::timeout(
                STARK_VERIFY_ACQUIRE_TIMEOUT,
                stark_verify_semaphore().acquire(),
            )
            .await;

            let verify_res = match permit_res {
                Err(_) => Err("STARK verifier is busy, try again later".to_string()),
                Ok(Err(e)) => Err(format!("STARK verifier internal error: {e}")),
                Ok(Ok(_permit)) => tokio::time::timeout(
                    STARK_VERIFY_TIMEOUT,
                    tokio::task::spawn_blocking(move || {
                        ves_stark_verifier::verify_compliance_proof_auto(
                            &proof_bytes,
                            &public_inputs,
                            &commitment_u64,
                        )
                    }),
                )
                .await
                .map_err(|_| "STARK proof verification timed out".to_string()),
            };

            match verify_res {
                Err(e) => {
                    stark_valid = Some(false);
                    stark_error = Some(e);
                }
                Ok(joined) => match joined {
                    Err(e) => {
                        stark_valid = Some(false);
                        stark_error = Some(format!("STARK verify join error: {e}"));
                    }
                    Ok(Ok(result)) => {
                        stark_valid = Some(result.valid);
                        stark_error = result.error;
                        stark_verification_time_ms = Some(result.verification_time_ms);
                    }
                    Ok(Err(e)) => {
                        stark_valid = Some(false);
                        stark_error = Some(e.to_string());
                    }
                },
            }
        }
    }

    let valid = if is_stark {
        base_valid && stark_valid.unwrap_or(false)
    } else {
        base_valid
    };

    let reason = if valid {
        None
    } else if !base_valid {
        reason
    } else if is_stark {
        Some("stark_invalid")
    } else {
        reason
    };

    Ok(Json(serde_json::json!({
        "proof_id": proof.proof_id,
        "event_id": proof.event_id,
        "tenant_id": proof.tenant_id.0,
        "store_id": proof.store_id.0,
        "proof_type": proof.proof_type,
        "proof_version": proof.proof_version,
        "policy_id": proof.policy_id,
        "policy_hash": hex::encode(proof.policy_hash),
        "proof_hash": hex::encode(proof.proof_hash),
        "proof_hash_match": proof_hash_match,
        "public_inputs_hash": public_inputs_hash,
        "canonical_public_inputs_hash": hex::encode(canonical_public_inputs_hash),
        "public_inputs_match": public_inputs_match,
        "witness_commitment": witness_commitment_u64,
        "witness_commitment_hex": witness_commitment_hex,
        "stark_valid": stark_valid,
        "stark_error": stark_error,
        "stark_verification_time_ms": stark_verification_time_ms,
        "valid": valid,
        "reason": reason,
    })))
}
