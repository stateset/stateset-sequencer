//! VES validity proof handlers.
//!
//! Validity proofs provide cryptographic attestation that a batch commitment
//! was correctly computed from its constituent events. This enables light
//! clients to verify batch integrity without processing all events.
//!
//! # Proof Workflow
//!
//! 1. Sequencer creates a batch commitment with Merkle root
//! 2. Client retrieves canonical public inputs via `/inputs`
//! 3. Client generates STARK proof off-chain proving:
//!    - All leaf hashes are correctly computed
//!    - Merkle tree is correctly constructed
//!    - State transition is valid
//! 4. Client submits proof via `/submit`
//! 5. Sequencer stores proof with batch commitment
//!
//! # Public Inputs
//!
//! The canonical public inputs include:
//! - `batch_id`: Unique commitment identifier
//! - `prev_state_root`: State root before this batch
//! - `new_state_root`: State root after this batch
//! - `merkle_root`: Root of the event Merkle tree
//! - `leaf_count`: Number of events in batch
//!
//! # Security
//!
//! - Proofs are encrypted at rest with AES-GCM
//! - AAD includes batch_id and proof_hash
//! - Verification can be done on-chain or off-chain

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use serde::Deserialize;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::instrument;
use uuid::Uuid;
use ves_stark_batch::public_inputs::{BatchPolicyKind, BatchPublicInputs};
use ves_stark_batch::verifier::verify_batch_proof;
use ves_stark_primitives::felt_from_u64;
use ves_stark_primitives::Felt;

use crate::api::auth_helpers::{ensure_admin, ensure_read};
use crate::api::handlers::ves::ves_validity_public_inputs;
use crate::api::types::SubmitVesValidityProofRequest;
use crate::api::utils::{decode_base64_any, internal_error};
use crate::auth::AuthContextExt;
use crate::crypto::{canonical_json_hash, compute_ves_validity_proof_hash};
use crate::server::AppState;

const MAX_VALIDITY_PROOF_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const STARK_VERIFY_TIMEOUT: Duration = Duration::from_secs(15);
const STARK_VERIFY_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

const STARK_VERIFY_ON_SUBMIT_ENV: &str = "VES_STARK_VERIFY_ON_SUBMIT";
const STARK_VERIFY_CONCURRENCY_ENV: &str = "VES_STARK_VERIFY_CONCURRENCY";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VesValidityBatchPublicInputs {
    #[serde(alias = "batch_id")]
    batch_id: Uuid,
    #[serde(alias = "tenant_id")]
    tenant_id: Uuid,
    #[serde(alias = "store_id")]
    store_id: Uuid,
    #[serde(alias = "leaf_count")]
    leaf_count: u64,
    #[serde(alias = "sequence_start")]
    sequence_start: u64,
    #[serde(alias = "sequence_end")]
    sequence_end: u64,
    #[serde(alias = "prev_state_root")]
    prev_state_root: String,
    #[serde(alias = "new_state_root")]
    new_state_root: String,
    #[serde(alias = "timestamp", default)]
    timestamp: u64,
    #[serde(alias = "all_compliant")]
    all_compliant: bool,
    #[serde(alias = "policy_kind", default)]
    policy_kind: u64,
    #[serde(alias = "policy_hash")]
    policy_hash: String,
    #[serde(alias = "policy_limit")]
    policy_limit: u64,
}

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

fn parse_hex_to_u64_array(
    field: &str,
    value: &str,
    chunk_bytes: usize,
    chunk_count: usize,
) -> Result<Vec<u64>, (StatusCode, String)> {
    let mut hex_str = value.trim();
    if let Some(stripped) = hex_str.strip_prefix("0x") {
        hex_str = stripped;
    }
    let expected_len = chunk_bytes
        .checked_mul(chunk_count)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("{field} size overflow")))?;

    if hex_str.len() != expected_len * 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "{field} must be {} hex characters ({} bytes)",
                expected_len * 2,
                expected_len
            ),
        ));
    }
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must be lowercase/uppercase hex characters only"),
        ));
    }

    let bytes = hex::decode(hex_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid {field} hex ({e})"),
        )
    })?;
    if bytes.len() != expected_len {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "{field} must decode to {expected_len} bytes (got {})",
                bytes.len()
            ),
        ));
    }

    if chunk_bytes != 4 && chunk_bytes != 8 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{field} uses unsupported chunk size"),
        ));
    }
    if chunk_count > 8 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{field} chunk count too large: {chunk_count}"),
        ));
    }

    let mut out = vec![0u64; chunk_count];
    for (idx, slot) in out.iter_mut().enumerate() {
        let offset = idx * chunk_bytes;
        let limb = if chunk_bytes == 8 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(chunk)
        } else {
            let mut chunk = [0u8; 4];
            chunk.copy_from_slice(&bytes[offset..offset + 4]);
            u64::from(u32::from_le_bytes(chunk))
        };
        *slot = limb;
    }

    Ok(out)
}

fn uuid_to_felts(id: &Uuid) -> [Felt; 4] {
    let bytes = id.as_bytes();
    [
        felt_from_u64(u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u64),
        felt_from_u64(u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as u64),
        felt_from_u64(u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as u64),
        felt_from_u64(u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as u64),
    ]
}

fn parse_batch_public_inputs(
    value: &serde_json::Value,
) -> Result<BatchPublicInputs, (StatusCode, String)> {
    let parsed: VesValidityBatchPublicInputs =
        serde_json::from_value(value.clone()).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid public inputs: {e}"),
            )
        })?;

    let prev_root_u64 = parse_hex_to_u64_array("prevStateRoot", &parsed.prev_state_root, 8, 4)?;
    let new_root_u64 = parse_hex_to_u64_array("newStateRoot", &parsed.new_state_root, 8, 4)?;
    let policy_hash_u64 = parse_hex_to_u64_array("policyHash", &parsed.policy_hash, 4, 8)?;

    let expected_events = parsed
        .sequence_end
        .checked_sub(parsed.sequence_start)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "sequenceStart / sequenceEnd range is invalid".to_string(),
            )
        })?;
    if parsed.leaf_count != expected_events {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "leafCount ({}) must equal sequenceEnd - sequenceStart + 1 ({})",
                parsed.leaf_count, expected_events
            ),
        ));
    }
    let num_events = usize::try_from(parsed.leaf_count).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "leafCount is too large to parse".to_string(),
        )
    })?;

    let policy_kind = match parsed.policy_kind {
        1 => BatchPolicyKind::OrderTotalCap,
        _ => BatchPolicyKind::AmlThreshold,
    };

    Ok(BatchPublicInputs::new(
        [
            felt_from_u64(prev_root_u64[0]),
            felt_from_u64(prev_root_u64[1]),
            felt_from_u64(prev_root_u64[2]),
            felt_from_u64(prev_root_u64[3]),
        ],
        [
            felt_from_u64(new_root_u64[0]),
            felt_from_u64(new_root_u64[1]),
            felt_from_u64(new_root_u64[2]),
            felt_from_u64(new_root_u64[3]),
        ],
        uuid_to_felts(&parsed.batch_id),
        uuid_to_felts(&parsed.tenant_id),
        uuid_to_felts(&parsed.store_id),
        parsed.sequence_start,
        parsed.sequence_end,
        parsed.timestamp,
        num_events,
        parsed.all_compliant,
        policy_kind,
        parsed.policy_limit,
        [
            felt_from_u64(policy_hash_u64[0]),
            felt_from_u64(policy_hash_u64[1]),
            felt_from_u64(policy_hash_u64[2]),
            felt_from_u64(policy_hash_u64[3]),
            felt_from_u64(policy_hash_u64[4]),
            felt_from_u64(policy_hash_u64[5]),
            felt_from_u64(policy_hash_u64[6]),
            felt_from_u64(policy_hash_u64[7]),
        ],
    ))
}

/// GET /api/v1/ves/validity/:batch_id/inputs - Get validity public inputs.
#[instrument(skip(state, auth), fields(batch_id = %batch_id))]
pub async fn get_ves_validity_public_inputs(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let commitment = super::get_ves_commitment_cached(&state, batch_id).await?;

    ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

    let public_inputs = ves_validity_public_inputs(&commitment);
    let public_inputs_hash = canonical_json_hash(&public_inputs);

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "public_inputs": public_inputs,
        "public_inputs_hash": hex::encode(public_inputs_hash),
    })))
}

/// POST /api/v1/ves/validity/:batch_id/proofs - Submit a validity proof.
#[instrument(skip(state, auth, request), fields(batch_id = %batch_id))]
pub async fn submit_ves_validity_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
    Json(request): Json<SubmitVesValidityProofRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let commitment = super::get_ves_commitment_cached(&state, batch_id).await?;

    ensure_admin(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

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

    let proof = decode_base64_any(&request.proof_b64)?;
    if proof.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofB64 must not be empty".to_string(),
        ));
    }
    if proof.len() > MAX_VALIDITY_PROOF_BYTES {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "proofB64 decoded bytes must be <= {} (got {})",
                MAX_VALIDITY_PROOF_BYTES,
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

    let canonical_inputs = ves_validity_public_inputs(&commitment);
    let public_inputs = match request.public_inputs {
        Some(v) if v != canonical_inputs => {
            return Err((
                StatusCode::BAD_REQUEST,
                "publicInputs must match the sequencer's canonical inputs for this batch"
                    .to_string(),
            ));
        }
        Some(v) => Some(v),
        None => Some(canonical_inputs),
    };

    if is_stark && stark_verify_on_submit_enabled() {
        let batch_public_inputs = parse_batch_public_inputs(public_inputs.as_ref().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Missing public inputs".to_string(),
        ))?)?;

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
        .map_err(internal_error)?;

        let verify_res = tokio::time::timeout(
            STARK_VERIFY_TIMEOUT,
            tokio::task::spawn_blocking(move || {
                verify_batch_proof(&proof_bytes, &batch_public_inputs)
            }),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "STARK proof verification timed out".to_string(),
            )
        })?;

        let verify_res = verify_res
            .map_err(internal_error)?
            .map_err(internal_error)?;

        if !verify_res.valid {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid STARK proof: {}",
                    verify_res
                        .error
                        .unwrap_or_else(|| "verification_failed".to_string())
                ),
            ));
        }
    }

    let summary = state
        .ves_validity_proof_store
        .submit_proof(
            &commitment.tenant_id,
            &commitment.store_id,
            batch_id,
            proof_type,
            request.proof_version,
            proof,
            public_inputs,
        )
        .await
        .map_err(|e| match e {
            crate::infra::SequencerError::BatchNotFound(_) => {
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

    Ok(Json(serde_json::json!({
        "proof_id": summary.proof_id,
        "batch_id": summary.batch_id,
        "tenant_id": summary.tenant_id.0,
        "store_id": summary.store_id.0,
        "proof_type": summary.proof_type,
        "proof_version": summary.proof_version,
        "proof_hash": hex::encode(summary.proof_hash),
        "public_inputs": summary.public_inputs,
        "submitted_at": summary.submitted_at,
    })))
}

/// GET /api/v1/ves/validity/:batch_id/proofs - List validity proofs for a batch.
#[instrument(skip(state, auth), fields(batch_id = %batch_id))]
pub async fn list_ves_validity_proofs(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let commitment = super::get_ves_commitment_cached(&state, batch_id).await?;

    ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

    let proofs = state
        .ves_validity_proof_store
        .list_proofs_for_batch(batch_id)
        .await
        .map_err(internal_error)?;

    let proofs: Vec<serde_json::Value> = proofs
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "proof_id": p.proof_id,
                "batch_id": p.batch_id,
                "tenant_id": p.tenant_id.0,
                "store_id": p.store_id.0,
                "proof_type": p.proof_type,
                "proof_version": p.proof_version,
                "proof_hash": hex::encode(p.proof_hash),
                "public_inputs": p.public_inputs,
                "submitted_at": p.submitted_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "batch_id": batch_id,
        "proofs": proofs,
        "count": proofs.len(),
    })))
}

/// GET /api/v1/ves/validity/proofs/:proof_id - Get a validity proof by ID.
#[instrument(skip(state, auth), fields(proof_id = %proof_id))]
pub async fn get_ves_validity_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_validity_proof_store
        .get_proof(proof_id)
        .await
        .map_err(internal_error)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Validity proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    Ok(Json(serde_json::json!({
        "proof_id": proof.proof_id,
        "batch_id": proof.batch_id,
        "tenant_id": proof.tenant_id.0,
        "store_id": proof.store_id.0,
        "proof_type": proof.proof_type,
        "proof_version": proof.proof_version,
        "proof_hash": hex::encode(proof.proof_hash),
        "proof_b64": base64::engine::general_purpose::STANDARD.encode(proof.proof),
        "public_inputs": proof.public_inputs,
        "submitted_at": proof.submitted_at,
    })))
}

/// GET /api/v1/ves/validity/proofs/:proof_id/verify - Verify a validity proof.
#[instrument(skip(state, auth), fields(proof_id = %proof_id))]
pub async fn verify_ves_validity_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_validity_proof_store
        .get_proof(proof_id)
        .await
        .map_err(internal_error)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Validity proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    let commitment = match state
        .ves_commitment_reader
        .get_commitment(proof.batch_id)
        .await
    {
        Ok(Some(commitment)) => commitment,
        Ok(None) => state
            .ves_commitment_engine
            .get_commitment(proof.batch_id)
            .await
            .map_err(internal_error)?
            .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?,
        Err(e) => return Err(internal_error(e)),
    };

    if commitment.tenant_id.0 != proof.tenant_id.0 || commitment.store_id.0 != proof.store_id.0 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Validity proof stream does not match commitment".to_string(),
        ));
    }

    let canonical_public_inputs = ves_validity_public_inputs(&commitment);
    let canonical_public_inputs_hash = canonical_json_hash(&canonical_public_inputs);

    let proof_hash_match = compute_ves_validity_proof_hash(&proof.proof) == proof.proof_hash;

    let stored_public_inputs_hash = proof.public_inputs.as_ref().map(canonical_json_hash);
    let public_inputs_match = stored_public_inputs_hash
        .as_ref()
        .is_some_and(|hash| *hash == canonical_public_inputs_hash);
    let public_inputs_hash = stored_public_inputs_hash.map(hex::encode);
    let is_stark = proof.proof_type.to_ascii_lowercase().starts_with("stark");

    let mut stark_valid: Option<bool> = None;
    let mut stark_error: Option<String> = None;
    let mut stark_verification_time_ms: Option<u64> = None;

    if is_stark
        && valid_base_validation(
            proof_hash_match,
            proof.public_inputs.as_ref(),
            public_inputs_match,
        )
    {
        if proof.proof_version != ves_stark_verifier::PROOF_VERSION {
            stark_valid = Some(false);
            stark_error = Some(format!(
                "unsupported proofVersion {} (expected {})",
                proof.proof_version,
                ves_stark_verifier::PROOF_VERSION
            ));
        } else {
            let batch_public_inputs = parse_batch_public_inputs(&canonical_public_inputs)?;
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
                        verify_batch_proof(&proof_bytes, &batch_public_inputs)
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
                    Ok(Ok(verify_result)) => {
                        stark_valid = Some(verify_result.valid);
                        stark_error = verify_result.error;
                        stark_verification_time_ms = Some(verify_result.verification_time_ms);
                    }
                    Ok(Err(batch_err)) => {
                        stark_valid = Some(false);
                        stark_error = Some(format!("STARK batch verification error: {batch_err}"));
                    }
                },
            }
        }
    }

    let base_valid = if !proof_hash_match {
        (false, Some("proof_hash_mismatch"))
    } else if proof.public_inputs.is_none() {
        (false, Some("missing_public_inputs"))
    } else if !public_inputs_match {
        (false, Some("public_inputs_mismatch"))
    } else {
        (true, None)
    };

    let valid = if is_stark {
        base_valid.0 && stark_valid.unwrap_or(false)
    } else {
        base_valid.0
    };

    let reason = if valid {
        None
    } else if !base_valid.0 {
        base_valid.1
    } else if is_stark {
        Some("stark_invalid")
    } else {
        base_valid.1
    };

    Ok(Json(serde_json::json!({
        "proof_id": proof.proof_id,
        "batch_id": proof.batch_id,
        "tenant_id": proof.tenant_id.0,
        "store_id": proof.store_id.0,
        "proof_type": proof.proof_type,
        "proof_version": proof.proof_version,
        "proof_hash": hex::encode(proof.proof_hash),
        "proof_hash_match": proof_hash_match,
        "public_inputs_hash": public_inputs_hash,
        "canonical_public_inputs_hash": hex::encode(canonical_public_inputs_hash),
        "public_inputs_match": public_inputs_match,
        "stark_valid": stark_valid,
        "stark_error": stark_error,
        "stark_verification_time_ms": stark_verification_time_ms,
        "valid": valid,
        "reason": reason,
    })))
}

fn valid_base_validation(
    proof_hash_match: bool,
    stored_public_inputs: Option<&serde_json::Value>,
    public_inputs_match: bool,
) -> bool {
    proof_hash_match && stored_public_inputs.is_some() && public_inputs_match
}
