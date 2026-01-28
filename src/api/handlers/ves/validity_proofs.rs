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
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_admin, ensure_read};
use crate::api::handlers::ves::ves_validity_public_inputs;
use crate::api::types::SubmitVesValidityProofRequest;
use crate::api::utils::decode_base64_any;
use crate::auth::AuthContextExt;
use crate::crypto::{canonical_json_hash, compute_ves_validity_proof_hash};
use crate::server::AppState;

/// GET /api/v1/ves/validity/:batch_id/inputs - Get validity public inputs.
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
            crate::infra::SequencerError::Encryption(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            crate::infra::SequencerError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
pub async fn get_ves_validity_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_validity_proof_store
        .get_proof(proof_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
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
pub async fn verify_ves_validity_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_validity_proof_store
        .get_proof(proof_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Validity proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    let commitment = match state.ves_commitment_reader.get_commitment(proof.batch_id).await {
        Ok(Some(commitment)) => commitment,
        Ok(None) => state
            .ves_commitment_engine
            .get_commitment(proof.batch_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    if commitment.tenant_id.0 != proof.tenant_id.0 || commitment.store_id.0 != proof.store_id.0 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Validity proof stream does not match commitment".to_string(),
        ));
    }

    let canonical_public_inputs = ves_validity_public_inputs(&commitment);
    let canonical_public_inputs_hash = canonical_json_hash(&canonical_public_inputs);

    let proof_hash_match =
        compute_ves_validity_proof_hash(&proof.proof) == proof.proof_hash;

    let stored_public_inputs_hash = proof.public_inputs.as_ref().map(canonical_json_hash);
    let public_inputs_match = stored_public_inputs_hash
        .as_ref()
        .is_some_and(|hash| *hash == canonical_public_inputs_hash);
    let public_inputs_hash = stored_public_inputs_hash.map(hex::encode);

    let (valid, reason) = if !proof_hash_match {
        (false, Some("proof_hash_mismatch"))
    } else if proof.public_inputs.is_none() {
        (false, Some("missing_public_inputs"))
    } else if !public_inputs_match {
        (false, Some("public_inputs_mismatch"))
    } else {
        (true, None)
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
        "valid": valid,
        "reason": reason,
    })))
}
