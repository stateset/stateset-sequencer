//! VES compliance proof handlers.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_read, ensure_write};
use crate::api::handlers::ves::ves_compliance_public_inputs;
use crate::api::types::{SubmitVesComplianceProofRequest, VesComplianceInputsRequest};
use crate::api::utils::decode_base64_any;
use crate::auth::AuthContextExt;
use crate::crypto::{
    canonical_json_hash, compute_ves_compliance_policy_hash, compute_ves_compliance_proof_hash,
};
use crate::server::AppState;

/// POST /api/v1/ves/compliance/:event_id/inputs - Get compliance public inputs.
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
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
        None => Some(canonical_inputs),
    };

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
        "event_id": summary.event_id,
        "tenant_id": summary.tenant_id.0,
        "store_id": summary.store_id.0,
        "proof_type": summary.proof_type,
        "proof_version": summary.proof_version,
        "policy_id": summary.policy_id,
        "policy_params": summary.policy_params,
        "policy_hash": hex::encode(summary.policy_hash),
        "proof_hash": hex::encode(summary.proof_hash),
        "public_inputs": summary.public_inputs,
        "submitted_at": summary.submitted_at,
    })))
}

/// GET /api/v1/ves/compliance/:event_id/proofs - List compliance proofs for an event.
pub async fn list_ves_compliance_proofs(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(event_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(event_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    ensure_read(&auth, inputs.tenant_id.0, inputs.store_id.0)?;

    let proofs = state
        .ves_compliance_proof_store
        .list_proofs_for_event(event_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
pub async fn get_ves_compliance_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_compliance_proof_store
        .get_proof(proof_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
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
        "proof_b64": base64::engine::general_purpose::STANDARD.encode(proof.proof),
        "public_inputs": proof.public_inputs,
        "submitted_at": proof.submitted_at,
    })))
}

/// GET /api/v1/ves/compliance/proofs/:proof_id/verify - Verify a compliance proof.
pub async fn verify_ves_compliance_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_compliance_proof_store
        .get_proof(proof_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Compliance proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(proof.event_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
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

    let proof_hash_match =
        compute_ves_compliance_proof_hash(&proof.proof) == proof.proof_hash;

    let stored_policy_hash_ok = proof.policy_hash == computed_policy_hash;

    let stored_public_inputs_hash = proof.public_inputs.as_ref().map(canonical_json_hash);
    let public_inputs_match = stored_public_inputs_hash
        .as_ref()
        .is_some_and(|hash| *hash == canonical_public_inputs_hash);
    let public_inputs_hash = stored_public_inputs_hash.map(hex::encode);

    let (valid, reason) = if !proof_hash_match {
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
        "valid": valid,
        "reason": reason,
    })))
}
