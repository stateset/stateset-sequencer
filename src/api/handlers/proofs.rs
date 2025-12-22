//! Legacy Merkle proof handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::api::auth_helpers::ensure_read;
use crate::api::types::{ProofQuery, VerifyProofRequest};
use crate::auth::AuthContextExt;
use crate::crypto::legacy_commitment_leaf_hash;
use crate::domain::{MerkleProof, StoreId, TenantId};
use crate::infra::CommitmentEngine;
use crate::server::AppState;

/// GET /api/v1/proofs/:sequence_number - Get inclusion proof for an event.
pub async fn get_inclusion_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(sequence_number): Path<u64>,
    Query(query): Query<ProofQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    // Get the commitment
    let commitment = state
        .commitment_engine
        .get_commitment(query.batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    if commitment.tenant_id.0 != tenant_id.0 || commitment.store_id.0 != store_id.0 {
        return Err((
            StatusCode::FORBIDDEN,
            "Commitment access denied".to_string(),
        ));
    }

    // Verify sequence is in range
    if sequence_number < commitment.sequence_range.0
        || sequence_number > commitment.sequence_range.1
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Sequence number not in commitment range".to_string(),
        ));
    }

    let start = commitment.sequence_range.0;
    let end = commitment.sequence_range.1;

    // Get leaf inputs for the commitment range.
    let leaf_inputs = state
        .event_store
        .get_leaf_inputs(&tenant_id, &store_id, start, end)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if leaf_inputs.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Commitment range contains no events".to_string(),
        ));
    }

    let expected_len = end
        .checked_sub(start)
        .and_then(|d| d.checked_add(1))
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Invalid sequence range".to_string(),
        ))?;

    if leaf_inputs.len() as u64 != expected_len {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Commitment range {}..={} contains {} events but expected {}",
                start,
                end,
                leaf_inputs.len(),
                expected_len
            ),
        ));
    }

    // Find the leaf index
    let leaf_index = (sequence_number - start) as usize;
    if leaf_index >= leaf_inputs.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid sequence number".to_string(),
        ));
    }

    if leaf_inputs[leaf_index].sequence_number != sequence_number {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Non-contiguous sequence numbers in commitment range".to_string(),
        ));
    }

    // Build leaves (supporting legacy commitments that used payload hashes directly).
    let leaves_v0: Vec<[u8; 32]> = leaf_inputs.iter().map(|i| i.payload_hash).collect();
    let leaves_v1: Vec<[u8; 32]> = leaf_inputs
        .iter()
        .map(|i| {
            legacy_commitment_leaf_hash(
                &tenant_id.0,
                &store_id.0,
                i.sequence_number,
                &i.payload_hash,
                &i.entity_type,
                &i.entity_id,
            )
        })
        .collect();

    let root_v0 = state.commitment_engine.compute_events_root(&leaves_v0);
    let root_v1 = state.commitment_engine.compute_events_root(&leaves_v1);

    let leaves = if root_v1 == commitment.events_root {
        &leaves_v1
    } else if root_v0 == commitment.events_root {
        &leaves_v0
    } else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Commitment events_root does not match events table".to_string(),
        ));
    };

    // Generate proof
    let proof = state.commitment_engine.prove_inclusion(leaf_index, leaves);

    Ok(Json(serde_json::json!({
        "sequence_number": sequence_number,
        "batch_id": commitment.batch_id,
        "events_root": hex::encode(commitment.events_root),
        "leaf_hash": hex::encode(proof.leaf_hash),
        "leaf_index": proof.leaf_index,
        "proof_path": proof.proof_path.iter().map(hex::encode).collect::<Vec<_>>(),
        "directions": proof.directions,
    })))
}

/// POST /api/v1/proofs/verify - Verify a Merkle proof.
pub async fn verify_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<VerifyProofRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !auth.can_read() && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Read permission required".to_string(),
        ));
    }

    // Parse hex strings
    let leaf_hash: [u8; 32] = hex::decode(&request.leaf_hash)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid leaf_hash: {}", e)))?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "leaf_hash must be 32 bytes".to_string(),
            )
        })?;

    let events_root: [u8; 32] = hex::decode(&request.events_root)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid events_root: {}", e),
            )
        })?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "events_root must be 32 bytes".to_string(),
            )
        })?;

    let proof_path: Vec<[u8; 32]> = request
        .proof_path
        .iter()
        .map(|h| {
            hex::decode(h)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid proof hash: {}", e),
                    )
                })
                .and_then(|bytes| {
                    bytes.try_into().map_err(|_| {
                        (
                            StatusCode::BAD_REQUEST,
                            "Each proof hash must be 32 bytes".to_string(),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let proof = MerkleProof::new(leaf_hash, proof_path, request.leaf_index);

    let valid = state
        .commitment_engine
        .verify_inclusion(leaf_hash, &proof, events_root);

    Ok(Json(serde_json::json!({
        "valid": valid,
        "leaf_hash": request.leaf_hash,
        "events_root": request.events_root,
    })))
}
