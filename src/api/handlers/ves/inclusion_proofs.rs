//! VES inclusion proof handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::api::auth_helpers::ensure_read;
use crate::api::types::{ProofQuery, VerifyVesProofRequest};
use crate::auth::AuthContextExt;
use crate::domain::{MerkleProof, StoreId, TenantId};
use crate::server::AppState;

/// GET /api/v1/ves/proofs/:sequence_number - Get VES inclusion proof.
pub async fn get_ves_inclusion_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(sequence_number): Path<u64>,
    Query(query): Query<ProofQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    let commitment = state
        .ves_commitment_engine
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
    let leaf_index = (sequence_number - start) as usize;

    let leaves = state
        .ves_commitment_engine
        .leaf_hashes_for_range(&tenant_id, &store_id, start, end)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let computed_root = state.ves_commitment_engine.compute_merkle_root(&leaves);
    if computed_root != commitment.merkle_root {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Commitment merkle_root does not match ves_events".to_string(),
        ));
    }

    let proof = state
        .ves_commitment_engine
        .prove_inclusion(leaf_index, &leaves)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "sequence_number": sequence_number,
        "batch_id": commitment.batch_id,
        "merkle_root": hex::encode(commitment.merkle_root),
        "leaf_hash": hex::encode(proof.leaf_hash),
        "leaf_index": proof.leaf_index,
        "proof_path": proof.proof_path.iter().map(hex::encode).collect::<Vec<_>>(),
        "directions": proof.directions,
    })))
}

/// POST /api/v1/ves/proofs/verify - Verify a VES Merkle proof.
pub async fn verify_ves_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<VerifyVesProofRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !auth.can_read() && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Read permission required".to_string(),
        ));
    }

    let leaf_hash: [u8; 32] = hex::decode(&request.leaf_hash)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid leaf_hash: {}", e)))?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "leaf_hash must be 32 bytes".to_string(),
            )
        })?;

    let merkle_root: [u8; 32] = hex::decode(&request.merkle_root)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid merkle_root: {}", e),
            )
        })?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "merkle_root must be 32 bytes".to_string(),
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
        .ves_commitment_engine
        .verify_inclusion(leaf_hash, &proof, merkle_root);

    Ok(Json(serde_json::json!({
        "valid": valid,
        "leaf_hash": request.leaf_hash,
        "merkle_root": request.merkle_root,
    })))
}
