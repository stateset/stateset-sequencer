//! Legacy Merkle proof handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use std::time::Duration;
use tracing::{debug, instrument};

use crate::api::auth_helpers::ensure_read;
use crate::api::types::{ProofQuery, VerifyProofRequest};
use crate::auth::AuthContextExt;
use crate::crypto::legacy_commitment_leaf_hash;
use crate::domain::{BatchCommitment, MerkleProof, StoreId, TenantId};
use crate::infra::CommitmentEngine;
use crate::server::AppState;

/// GET /api/v1/proofs/:sequence_number - Get inclusion proof for an event.
#[instrument(skip(state, auth), fields(
    sequence_number = sequence_number,
    tenant_id = %query.tenant_id,
    store_id = %query.store_id,
    batch_id = %query.batch_id
))]
pub async fn get_inclusion_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(sequence_number): Path<u64>,
    Query(query): Query<ProofQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("Getting inclusion proof for sequence {}", sequence_number);
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    // Get the commitment (cache -> replica -> primary fallback)
    let commitment_cache = &state.cache_manager.commitments;
    let mut commitment_lock_acquired = false;
    let commitment = if let Some(cached) = commitment_cache.get_by_batch_id(&query.batch_id).await {
        cached.commitment
    } else {
        let (cached, lock_acquired) =
            commitment_cache.get_by_batch_id_with_lock(&query.batch_id).await;
        commitment_lock_acquired = lock_acquired;
        if let Some(cached) = cached {
            cached.commitment
        } else {
            if !lock_acquired {
                tokio::time::sleep(Duration::from_millis(25)).await;
                if let Some(cached) = commitment_cache.get_by_batch_id(&query.batch_id).await {
                    cached.commitment
                } else {
                    match state.commitment_reader.get_commitment(query.batch_id).await {
                        Ok(Some(commitment)) => {
                            commitment_cache
                                .insert(commitment.clone(), commitment.events_root)
                                .await;
                            commitment
                        }
                        Ok(None) => {
                            let fallback = match state
                                .commitment_engine
                                .get_commitment(query.batch_id)
                                .await
                            {
                                Ok(Some(commitment)) => commitment,
                                Ok(None) => {
                                    if lock_acquired {
                                        commitment_cache
                                            .release_batch_id_lock(&query.batch_id)
                                            .await;
                                    }
                                    return Err((
                                        StatusCode::NOT_FOUND,
                                        "Commitment not found".to_string(),
                                    ));
                                }
                                Err(e) => {
                                    if lock_acquired {
                                        commitment_cache
                                            .release_batch_id_lock(&query.batch_id)
                                            .await;
                                    }
                                    return Err((
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        e.to_string(),
                                    ));
                                }
                            };
                            commitment_cache
                                .insert(fallback.clone(), fallback.events_root)
                                .await;
                            fallback
                        }
                        Err(e) => {
                            if lock_acquired {
                                commitment_cache.release_batch_id_lock(&query.batch_id).await;
                            }
                            return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
                        }
                    }
                }
            } else {
                match state.commitment_reader.get_commitment(query.batch_id).await {
                    Ok(Some(commitment)) => {
                        commitment_cache
                            .insert(commitment.clone(), commitment.events_root)
                            .await;
                        commitment
                    }
                    Ok(None) => {
                        let fallback = match state
                            .commitment_engine
                            .get_commitment(query.batch_id)
                            .await
                        {
                            Ok(Some(commitment)) => commitment,
                            Ok(None) => {
                                if lock_acquired {
                                    commitment_cache
                                        .release_batch_id_lock(&query.batch_id)
                                        .await;
                                }
                                return Err((
                                    StatusCode::NOT_FOUND,
                                    "Commitment not found".to_string(),
                                ));
                            }
                            Err(e) => {
                                if lock_acquired {
                                    commitment_cache
                                        .release_batch_id_lock(&query.batch_id)
                                        .await;
                                }
                                return Err((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    e.to_string(),
                                ));
                            }
                        };
                        commitment_cache
                            .insert(fallback.clone(), fallback.events_root)
                            .await;
                        fallback
                    }
                    Err(e) => {
                        if lock_acquired {
                            commitment_cache.release_batch_id_lock(&query.batch_id).await;
                        }
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
                    }
                }
            }
        }
    };

    if commitment_lock_acquired {
        commitment_cache.release_batch_id_lock(&query.batch_id).await;
    }

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
    let mut leaf_inputs = state
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
        // Fallback to primary if replica is lagging.
        leaf_inputs = state
            .sequencer
            .event_store()
            .get_leaf_inputs(&tenant_id, &store_id, start, end)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

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

    let root_v0 = state.commitment_reader.compute_events_root(&leaves_v0);
    let root_v1 = state.commitment_reader.compute_events_root(&leaves_v1);

    let leaves = if root_v1 == commitment.events_root {
        &leaves_v1
    } else if root_v0 == commitment.events_root {
        &leaves_v0
    } else {
        // Retry with primary in case of replica lag.
        let leaf_inputs_primary = state
            .sequencer
            .event_store()
            .get_leaf_inputs(&tenant_id, &store_id, start, end)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let leaves_v0_primary: Vec<[u8; 32]> =
            leaf_inputs_primary.iter().map(|i| i.payload_hash).collect();
        let leaves_v1_primary: Vec<[u8; 32]> = leaf_inputs_primary
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

        let root_v0_primary = state.commitment_reader.compute_events_root(&leaves_v0_primary);
        let root_v1_primary = state.commitment_reader.compute_events_root(&leaves_v1_primary);

        if root_v1_primary == commitment.events_root {
            return generate_cached_proof(
                &state,
                &tenant_id,
                &store_id,
                sequence_number,
                &commitment,
                leaf_index,
                &leaves_v1_primary,
            )
            .await;
        } else if root_v0_primary == commitment.events_root {
            return generate_cached_proof(
                &state,
                &tenant_id,
                &store_id,
                sequence_number,
                &commitment,
                leaf_index,
                &leaves_v0_primary,
            )
            .await;
        } else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Commitment events_root does not match events table".to_string(),
            ));
        }
    };

    // Generate proof (with cache)
    return generate_cached_proof(
        &state,
        &tenant_id,
        &store_id,
        sequence_number,
        &commitment,
        leaf_index,
        leaves,
    )
    .await;
}

async fn generate_cached_proof(
    state: &AppState,
    tenant_id: &TenantId,
    store_id: &StoreId,
    sequence_number: u64,
    commitment: &BatchCommitment,
    leaf_index: usize,
    leaves: &[[u8; 32]],
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof_cache = &state.cache_manager.proofs;

    if let Some(proof) = proof_cache
        .get(&tenant_id.0, &store_id.0, sequence_number)
        .await
    {
        if state
            .commitment_reader
            .verify_inclusion(proof.leaf_hash, &proof, commitment.events_root)
        {
            return Ok(Json(serde_json::json!({
                "sequence_number": sequence_number,
                "batch_id": commitment.batch_id,
                "events_root": hex::encode(commitment.events_root),
                "leaf_hash": hex::encode(proof.leaf_hash),
                "leaf_index": proof.leaf_index,
                "proof_path": proof.proof_path.iter().map(hex::encode).collect::<Vec<_>>(),
                "directions": proof.directions,
            })));
        }
    }

    let (cached, lock_acquired) = proof_cache
        .get_with_lock(&tenant_id.0, &store_id.0, sequence_number)
        .await;
    if let Some(proof) = cached {
        if state
            .commitment_reader
            .verify_inclusion(proof.leaf_hash, &proof, commitment.events_root)
        {
            return Ok(Json(serde_json::json!({
                "sequence_number": sequence_number,
                "batch_id": commitment.batch_id,
                "events_root": hex::encode(commitment.events_root),
                "leaf_hash": hex::encode(proof.leaf_hash),
                "leaf_index": proof.leaf_index,
                "proof_path": proof.proof_path.iter().map(hex::encode).collect::<Vec<_>>(),
                "directions": proof.directions,
            })));
        }
    }

    if !lock_acquired {
        tokio::time::sleep(Duration::from_millis(25)).await;
        if let Some(proof) = proof_cache
            .get(&tenant_id.0, &store_id.0, sequence_number)
            .await
        {
            if state
                .commitment_reader
                .verify_inclusion(proof.leaf_hash, &proof, commitment.events_root)
            {
                return Ok(Json(serde_json::json!({
                    "sequence_number": sequence_number,
                    "batch_id": commitment.batch_id,
                    "events_root": hex::encode(commitment.events_root),
                    "leaf_hash": hex::encode(proof.leaf_hash),
                    "leaf_index": proof.leaf_index,
                    "proof_path": proof.proof_path.iter().map(hex::encode).collect::<Vec<_>>(),
                    "directions": proof.directions,
                })));
            }
        }
    }

    let proof = state.commitment_reader.prove_inclusion(leaf_index, leaves);
    proof_cache
        .insert(tenant_id.0, store_id.0, sequence_number, proof.clone())
        .await;
    if lock_acquired {
        proof_cache
            .release_lock(&tenant_id.0, &store_id.0, sequence_number)
            .await;
    }

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
#[instrument(skip(state, auth, request), fields(leaf_index = request.leaf_index))]
pub async fn verify_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<VerifyProofRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("Verifying Merkle proof");
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
        .commitment_reader
        .verify_inclusion(leaf_hash, &proof, events_root);

    Ok(Json(serde_json::json!({
        "valid": valid,
        "leaf_hash": request.leaf_hash,
        "events_root": request.events_root,
    })))
}
