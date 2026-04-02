//! VES commitment handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use std::collections::HashSet;
use tracing::instrument;
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_admin, ensure_read, ensure_write, is_bootstrap_admin};
use crate::api::types::{
    AnchorNotificationRequest, CommitAndAnchorVesRequest, CreateCommitmentRequest, HeadQuery,
    PendingCommitmentsQuery,
};
use crate::api::utils::internal_error;
use crate::auth::AuthContextExt;
use crate::domain::{Hash256, StoreId, TenantId, VesBatchCommitment};
use crate::server::AppState;

fn merge_unique_ves_commitments(
    replica_commitments: Vec<VesBatchCommitment>,
    primary_commitments: Vec<VesBatchCommitment>,
) -> Vec<VesBatchCommitment> {
    let mut seen = HashSet::new();
    let mut merged = Vec::new();

    for commitment in replica_commitments.into_iter().chain(primary_commitments) {
        if seen.insert(commitment.batch_id) {
            merged.push(commitment);
        }
    }

    merged.sort_by_key(|commitment| (commitment.committed_at, commitment.batch_id));
    merged
}

/// GET /api/v1/ves/commitments - List VES commitments.
#[instrument(skip(state, auth, query))]
pub async fn list_ves_commitments(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_read(&auth, query.tenant_id, query.store_id)?;

    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    let replica_commitments = state
        .ves_commitment_reader
        .list_unanchored(&tenant_id, &store_id)
        .await;
    let primary_commitments = state
        .ves_commitment_engine
        .list_unanchored(&tenant_id, &store_id)
        .await;

    let commitments = match (replica_commitments, primary_commitments) {
        (Ok(replica), Ok(primary)) => merge_unique_ves_commitments(replica, primary),
        (Ok(replica), Err(_)) => replica,
        (Err(_), Ok(primary)) => primary,
        (Err(err), Err(_)) => return Err(internal_error(err)),
    };

    let response: Vec<serde_json::Value> = commitments
        .iter()
        .map(|c| {
            serde_json::json!({
                "batch_id": c.batch_id,
                "tenant_id": c.tenant_id.0,
                "store_id": c.store_id.0,
                "ves_version": c.ves_version,
                "tree_depth": c.tree_depth,
                "leaf_count": c.leaf_count,
                "padded_leaf_count": c.padded_leaf_count,
                "merkle_root": hex::encode(c.merkle_root),
                "prev_state_root": hex::encode(c.prev_state_root),
                "new_state_root": hex::encode(c.new_state_root),
                "sequence_start": c.sequence_range.0,
                "sequence_end": c.sequence_range.1,
                "committed_at": c.committed_at,
                "is_anchored": c.is_anchored(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "commitments": response,
        "count": response.len(),
    })))
}

/// GET /api/v1/ves/commitments/:batch_id - Get a VES commitment.
#[instrument(skip(state, auth), fields(batch_id = %batch_id))]
pub async fn get_ves_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let commitment = super::get_ves_commitment_cached(&state, batch_id).await?;
    ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;
    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "tenant_id": commitment.tenant_id.0,
        "store_id": commitment.store_id.0,
        "ves_version": commitment.ves_version,
        "tree_depth": commitment.tree_depth,
        "leaf_count": commitment.leaf_count,
        "padded_leaf_count": commitment.padded_leaf_count,
        "merkle_root": hex::encode(commitment.merkle_root),
        "prev_state_root": hex::encode(commitment.prev_state_root),
        "new_state_root": hex::encode(commitment.new_state_root),
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
        "committed_at": commitment.committed_at,
        "chain_id": commitment.chain_id,
        "chain_tx_hash": commitment.chain_tx_hash.map(hex::encode),
        "chain_block_number": commitment.chain_block_number,
        "anchored_at": commitment.anchored_at,
        "is_anchored": commitment.is_anchored(),
    })))
}

/// POST /api/v1/ves/commitments - Create a VES commitment.
#[instrument(skip(state, auth, request))]
pub async fn create_ves_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<CreateCommitmentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_write(&auth, request.tenant_id, request.store_id)?;

    let tenant_id = TenantId::from_uuid(request.tenant_id);
    let store_id = StoreId::from_uuid(request.store_id);

    let commitment = state
        .ves_commitment_engine
        .create_and_store_commitment(
            &tenant_id,
            &store_id,
            (request.sequence_start, request.sequence_end),
        )
        .await
        .map_err(|e| match e {
            crate::infra::SequencerError::Database(_) => internal_error(e),
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        })?;

    state
        .cache_manager
        .ves_commitments
        .insert(commitment.clone())
        .await;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "tenant_id": commitment.tenant_id.0,
        "store_id": commitment.store_id.0,
        "ves_version": commitment.ves_version,
        "tree_depth": commitment.tree_depth,
        "leaf_count": commitment.leaf_count,
        "padded_leaf_count": commitment.padded_leaf_count,
        "merkle_root": hex::encode(commitment.merkle_root),
        "prev_state_root": hex::encode(commitment.prev_state_root),
        "new_state_root": hex::encode(commitment.new_state_root),
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
        "committed_at": commitment.committed_at,
    })))
}

/// POST /api/v1/ves/commitments/anchor - Create and anchor a VES commitment in one call.
#[instrument(skip(state, auth, request))]
pub async fn commit_and_anchor_ves_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<CommitAndAnchorVesRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    ensure_admin(&auth, request.tenant_id, request.store_id)?;

    let tenant_id = TenantId::from_uuid(request.tenant_id);
    let store_id = StoreId::from_uuid(request.store_id);

    let (start, end) = match (request.sequence_start, request.sequence_end) {
        (Some(start), Some(end)) => (start, end),
        (None, None) => {
            let head = state
                .ves_sequencer
                .head(&tenant_id, &store_id)
                .await
                .map_err(internal_error)?;

            if head == 0 {
                return Err((StatusCode::BAD_REQUEST, "no events to commit".to_string()));
            }

            let last_end = state
                .ves_commitment_engine
                .last_sequence_end(&tenant_id, &store_id)
                .await
                .map_err(internal_error)?;
            let start = last_end.map(|v| v.saturating_add(1)).unwrap_or(1);
            if start > head {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("no new events to commit (head_sequence={head})"),
                ));
            }

            let max_events = request.max_events.unwrap_or(1024).max(1);
            let end = start.saturating_add(max_events.saturating_sub(1)).min(head);
            (start, end)
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "sequence_start and sequence_end must be provided together".to_string(),
            ))
        }
    };

    let commitment = state
        .ves_commitment_engine
        .create_and_store_commitment(&tenant_id, &store_id, (start, end))
        .await
        .map_err(|e| match e {
            crate::infra::SequencerError::Database(_) => internal_error(e),
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        })?;

    state
        .cache_manager
        .ves_commitments
        .insert(commitment.clone())
        .await;

    if commitment.is_submitted() {
        return Ok(Json(serde_json::json!({
            "batch_id": commitment.batch_id,
            "status": "already_anchored",
            "chain_id": commitment.chain_id,
            "chain_tx_hash": commitment.chain_tx_hash.map(hex::encode),
            "chain_block_number": commitment.chain_block_number,
            "merkle_root": hex::encode(commitment.merkle_root),
            "prev_state_root": hex::encode(commitment.prev_state_root),
            "new_state_root": hex::encode(commitment.new_state_root),
            "sequence_start": commitment.sequence_range.0,
            "sequence_end": commitment.sequence_range.1,
        })));
    }

    let (tx_hash, chain_block_number) = anchor_service
        .anchor_ves_commitment(&commitment)
        .await
        .map_err(internal_error)?;

    state
        .ves_commitment_engine
        .update_chain_tx(
            commitment.batch_id,
            anchor_service.chain_id() as u32,
            tx_hash,
            chain_block_number,
        )
        .await
        .map_err(internal_error)?;

    state
        .cache_manager
        .ves_commitments
        .invalidate(&commitment.batch_id)
        .await;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "status": "anchored",
        "chain_id": anchor_service.chain_id(),
        "chain_tx_hash": hex::encode(tx_hash),
        "chain_block_number": chain_block_number,
        "merkle_root": hex::encode(commitment.merkle_root),
        "prev_state_root": hex::encode(commitment.prev_state_root),
        "new_state_root": hex::encode(commitment.new_state_root),
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
    })))
}

/// GET /v1/commitments/pending - List pending (unanchored) VES commitments (anchor compat).
#[instrument(skip(state, auth, query))]
pub async fn list_pending_ves_commitments(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<PendingCommitmentsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !is_bootstrap_admin(&auth) {
        return Err((
            StatusCode::FORBIDDEN,
            "Bootstrap admin permission required".to_string(),
        ));
    }

    let limit = query.limit.unwrap_or(1000).min(5000) as usize;
    let commitments = state
        .ves_commitment_reader
        .list_unanchored_global(limit)
        .await
        .map_err(internal_error)?;

    let commitments: Vec<serde_json::Value> = commitments
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "batch_id": c.batch_id,
                "tenant_id": c.tenant_id.0,
                "store_id": c.store_id.0,
                "prev_state_root": format!("0x{}", hex::encode(c.prev_state_root)),
                "new_state_root": format!("0x{}", hex::encode(c.new_state_root)),
                "events_root": format!("0x{}", hex::encode(c.merkle_root)),
                "sequence_start": c.sequence_range.0,
                "sequence_end": c.sequence_range.1,
                "event_count": c.leaf_count,
                "committed_at": c.committed_at,
                "chain_tx_hash": c.chain_tx_hash.map(|h| format!("0x{}", hex::encode(h))),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "commitments": commitments,
        "total": commitments.len(),
    })))
}

/// POST /v1/commitments/:batch_id/anchored - Notify anchor completion (anchor compat).
#[instrument(skip(state, auth, request), fields(batch_id = %batch_id))]
pub async fn notify_ves_commitment_anchored(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
    Json(request): Json<AnchorNotificationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !is_bootstrap_admin(&auth) {
        return Err((
            StatusCode::FORBIDDEN,
            "Bootstrap admin permission required".to_string(),
        ));
    }

    let commitment = super::get_ves_commitment_cached(&state, batch_id).await?;

    let chain_id: u32 = request.chain_id.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "chain_id must fit in u32".to_string(),
        )
    })?;

    let tx_hash_str = request.chain_tx_hash.trim();
    if tx_hash_str.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "chain_tx_hash must not be empty".to_string(),
        ));
    }
    let tx_hash_str = tx_hash_str.strip_prefix("0x").unwrap_or(tx_hash_str);
    let tx_hash_bytes = hex::decode(tx_hash_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid chain_tx_hash: {e}"),
        )
    })?;
    let tx_hash: Hash256 = tx_hash_bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "chain_tx_hash must be 32 bytes".to_string(),
        )
    })?;

    if commitment.is_submitted() {
        let existing = commitment.chain_tx_hash.ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Commitment marked as submitted but missing tx hash".to_string(),
        ))?;
        if existing == tx_hash {
            return Ok(Json(serde_json::json!({
                "batch_id": batch_id,
                "status": "already_anchored",
            })));
        }

        return Err((
            StatusCode::CONFLICT,
            "commitment already anchored with different tx hash".to_string(),
        ));
    }

    state
        .ves_commitment_engine
        .update_chain_tx(batch_id, chain_id, tx_hash, request.block_number)
        .await
        .map_err(internal_error)?;

    state
        .cache_manager
        .ves_commitments
        .invalidate(&batch_id)
        .await;

    let _ = request.gas_used;

    Ok(Json(serde_json::json!({
        "batch_id": batch_id,
        "status": "anchored",
        "chain_tx_hash": format!("0x{}", hex::encode(tx_hash)),
        "chain_id": chain_id,
        "block_number": request.block_number,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_unique_ves_commitments_dedupes_and_sorts() {
        let tenant_id = TenantId::new();
        let store_id = StoreId::new();
        let first = VesBatchCommitment::new(tenant_id, store_id, 1, 1, 1, [1u8; 32], (1, 1));
        let second = VesBatchCommitment::new(tenant_id, store_id, 1, 1, 1, [2u8; 32], (2, 2));

        let merged = merge_unique_ves_commitments(
            vec![second.clone(), first.clone()],
            vec![first.clone(), second.clone()],
        );

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].batch_id, first.batch_id);
        assert_eq!(merged[1].batch_id, second.batch_id);
    }
}
