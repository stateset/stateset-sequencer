//! VES commitment handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_admin, ensure_read, ensure_write, is_bootstrap_admin};
use crate::api::types::{
    AnchorNotificationRequest, CommitAndAnchorVesRequest, CreateCommitmentRequest, HeadQuery,
    PendingCommitmentsQuery,
};
use crate::auth::AuthContextExt;
use crate::domain::{Hash256, StoreId, TenantId};
use crate::server::AppState;

/// GET /api/v1/ves/commitments - List VES commitments.
pub async fn list_ves_commitments(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_read(&auth, query.tenant_id, query.store_id)?;

    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    let commitments = state
        .ves_commitment_engine
        .list_unanchored(&tenant_id, &store_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
pub async fn get_ves_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.ves_commitment_engine.get_commitment(batch_id).await {
        Ok(Some(commitment)) => {
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
        Ok(None) => Err((StatusCode::NOT_FOUND, "Commitment not found".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// POST /api/v1/ves/commitments - Create a VES commitment.
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
            crate::infra::SequencerError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        })?;

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
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            if head == 0 {
                return Err((StatusCode::BAD_REQUEST, "no events to commit".to_string()));
            }

            let last_end = state
                .ves_commitment_engine
                .last_sequence_end(&tenant_id, &store_id)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let start = last_end.map(|v| v.saturating_add(1)).unwrap_or(1);
            if start > head {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("no new events to commit (head_sequence={head})"),
                ));
            }

            let max_events = request.max_events.unwrap_or(1024).max(1);
            let end = start
                .checked_add(max_events.saturating_sub(1))
                .unwrap_or(u64::MAX)
                .min(head);
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
            crate::infra::SequencerError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        })?;

    if commitment.is_anchored() {
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .ves_commitment_engine
        .update_chain_tx(
            commitment.batch_id,
            anchor_service.chain_id() as u32,
            tx_hash,
            chain_block_number,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
        .ves_commitment_engine
        .list_unanchored_global(limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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

    let commitment = state
        .ves_commitment_engine
        .get_commitment(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

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

    if commitment.is_anchored() {
        let existing = commitment
            .chain_tx_hash
            .expect("is_anchored implies tx hash");
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = request.gas_used;

    Ok(Json(serde_json::json!({
        "batch_id": batch_id,
        "status": "anchored",
        "chain_tx_hash": format!("0x{}", hex::encode(tx_hash)),
        "chain_id": chain_id,
        "block_number": request.block_number,
    })))
}
