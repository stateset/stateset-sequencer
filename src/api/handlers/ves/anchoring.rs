//! VES anchor handlers.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_admin, ensure_read};
use crate::api::types::AnchorRequest;
use crate::auth::AuthContextExt;
use crate::server::AppState;

/// POST /api/v1/ves/anchor - Anchor a VES commitment on-chain.
pub async fn anchor_ves_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<AnchorRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    let commitment = state
        .ves_commitment_engine
        .get_commitment(request.batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    ensure_admin(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

    if commitment.is_anchored() {
        return Ok(Json(serde_json::json!({
            "batch_id": commitment.batch_id,
            "status": "already_anchored",
            "chain_tx_hash": commitment.chain_tx_hash.map(hex::encode),
        })));
    }

    let (tx_hash, chain_block_number) = anchor_service
        .anchor_ves_commitment(&commitment)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .ves_commitment_engine
        .update_chain_tx(
            request.batch_id,
            anchor_service.chain_id() as u32,
            tx_hash,
            chain_block_number,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "status": "anchored",
        "chain_tx_hash": hex::encode(tx_hash),
        "chain_block_number": chain_block_number,
        "merkle_root": hex::encode(commitment.merkle_root),
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
    })))
}

/// GET /api/v1/ves/anchor/:batch_id/verify - Verify VES commitment is anchored on-chain.
pub async fn verify_ves_anchor_onchain(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    let is_anchored = anchor_service
        .verify_anchored(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Ok(Some(commitment)) = state.ves_commitment_engine.get_commitment(batch_id).await {
        ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;
    } else if !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Commitment access denied".to_string(),
        ));
    }

    Ok(Json(serde_json::json!({
        "batch_id": batch_id,
        "anchored_on_chain": is_anchored,
    })))
}
