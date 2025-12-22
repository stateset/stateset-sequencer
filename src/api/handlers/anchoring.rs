//! Legacy anchor handlers.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_admin, ensure_read};
use crate::api::types::AnchorRequest;
use crate::auth::AuthContextExt;
use crate::infra::CommitmentEngine;
use crate::server::AppState;

/// POST /api/v1/anchor - Anchor a commitment on-chain.
pub async fn anchor_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<AnchorRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Check if anchor service is configured
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    // Get the commitment
    let commitment = state
        .commitment_engine
        .get_commitment(request.batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    ensure_admin(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

    // Check if already anchored
    if commitment.is_anchored() {
        return Ok(Json(serde_json::json!({
            "batch_id": commitment.batch_id,
            "status": "already_anchored",
            "chain_tx_hash": commitment.chain_tx_hash.map(hex::encode),
        })));
    }

    // Anchor on-chain
    let tx_hash = anchor_service
        .anchor_commitment(&commitment)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update commitment with chain tx hash
    state
        .commitment_engine
        .update_chain_tx(request.batch_id, tx_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "status": "anchored",
        "chain_tx_hash": hex::encode(tx_hash),
        "events_root": hex::encode(commitment.events_root),
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
    })))
}

/// GET /api/v1/anchor/status - Get anchor service status.
pub async fn get_anchor_status(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !auth.can_read() && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Read permission required".to_string(),
        ));
    }

    let anchor_configured = state.anchor_service.is_some();

    Ok(Json(serde_json::json!({
        "anchor_enabled": anchor_configured,
        "message": if anchor_configured {
            "Anchor service is configured and ready"
        } else {
            "Anchor service not configured. Set L2_RPC_URL, SET_REGISTRY_ADDRESS, SEQUENCER_PRIVATE_KEY"
        }
    })))
}

/// GET /api/v1/anchor/:batch_id/verify - Verify commitment is anchored on-chain.
pub async fn verify_anchor_onchain(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Check if anchor service is configured
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    let is_anchored = anchor_service
        .verify_anchored(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // If we can find a local commitment, enforce tenant/store access.
    if let Ok(Some(commitment)) = state.commitment_engine.get_commitment(batch_id).await {
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
