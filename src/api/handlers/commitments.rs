//! Legacy commitment handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use std::time::Duration;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_read, ensure_write};
use crate::api::types::{CreateCommitmentRequest, HeadQuery};
use crate::auth::AuthContextExt;
use crate::domain::{StoreId, TenantId};
use crate::infra::CommitmentEngine;
use crate::server::AppState;

/// GET /api/v1/commitments/:batch_id - Get a commitment by ID.
#[instrument(skip(state, auth), fields(batch_id = %batch_id))]
pub async fn get_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("Getting commitment by ID");
    let cache = &state.cache_manager.commitments;
    if let Some(cached) = cache.get_by_batch_id(&batch_id).await {
        ensure_read(&auth, cached.commitment.tenant_id.0, cached.commitment.store_id.0)?;
        return Ok(Json(serde_json::json!(cached.commitment)));
    }

    let (cached, lock_acquired) = cache.get_by_batch_id_with_lock(&batch_id).await;
    if let Some(cached) = cached {
        ensure_read(&auth, cached.commitment.tenant_id.0, cached.commitment.store_id.0)?;
        return Ok(Json(serde_json::json!(cached.commitment)));
    }

    if !lock_acquired {
        tokio::time::sleep(Duration::from_millis(25)).await;
        if let Some(cached) = cache.get_by_batch_id(&batch_id).await {
            ensure_read(&auth, cached.commitment.tenant_id.0, cached.commitment.store_id.0)?;
            return Ok(Json(serde_json::json!(cached.commitment)));
        }
    }

    let commitment = match state.commitment_reader.get_commitment(batch_id).await {
        Ok(Some(commitment)) => Some(commitment),
        Ok(None) => {
            // Fallback to primary in case of replica lag.
            match state.commitment_engine.get_commitment(batch_id).await {
                Ok(commitment) => commitment,
                Err(e) => {
                    if lock_acquired {
                        cache.release_batch_id_lock(&batch_id).await;
                    }
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
                }
            }
        }
        Err(e) => {
            if lock_acquired {
                cache.release_batch_id_lock(&batch_id).await;
            }
            return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        }
    };

    if let Some(commitment) = commitment {
        if let Err(err) = ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0) {
            if lock_acquired {
                cache.release_batch_id_lock(&batch_id).await;
            }
            return Err(err);
        }
        cache
            .insert(commitment.clone(), commitment.events_root)
            .await;
        if lock_acquired {
            cache.release_batch_id_lock(&batch_id).await;
        }
        return Ok(Json(serde_json::json!(commitment)));
    }

    if lock_acquired {
        cache.release_batch_id_lock(&batch_id).await;
    }
    Err((StatusCode::NOT_FOUND, "Commitment not found".to_string()))
}

/// POST /api/v1/commitments - Create a commitment.
#[instrument(skip(state, auth, request), fields(
    tenant_id = %request.tenant_id,
    store_id = %request.store_id,
    sequence_start = request.sequence_start,
    sequence_end = request.sequence_end
))]
pub async fn create_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<CreateCommitmentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    info!("Creating commitment for sequence range {}..{}", request.sequence_start, request.sequence_end);
    ensure_write(&auth, request.tenant_id, request.store_id)?;

    let tenant_id = TenantId::from_uuid(request.tenant_id);
    let store_id = StoreId::from_uuid(request.store_id);

    // Create and store the commitment atomically.
    let commitment = state
        .commitment_engine
        .create_and_store_commitment(
            &tenant_id,
            &store_id,
            (request.sequence_start, request.sequence_end),
        )
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    state
        .cache_manager
        .commitments
        .insert(commitment.clone(), commitment.events_root)
        .await;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "tenant_id": commitment.tenant_id.0,
        "store_id": commitment.store_id.0,
        "prev_state_root": hex::encode(commitment.prev_state_root),
        "new_state_root": hex::encode(commitment.new_state_root),
        "events_root": hex::encode(commitment.events_root),
        "event_count": commitment.event_count,
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
        "committed_at": commitment.committed_at,
    })))
}

/// GET /api/v1/commitments - List commitments.
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    store_id = %query.store_id
))]
pub async fn list_commitments(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("Listing commitments");
    ensure_read(&auth, query.tenant_id, query.store_id)?;

    // List all unanchored commitments for now, then filter by tenant/store.
    let commitments = state
        .commitment_reader
        .list_unanchored_by_stream(
            &TenantId::from_uuid(query.tenant_id),
            &StoreId::from_uuid(query.store_id),
            None,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<serde_json::Value> = commitments
        .iter()
        .map(|c| {
            serde_json::json!({
                "batch_id": c.batch_id,
                "tenant_id": c.tenant_id.0,
                "store_id": c.store_id.0,
                "events_root": hex::encode(c.events_root),
                "event_count": c.event_count,
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
