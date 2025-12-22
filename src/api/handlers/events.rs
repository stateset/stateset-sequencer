//! Event read handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::api::auth_helpers::ensure_read;
use crate::api::types::{HeadQuery, ListEventsQuery};
use crate::auth::AuthContextExt;
use crate::domain::{EntityType, StoreId, TenantId};
use crate::infra::{EventStore, Sequencer};
use crate::server::AppState;

/// GET /api/v1/events - List events for a tenant/store.
pub async fn list_events(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<ListEventsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);
    let from = query.from.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(1000) as u64;

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    if limit == 0 {
        return Ok(Json(serde_json::json!({
            "events": [],
            "count": 0,
        })));
    }

    let end = from.saturating_add(limit.saturating_sub(1));

    match state
        .event_store
        .read_range(&tenant_id, &store_id, from, end)
        .await
    {
        Ok(events) => Ok(Json(serde_json::json!({
            "events": events,
            "count": events.len(),
        }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// GET /api/v1/head - Get head sequence for a tenant/store.
pub async fn get_head(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    match state.sequencer.head(&tenant_id, &store_id).await {
        Ok(head) => Ok(Json(serde_json::json!({ "head_sequence": head }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// GET /api/v1/entities/:entity_type/:entity_id - Get event history for an entity.
pub async fn get_entity_history(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path((entity_type, entity_id)): Path<(String, String)>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);
    let entity_type = EntityType::from(entity_type.as_str());

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    match state
        .event_store
        .read_entity(&tenant_id, &store_id, &entity_type, &entity_id)
        .await
    {
        Ok(events) => Ok(Json(serde_json::json!({
            "entity_type": entity_type.as_str(),
            "entity_id": entity_id,
            "events": events,
            "count": events.len(),
        }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
