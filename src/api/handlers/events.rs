//! Event read handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use tracing::{debug, instrument};

use crate::api::auth_helpers::ensure_read;
use crate::api::types::{EntityHistoryQuery, HeadQuery, ListEventsQuery};
use crate::api::utils::internal_error;
use crate::auth::AuthContextExt;
use crate::domain::{EntityType, StoreId, TenantId};
use crate::infra::{EventStore, Sequencer, SequencerError};
use crate::server::AppState;

fn map_read_range_error(err: SequencerError) -> (StatusCode, String) {
    match err {
        SequencerError::InvariantViolation { invariant, message }
            if invariant == "sequence_range" =>
        {
            (StatusCode::CONFLICT, message)
        }
        _ => internal_error(err),
    }
}

/// Hard max for entity history results to prevent unbounded responses.
const MAX_ENTITY_HISTORY: usize = 100;
/// Maximum length for entity_type path parameter.
const MAX_ENTITY_TYPE_LEN: usize = 128;
/// Maximum length for entity_id path parameter.
const MAX_ENTITY_ID_LEN: usize = 512;

/// GET /api/v1/events - List events for a tenant/store.
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    store_id = %query.store_id,
    from = query.from,
    limit = query.limit
))]
pub async fn list_events(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<ListEventsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("Listing events for tenant/store");
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);
    let from = query.from.unwrap_or(0);
    let requested_limit = query.limit.unwrap_or(100);
    if requested_limit == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "limit must be greater than 0".to_string(),
        ));
    }
    let limit = requested_limit.min(1000) as u64;

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    let end = from.saturating_add(limit.saturating_sub(1));

    let mut events = state
        .event_store
        .read_range(&tenant_id, &store_id, from, end)
        .await
        .map_err(map_read_range_error)?;

    if events.is_empty() {
        let head = state
            .sequencer
            .head(&tenant_id, &store_id)
            .await
            .map_err(internal_error)?;
        let expected_start = if from == 0 { 1 } else { from };
        if head >= expected_start {
            events = state
                .sequencer
                .event_store()
                .read_range(&tenant_id, &store_id, from, end)
                .await
                .map_err(map_read_range_error)?;
        }
    }

    Ok(Json(serde_json::json!({
        "events": events,
        "count": events.len(),
    })))
}

/// GET /api/v1/head - Get head sequence for a tenant/store.
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    store_id = %query.store_id
))]
pub async fn get_head(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("Getting head sequence");
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    match state.sequencer.head(&tenant_id, &store_id).await {
        Ok(head) => Ok(Json(serde_json::json!({ "head_sequence": head }))),
        Err(e) => Err(internal_error(e)),
    }
}

/// GET /api/v1/entities/:entity_type/:entity_id - Get event history for an entity.
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    store_id = %query.store_id,
    entity_type = %entity_type,
    entity_id = %entity_id
))]
pub async fn get_entity_history(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path((entity_type, entity_id)): Path<(String, String)>,
    Query(query): Query<EntityHistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("Getting entity history");

    if entity_type.is_empty() || entity_type.len() > MAX_ENTITY_TYPE_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "entity_type must be between 1 and {} characters",
                MAX_ENTITY_TYPE_LEN
            ),
        ));
    }
    if entity_id.is_empty() || entity_id.len() > MAX_ENTITY_ID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "entity_id must be between 1 and {} characters",
                MAX_ENTITY_ID_LEN
            ),
        ));
    }

    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);
    let entity_type = EntityType::from(entity_type.as_str());
    let offset_u64 = query.from.unwrap_or(0);
    let offset = usize::try_from(offset_u64).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "from offset exceeds platform limit".to_string(),
        )
    })?;
    let requested_limit = query.limit.unwrap_or(MAX_ENTITY_HISTORY as u32);
    let limit = if requested_limit == 0 {
        MAX_ENTITY_HISTORY as u32
    } else {
        requested_limit
    }
    .min(MAX_ENTITY_HISTORY as u32) as usize;

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    match state
        .event_store
        .read_entity(&tenant_id, &store_id, &entity_type, &entity_id)
        .await
    {
        Ok(events) => {
            let total = events.len();
            let page: Vec<_> = events.into_iter().skip(offset).take(limit).collect();
            let count = page.len();
            let has_more = offset.saturating_add(count) < total;
            Ok(Json(serde_json::json!({
                "entity_type": entity_type.as_str(),
                "entity_id": entity_id,
                "events": page,
                "count": count,
                "total": total,
                "has_more": has_more,
            })))
        }
        Err(e) => Err(internal_error(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_read_range_error_returns_conflict_for_sequence_gap() {
        let err = SequencerError::InvariantViolation {
            invariant: "sequence_range".to_string(),
            message: "sequence gap detected".to_string(),
        };

        let mapped = map_read_range_error(err);
        assert_eq!(mapped.0, StatusCode::CONFLICT);
        assert_eq!(mapped.1, "sequence gap detected");
    }

    #[test]
    fn test_map_read_range_error_defaults_to_internal_error() {
        let err = SequencerError::EventNotFound(uuid::Uuid::nil());
        let mapped = map_read_range_error(err);
        assert_eq!(mapped.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(mapped.1, "Internal server error");
    }
}
