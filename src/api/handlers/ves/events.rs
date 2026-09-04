//! Read endpoints for the VES event stream.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use tracing::instrument;

use crate::api::auth_helpers::ensure_read;
use crate::api::types::{EntityHistoryQuery, HeadQuery, ListEventsQuery};
use crate::api::utils::internal_error;
use crate::auth::AuthContextExt;
use crate::domain::{EntityType, StoreId, TenantId, MAX_ENTITY_HISTORY_PAGE};
use crate::infra::SequencerError;
use crate::server::AppState;

// Keep the API boundary aligned with the VES database schema so an accepted
// identifier can always be persisted and queried.
const MAX_ENTITY_TYPE_LEN: usize = 64;
const MAX_ENTITY_ID_LEN: usize = 256;

fn map_read_error(error: SequencerError) -> (StatusCode, String) {
    match error {
        SequencerError::InvariantViolation { invariant, message }
            if invariant == "sequence_range" =>
        {
            (StatusCode::CONFLICT, message)
        }
        other => internal_error(other),
    }
}

/// GET /api/v1/ves/events - Read a bounded page from the canonical VES stream.
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    store_id = %query.store_id,
    from = query.from,
    limit = query.limit
))]
pub async fn list_ves_events(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<ListEventsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);
    ensure_read(&auth, tenant_id.0, store_id.0)?;

    let from = query.from.unwrap_or(1).max(1);
    let requested_limit = query.limit.unwrap_or(100);
    if requested_limit == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "limit must be greater than 0".to_string(),
        ));
    }
    let limit = u64::from(requested_limit.min(1000));
    let end = from.saturating_add(limit.saturating_sub(1));

    // Agent decisions and base-version checks require read-your-write
    // consistency, so canonical VES reads use the writer-backed sequencer.
    let events = state
        .ves_sequencer
        .read_range(&tenant_id, &store_id, from, end)
        .await
        .map_err(map_read_error)?;
    let head_sequence = state
        .ves_sequencer
        .head(&tenant_id, &store_id)
        .await
        .map_err(internal_error)?;
    let next_sequence = events
        .last()
        .map(|event| event.sequence_number().saturating_add(1))
        .unwrap_or(from);
    let count = events.len();

    Ok(Json(serde_json::json!({
        "events": events,
        "count": count,
        "next_sequence": next_sequence,
        "head_sequence": head_sequence,
        "has_more": next_sequence <= head_sequence,
    })))
}

/// GET /api/v1/ves/head - Get the canonical VES stream head.
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    store_id = %query.store_id
))]
pub async fn get_ves_head(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);
    ensure_read(&auth, tenant_id.0, store_id.0)?;

    let head = state
        .ves_sequencer
        .head(&tenant_id, &store_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({ "head_sequence": head })))
}

/// GET /api/v1/ves/entities/:entity_type/:entity_id - Read VES entity history.
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    store_id = %query.store_id,
    entity_type = %entity_type,
    entity_id = %entity_id
))]
pub async fn get_ves_entity_history(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path((entity_type, entity_id)): Path<(String, String)>,
    Query(query): Query<EntityHistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if entity_type.is_empty() || entity_type.len() > MAX_ENTITY_TYPE_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("entity_type must be between 1 and {MAX_ENTITY_TYPE_LEN} characters"),
        ));
    }
    if entity_id.is_empty() || entity_id.len() > MAX_ENTITY_ID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("entity_id must be between 1 and {MAX_ENTITY_ID_LEN} characters"),
        ));
    }

    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);
    let entity_type = EntityType::from(entity_type.as_str());
    ensure_read(&auth, tenant_id.0, store_id.0)?;

    let offset = query.from.unwrap_or(0);
    let requested_limit = query.limit.unwrap_or(MAX_ENTITY_HISTORY_PAGE);
    let limit = if requested_limit == 0 {
        MAX_ENTITY_HISTORY_PAGE
    } else {
        requested_limit.min(MAX_ENTITY_HISTORY_PAGE)
    };
    let page = state
        .ves_sequencer
        .read_entity_page(
            &tenant_id,
            &store_id,
            &entity_type,
            &entity_id,
            offset,
            limit,
        )
        .await
        .map_err(internal_error)?;
    let count = page.events.len();
    let has_more = offset.saturating_add(count as u64) < page.total;

    Ok(Json(serde_json::json!({
        "entity_type": entity_type.as_str(),
        "entity_id": entity_id,
        "events": page.events,
        "count": count,
        "total": page.total,
        "current_version": page.total,
        "has_more": has_more,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_gap_maps_to_conflict() {
        let error = SequencerError::InvariantViolation {
            invariant: "sequence_range".to_string(),
            message: "gap".to_string(),
        };
        assert_eq!(
            map_read_error(error),
            (StatusCode::CONFLICT, "gap".to_string())
        );
    }
}
