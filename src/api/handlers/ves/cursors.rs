//! Durable acknowledgement cursors for REST and tool-host consumers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::api::auth_helpers::ensure_read;
use crate::api::utils::internal_error;
use crate::auth::AuthContextExt;
use crate::domain::{StoreId, TenantId};
use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct CursorQuery {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcknowledgeCursorRequest {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub sequence_number: u64,
}

/// GET /api/v1/ves/cursors/:agent_id
pub async fn get_agent_cursor(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    authorize_cursor(&auth, agent_id, query.tenant_id, query.store_id)?;
    let cursor = state
        .ves_sequencer
        .agent_cursor_store()
        .get(query.tenant_id, query.store_id, agent_id)
        .await
        .map_err(internal_error)?;
    let acknowledged_sequence = cursor
        .as_ref()
        .map(|cursor| cursor.sequence())
        .transpose()
        .map_err(internal_error)?
        .unwrap_or(0);
    let head_sequence = state
        .ves_sequencer
        .head(
            &TenantId::from_uuid(query.tenant_id),
            &StoreId::from_uuid(query.store_id),
        )
        .await
        .map_err(internal_error)?;

    Ok(Json(serde_json::json!({
        "tenantId": query.tenant_id,
        "storeId": query.store_id,
        "agentId": agent_id,
        "acknowledgedSequence": acknowledged_sequence,
        "headSequence": head_sequence,
        "lag": head_sequence.saturating_sub(acknowledged_sequence),
        "updatedAt": cursor.map(|cursor| cursor.updated_at.to_rfc3339()),
    })))
}

/// PUT /api/v1/ves/cursors/:agent_id
pub async fn acknowledge_agent_cursor(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<AcknowledgeCursorRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    authorize_cursor(&auth, agent_id, request.tenant_id, request.store_id)?;
    let head_sequence = state
        .ves_sequencer
        .head(
            &TenantId::from_uuid(request.tenant_id),
            &StoreId::from_uuid(request.store_id),
        )
        .await
        .map_err(internal_error)?;
    if request.sequence_number > head_sequence {
        return Err((
            StatusCode::BAD_REQUEST,
            "sequenceNumber cannot exceed the stream head".to_string(),
        ));
    }
    let cursor = state
        .ves_sequencer
        .agent_cursor_store()
        .acknowledge(
            request.tenant_id,
            request.store_id,
            agent_id,
            request.sequence_number,
        )
        .await
        .map_err(internal_error)?;
    let acknowledged_sequence = cursor.sequence().map_err(internal_error)?;

    Ok(Json(serde_json::json!({
        "tenantId": request.tenant_id,
        "storeId": request.store_id,
        "agentId": agent_id,
        "acknowledgedSequence": acknowledged_sequence,
        "headSequence": head_sequence,
        "lag": head_sequence.saturating_sub(acknowledged_sequence),
        "updatedAt": cursor.updated_at.to_rfc3339(),
    })))
}

fn authorize_cursor(
    auth: &crate::auth::AuthContext,
    agent_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    ensure_read(auth, tenant_id, store_id)?;
    if !auth.is_admin() && auth.agent_id != Some(agent_id) {
        return Err((StatusCode::FORBIDDEN, "Agent access denied".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthContext, Permissions};

    fn agent_auth(tenant_id: Uuid, store_id: Uuid, agent_id: Uuid) -> AuthContext {
        AuthContext {
            tenant_id,
            store_ids: vec![store_id],
            agent_id: Some(agent_id),
            rate_limit: None,
            permissions: Permissions::read_only(),
        }
    }

    #[test]
    fn agent_can_only_access_its_own_cursor() {
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let auth = agent_auth(tenant_id, store_id, agent_id);

        assert!(authorize_cursor(&auth, agent_id, tenant_id, store_id).is_ok());
        assert_eq!(
            authorize_cursor(&auth, Uuid::new_v4(), tenant_id, store_id)
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn bootstrap_admin_can_access_any_agent_cursor() {
        assert!(authorize_cursor(
            &AuthContext::bootstrap_admin(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .is_ok());
    }
}
