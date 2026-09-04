//! Durable projection read endpoints.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use tracing::instrument;

use crate::api::auth_helpers::ensure_read;
use crate::api::types::ProjectionQuery;
use crate::api::utils::internal_error;
use crate::auth::AuthContextExt;
use crate::server::AppState;

const MAX_ENTITY_TYPE_LEN: usize = 128;
const MAX_ENTITY_ID_LEN: usize = 512;

/// GET /api/v1/projections/:entity_type/:entity_id
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    store_id = %query.store_id,
    entity_type = %entity_type,
    entity_id = %entity_id
))]
pub async fn get_projection(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path((entity_type, entity_id)): Path<(String, String)>,
    Query(query): Query<ProjectionQuery>,
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
    ensure_read(&auth, query.tenant_id, query.store_id)?;

    let source = query.source.as_deref().unwrap_or("ves");
    let table = match source {
        "ves" => "ves_projection_documents",
        "legacy" => "projection_documents",
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "source must be `ves` or `legacy`".to_string(),
            ))
        }
    };

    // The table name is selected exclusively from the fixed allowlist above.
    let sql = format!(
        r#"
        SELECT document, version, updated_at
        FROM {table}
        WHERE tenant_id = $1 AND store_id = $2
          AND entity_type = $3 AND entity_id = $4
        "#
    );
    let row: Option<(serde_json::Value, i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(&sql)
        .bind(query.tenant_id)
        .bind(query.store_id)
        .bind(&entity_type)
        .bind(&entity_id)
        .fetch_optional(&state.read_pool)
        .await
        .map_err(internal_error)?;

    let Some((document, version, updated_at)) = row else {
        return Err((StatusCode::NOT_FOUND, "Projection not found".to_string()));
    };
    let version =
        u64::try_from(version).map_err(|_| internal_error("projection version is negative"))?;

    Ok(Json(serde_json::json!({
        "tenant_id": query.tenant_id,
        "store_id": query.store_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "source": source,
        "version": version,
        "updated_at": updated_at,
        "document": document,
    })))
}
