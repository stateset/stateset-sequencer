//! Schema registry API handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_admin, ensure_read, ensure_write};
use crate::api::types::{
    RegisterSchemaRequest, RegisterSchemaResponse, SchemaByEventTypeQuery, SchemaListResponse,
    SchemaQuery, SchemaResponse, SchemaVersionQuery, UpdateSchemaStatusRequest,
    ValidatePayloadRequest, ValidationErrorResponse, ValidationResponse,
};
use crate::auth::AuthContextExt;
use crate::domain::{
    EventType, Schema, SchemaCompatibility, SchemaId, SchemaStatus, TenantId,
};
use crate::infra::SchemaStore;
use crate::server::AppState;

/// Convert a Schema domain object to API response.
fn schema_to_response(schema: &Schema) -> SchemaResponse {
    SchemaResponse {
        id: schema.id.0,
        tenant_id: schema.tenant_id.0,
        event_type: schema.event_type.to_string(),
        version: schema.version,
        schema_json: schema.schema_json.clone(),
        status: match schema.status {
            SchemaStatus::Active => "active".to_string(),
            SchemaStatus::Deprecated => "deprecated".to_string(),
            SchemaStatus::Archived => "archived".to_string(),
        },
        compatibility: match schema.compatibility {
            SchemaCompatibility::Forward => "forward".to_string(),
            SchemaCompatibility::Backward => "backward".to_string(),
            SchemaCompatibility::Full => "full".to_string(),
            SchemaCompatibility::None => "none".to_string(),
        },
        description: schema.description.clone(),
        created_at: schema.created_at.to_rfc3339(),
        updated_at: schema.updated_at.to_rfc3339(),
        created_by: schema.created_by.clone(),
    }
}

/// POST /api/v1/schemas - Register a new schema.
#[instrument(skip(state, auth, request), fields(
    tenant_id = %request.tenant_id,
    event_type = %request.event_type
))]
pub async fn register_schema(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<RegisterSchemaRequest>,
) -> Result<Json<RegisterSchemaResponse>, (StatusCode, String)> {
    info!("Registering schema for event type: {}", request.event_type);
    // Require write access to the tenant
    ensure_write(&auth, request.tenant_id, Uuid::nil())?;

    let tenant_id = TenantId::from_uuid(request.tenant_id);
    let event_type = EventType::from(request.event_type.as_str());

    // Parse compatibility mode
    let compatibility = match request.compatibility.as_deref() {
        Some("forward") => SchemaCompatibility::Forward,
        Some("backward") | None => SchemaCompatibility::Backward,
        Some("full") => SchemaCompatibility::Full,
        Some("none") => SchemaCompatibility::None,
        Some(other) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid compatibility mode: {}", other),
            ))
        }
    };

    // Create the schema
    let schema = Schema::new(tenant_id, event_type, 0, request.schema_json)
        .with_compatibility(compatibility);

    let schema = if let Some(desc) = request.description {
        schema.with_description(desc)
    } else {
        schema
    };

    // Register it
    match state.schema_store.register(schema).await {
        Ok(registered) => Ok(Json(RegisterSchemaResponse {
            id: registered.id.0,
            event_type: registered.event_type.to_string(),
            version: registered.version,
            created_at: registered.created_at.to_rfc3339(),
        })),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

/// GET /api/v1/schemas - List all schemas for a tenant.
#[instrument(skip(state, auth), fields(tenant_id = %query.tenant_id))]
pub async fn list_schemas(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<SchemaQuery>,
) -> Result<Json<SchemaListResponse>, (StatusCode, String)> {
    debug!("Listing schemas for tenant");
    // Verify caller has read access to the requested tenant (store_id not applicable for schemas)
    ensure_read(&auth, query.tenant_id, Uuid::nil())?;

    let tenant_id = TenantId::from_uuid(query.tenant_id);

    match state.schema_store.list_by_tenant(&tenant_id).await {
        Ok(schemas) => {
            let responses: Vec<SchemaResponse> = schemas.iter().map(schema_to_response).collect();
            let count = responses.len();
            Ok(Json(SchemaListResponse {
                schemas: responses,
                count,
            }))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// GET /api/v1/schemas/:schema_id - Get a schema by ID.
#[instrument(skip(state, auth), fields(schema_id = %schema_id))]
pub async fn get_schema(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(schema_id): Path<Uuid>,
) -> Result<Json<SchemaResponse>, (StatusCode, String)> {
    debug!("Getting schema by ID");
    let schema_id = SchemaId::from_uuid(schema_id);

    // Fetch schema first, then verify tenant ownership
    match state.schema_store.get_by_id(schema_id).await {
        Ok(Some(schema)) => {
            // Verify caller has read access to this schema's tenant
            ensure_read(&auth, schema.tenant_id.0, Uuid::nil())?;
            Ok(Json(schema_to_response(&schema)))
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, "Schema not found".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// GET /api/v1/schemas/event-type/:event_type - Get schemas for an event type.
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    event_type = %event_type,
    version = query.version
))]
pub async fn get_schemas_by_event_type(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(event_type): Path<String>,
    Query(query): Query<SchemaVersionQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("Getting schemas by event type");
    // Verify caller has read access to the requested tenant
    ensure_read(&auth, query.tenant_id, Uuid::nil())?;

    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let event_type = EventType::from(event_type.as_str());

    // If version specified, get that specific version
    if let Some(version) = query.version {
        match state
            .schema_store
            .get_version(&tenant_id, &event_type, version)
            .await
        {
            Ok(Some(schema)) => Ok(Json(serde_json::json!({
                "schema": schema_to_response(&schema)
            }))),
            Ok(None) => Err((
                StatusCode::NOT_FOUND,
                format!("Schema version {} not found", version),
            )),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    } else {
        // List all versions
        match state
            .schema_store
            .list_versions(&tenant_id, &event_type)
            .await
        {
            Ok(schemas) => {
                let responses: Vec<SchemaResponse> =
                    schemas.iter().map(schema_to_response).collect();
                let count = responses.len();
                Ok(Json(serde_json::json!({
                    "schemas": responses,
                    "count": count
                })))
            }
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }
}

/// GET /api/v1/schemas/event-type/:event_type/latest - Get latest schema for an event type.
#[instrument(skip(state, auth), fields(
    tenant_id = %query.tenant_id,
    event_type = %event_type
))]
pub async fn get_latest_schema(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(event_type): Path<String>,
    Query(query): Query<SchemaByEventTypeQuery>,
) -> Result<Json<SchemaResponse>, (StatusCode, String)> {
    debug!("Getting latest schema for event type");
    // Verify caller has read access to the requested tenant
    ensure_read(&auth, query.tenant_id, Uuid::nil())?;

    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let event_type = EventType::from(event_type.as_str());

    match state.schema_store.get_latest(&tenant_id, &event_type).await {
        Ok(Some(schema)) => Ok(Json(schema_to_response(&schema))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            format!("No schema found for event type: {}", event_type),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// PUT /api/v1/schemas/:schema_id/status - Update schema status.
#[instrument(skip(state, auth, request), fields(
    schema_id = %schema_id,
    new_status = %request.status
))]
pub async fn update_schema_status(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(schema_id): Path<Uuid>,
    Json(request): Json<UpdateSchemaStatusRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    info!("Updating schema status to: {}", request.status);
    let schema_id = SchemaId::from_uuid(schema_id);

    // Fetch schema first to verify tenant ownership
    let schema = match state.schema_store.get_by_id(schema_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "Schema not found".to_string())),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    // Verify caller has write access to this schema's tenant
    ensure_write(&auth, schema.tenant_id.0, Uuid::nil())?;

    let status = match request.status.as_str() {
        "active" => SchemaStatus::Active,
        "deprecated" => SchemaStatus::Deprecated,
        "archived" => SchemaStatus::Archived,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid status: {}", other),
            ))
        }
    };

    match state.schema_store.update_status(schema_id, status).await {
        Ok(()) => Ok(Json(serde_json::json!({
            "success": true,
            "schema_id": schema_id.0,
            "new_status": request.status
        }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// DELETE /api/v1/schemas/:schema_id - Delete a schema.
#[instrument(skip(state, auth), fields(schema_id = %schema_id))]
pub async fn delete_schema(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(schema_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    warn!("Deleting schema: {}", schema_id);
    let schema_id = SchemaId::from_uuid(schema_id);

    // Fetch schema first to verify tenant ownership
    let schema = match state.schema_store.get_by_id(schema_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "Schema not found".to_string())),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    // Verify caller has admin access to this schema's tenant
    ensure_admin(&auth, schema.tenant_id.0, Uuid::nil())?;

    match state.schema_store.delete(schema_id).await {
        Ok(()) => Ok(Json(serde_json::json!({
            "success": true,
            "deleted_schema_id": schema_id.0
        }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// POST /api/v1/schemas/validate - Validate a payload against a schema.
#[instrument(skip(state, auth, request), fields(
    tenant_id = %request.tenant_id,
    event_type = %request.event_type,
    schema_version = request.schema_version
))]
pub async fn validate_payload(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<ValidatePayloadRequest>,
) -> Result<Json<ValidationResponse>, (StatusCode, String)> {
    debug!("Validating payload against schema");
    // Verify caller has read access to the requested tenant
    ensure_read(&auth, request.tenant_id, Uuid::nil())?;

    let tenant_id = TenantId::from_uuid(request.tenant_id);
    let event_type = EventType::from(request.event_type.as_str());

    // If a specific version is requested, validate against that
    let result = if let Some(version) = request.schema_version {
        state
            .schema_store
            .validate_with_version(&tenant_id, &event_type, version, &request.payload)
            .await
    } else {
        state
            .schema_store
            .validate(&tenant_id, &event_type, &request.payload)
            .await
    };

    match result {
        Ok(validation_result) => Ok(Json(ValidationResponse {
            valid: validation_result.valid,
            schema_id: validation_result.schema_id.map(|id| id.0),
            schema_version: validation_result.schema_version,
            errors: validation_result
                .errors
                .into_iter()
                .map(|e| ValidationErrorResponse {
                    path: e.path,
                    message: e.message,
                })
                .collect(),
        })),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
