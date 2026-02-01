//! Agent registration and management handlers.
//!
//! Provides endpoints for AI agents to:
//! - Register with the sequencer and receive an API key
//! - List their signing keys
//! - Get agent status and metadata

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::api::types::{
    AgentRegistrationRequest, AgentRegistrationResponse, AgentResponse, ApiKeyResponse,
    CreateApiKeyRequest, ListApiKeysResponse,
};
use crate::auth::{ApiKeyRecord, ApiKeyStore, ApiKeyValidator, AuthContextExt, Permissions};
use crate::server::AppState;

/// POST /api/v1/agents/register - Register a new agent and receive an API key.
///
/// This endpoint allows AI agents to self-register with the sequencer.
/// Upon successful registration, the agent receives an API key for authentication.
#[instrument(skip(state, request), fields(agent_name = %request.name))]
pub async fn register_agent(
    State(state): State<AppState>,
    Json(request): Json<AgentRegistrationRequest>,
) -> Result<Json<AgentRegistrationResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!("Registering new agent: {}", request.name);

    if request.tenant_id.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "tenant_id is not allowed for self-service registration",
                "code": "TENANT_ID_NOT_ALLOWED"
            })),
        ));
    }

    if request.admin.unwrap_or(false) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "success": false,
                "error": "admin registration is not permitted",
                "code": "ADMIN_NOT_ALLOWED"
            })),
        ));
    }

    // Generate a new agent ID
    let agent_id = Uuid::new_v4();

    // Always create a new tenant for self-service registration
    let tenant_id = Uuid::new_v4();

    // Generate API key for this agent
    let (plaintext_key, key_hash) = ApiKeyValidator::generate_key(&tenant_id);

    // Determine permissions based on request
    let permissions = if request.read_only.unwrap_or(false) {
        Permissions::read_only()
    } else {
        Permissions::read_write()
    };

    // Create API key record
    let api_key_record = ApiKeyRecord {
        key_hash: key_hash.clone(),
        tenant_id,
        store_ids: request.store_ids.clone().unwrap_or_default(),
        permissions,
        agent_id: Some(agent_id),
        active: true,
        rate_limit: request.rate_limit,
    };

    // Store in database
    if let Err(e) = state.api_key_store.store(&api_key_record).await {
        warn!("Failed to store API key: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": "Failed to create API key",
                "code": "INTERNAL_ERROR"
            })),
        ));
    }

    // Also register in the in-memory validator for immediate use
    state.api_key_validator.register_key(api_key_record);

    info!(
        "Agent registered successfully: agent_id={}, tenant_id={}",
        agent_id, tenant_id
    );

    Ok(Json(AgentRegistrationResponse {
        success: true,
        agent_id,
        tenant_id,
        api_key: plaintext_key,
        permissions: if request.read_only.unwrap_or(false) {
            "read".to_string()
        } else {
            "read_write".to_string()
        },
        message: "Agent registered successfully. Store your API key securely - it cannot be retrieved later.".to_string(),
    }))
}

/// GET /api/v1/agents/:agent_id - Get agent details.
#[instrument(skip(state, auth), fields(agent_id = %agent_id))]
pub async fn get_agent(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<AgentResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Agents can only view their own details, or admins can view any
    if auth.agent_id != Some(agent_id) && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "success": false,
                "error": "Access denied",
                "code": "FORBIDDEN"
            })),
        ));
    }

    // Get API keys for this agent to determine status
    let keys = state
        .api_key_store
        .list_for_tenant(&auth.tenant_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to fetch agent: {:?}", e),
                    "code": "INTERNAL_ERROR"
                })),
            )
        })?;

    let agent_key = keys
        .iter()
        .find(|k| k.agent_id == Some(agent_id))
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Agent not found",
                    "code": "NOT_FOUND"
                })),
            )
        })?;

    Ok(Json(AgentResponse {
        agent_id,
        tenant_id: agent_key.tenant_id,
        active: agent_key.active,
        permissions: if agent_key.permissions.admin {
            "admin".to_string()
        } else if agent_key.permissions.write {
            "read_write".to_string()
        } else {
            "read".to_string()
        },
        store_ids: agent_key.store_ids.clone(),
        rate_limit: agent_key.rate_limit,
    }))
}

/// POST /api/v1/agents/:agent_id/keys - Create a new API key for an existing agent.
#[instrument(skip(state, auth, request), fields(agent_id = %agent_id))]
pub async fn create_agent_api_key(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(agent_id): Path<Uuid>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Only the agent itself or an admin can create keys
    if auth.agent_id != Some(agent_id) && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "success": false,
                "error": "Access denied",
                "code": "FORBIDDEN"
            })),
        ));
    }

    // Generate new API key
    let (plaintext_key, key_hash) = ApiKeyValidator::generate_key(&auth.tenant_id);

    let permissions = if request.admin.unwrap_or(false) && auth.is_admin() {
        Permissions::admin()
    } else if request.read_only.unwrap_or(false) {
        Permissions::read_only()
    } else {
        Permissions::read_write()
    };

    let api_key_record = ApiKeyRecord {
        key_hash: key_hash.clone(),
        tenant_id: auth.tenant_id,
        store_ids: request.store_ids.clone().unwrap_or_default(),
        permissions,
        agent_id: Some(agent_id),
        active: true,
        rate_limit: request.rate_limit,
    };

    if let Err(e) = state.api_key_store.store(&api_key_record).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create API key: {:?}", e),
                "code": "INTERNAL_ERROR"
            })),
        ));
    }

    state.api_key_validator.register_key(api_key_record);

    Ok(Json(ApiKeyResponse {
        success: true,
        api_key: plaintext_key,
        key_hash_prefix: key_hash[..16].to_string(),
        permissions: if request.admin.unwrap_or(false) && auth.is_admin() {
            "admin".to_string()
        } else if request.read_only.unwrap_or(false) {
            "read".to_string()
        } else {
            "read_write".to_string()
        },
        message: "API key created. Store it securely - it cannot be retrieved later.".to_string(),
    }))
}

/// GET /api/v1/agents/:agent_id/api-keys - List API keys for an agent.
#[instrument(skip(state, auth), fields(agent_id = %agent_id))]
pub async fn list_agent_api_keys(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<ListApiKeysResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Only the agent itself or an admin can list keys
    if auth.agent_id != Some(agent_id) && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "success": false,
                "error": "Access denied",
                "code": "FORBIDDEN"
            })),
        ));
    }

    let all_keys = state
        .api_key_store
        .list_for_tenant(&auth.tenant_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to list keys: {:?}", e),
                    "code": "INTERNAL_ERROR"
                })),
            )
        })?;

    let agent_keys: Vec<_> = all_keys
        .into_iter()
        .filter(|k| k.agent_id == Some(agent_id))
        .map(|k| crate::api::types::ApiKeyInfo {
            key_hash_prefix: k.key_hash[..16].to_string(),
            active: k.active,
            permissions: if k.permissions.admin {
                "admin".to_string()
            } else if k.permissions.write {
                "read_write".to_string()
            } else {
                "read".to_string()
            },
            rate_limit: k.rate_limit,
        })
        .collect();

    let count = agent_keys.len();
    Ok(Json(ListApiKeysResponse {
        keys: agent_keys,
        count,
    }))
}

/// DELETE /api/v1/agents/:agent_id/api-keys/:key_prefix - Revoke an API key.
#[instrument(skip(state, auth), fields(agent_id = %agent_id, key_prefix = %key_prefix))]
pub async fn revoke_agent_api_key(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path((agent_id, key_prefix)): Path<(Uuid, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Only the agent itself or an admin can revoke keys
    if auth.agent_id != Some(agent_id) && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "success": false,
                "error": "Access denied",
                "code": "FORBIDDEN"
            })),
        ));
    }

    // Find the key by prefix
    let all_keys = state
        .api_key_store
        .list_for_tenant(&auth.tenant_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to list keys: {:?}", e),
                    "code": "INTERNAL_ERROR"
                })),
            )
        })?;

    let key_to_revoke = all_keys
        .iter()
        .find(|k| k.agent_id == Some(agent_id) && k.key_hash.starts_with(&key_prefix))
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "success": false,
                    "error": "API key not found",
                    "code": "NOT_FOUND"
                })),
            )
        })?;

    // Revoke in database
    state
        .api_key_store
        .revoke(&key_to_revoke.key_hash)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to revoke key: {:?}", e),
                    "code": "INTERNAL_ERROR"
                })),
            )
        })?;

    // Also revoke in memory
    state.api_key_validator.revoke(&key_to_revoke.key_hash);

    info!("API key revoked for agent {}", agent_id);

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "API key revoked successfully"
    })))
}
