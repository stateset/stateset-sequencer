//! Agent registration and management handlers.
//!
//! Provides endpoints for AI agents to:
//! - Register with the sequencer and receive an API key
//! - List their signing keys
//! - Get agent status and metadata

use axum::extract::{ConnectInfo, Extension, Path, State};
use axum::http::header::{CACHE_CONTROL, RETRY_AFTER, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::Json;
use std::net::SocketAddr;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use crate::api::types::{
    AgentRegistrationRequest, AgentRegistrationResponse, AgentResponse, ApiKeyResponse,
    CreateApiKeyRequest, ListApiKeysResponse,
};
use crate::auth::{ApiKeyRecord, ApiKeyStore, ApiKeyValidator, AuthContextExt, Permissions};
use crate::infra::{extract_client_ip, AuditAction, AuditLogBuilder};
use crate::server::AppState;

const MAX_AGENT_NAME_LEN: usize = 128;
const MAX_DESCRIPTION_LEN: usize = 1024;
const MAX_STORE_IDS: usize = 50;
const MAX_RATE_LIMIT_RPM: u32 = 10_000;

/// POST /api/v1/agents/register - Register a new agent and receive an API key.
///
/// This endpoint allows AI agents to self-register with the sequencer.
/// Upon successful registration, the agent receives an API key for authentication.
#[allow(clippy::type_complexity)]
#[instrument(skip(state, request), fields(agent_name = %request.name))]
pub async fn register_agent(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AgentRegistrationRequest>,
) -> Result<
    (HeaderMap, Json<AgentRegistrationResponse>),
    (StatusCode, HeaderMap, Json<serde_json::Value>),
> {
    info!("Registering new agent: {}", request.name);

    let client_ip = extract_client_ip(&headers, remote_addr, state.trust_proxy_headers)
        .map(|ip| ip.to_string());
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if !state.public_registration_enabled {
        record_registration_metric(&state, "error", "REGISTRATION_DISABLED").await;
        log_registration_audit(
            &state,
            &request,
            None,
            None,
            client_ip.as_deref(),
            user_agent.as_deref(),
            request_id.as_deref(),
            Some("public registration disabled".to_string()),
        )
        .await;
        return Err((
            StatusCode::FORBIDDEN,
            HeaderMap::new(),
            Json(serde_json::json!({
                "success": false,
                "error": "public registration is disabled",
                "code": "REGISTRATION_DISABLED"
            })),
        ));
    }

    let mut rate_limit_headers = HeaderMap::new();
    if let Some(ref limiter) = state.public_registration_limiter {
        let key = client_ip.clone().unwrap_or_else(|| "unknown".to_string());
        let limiter_key = format!("public_register:{}", key);
        if limiter.check(&limiter_key).is_err() {
            record_registration_metric(&state, "error", "RATE_LIMIT_EXCEEDED").await;
            log_registration_audit(
                &state,
                &request,
                None,
                None,
                client_ip.as_deref(),
                user_agent.as_deref(),
                request_id.as_deref(),
                Some("rate limit exceeded".to_string()),
            )
            .await;
            let (mut headers, reset_after) = rate_limit_headers_snapshot(limiter, &limiter_key);
            headers.insert(
                RETRY_AFTER,
                HeaderValue::from_str(&reset_after.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("60")),
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                headers,
                Json(serde_json::json!({
                    "success": false,
                    "error": "rate limit exceeded",
                    "code": "RATE_LIMIT_EXCEEDED"
                })),
            ));
        }

        let (headers, _) = rate_limit_headers_snapshot(limiter, &limiter_key);
        rate_limit_headers = headers;
    }

    let trimmed_name = request.name.trim();
    if trimmed_name.is_empty() {
        record_registration_metric(&state, "error", "INVALID_NAME").await;
        log_registration_audit(
            &state,
            &request,
            None,
            None,
            client_ip.as_deref(),
            user_agent.as_deref(),
            request_id.as_deref(),
            Some("name is required".to_string()),
        )
        .await;
        return Err((
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Json(serde_json::json!({
                "success": false,
                "error": "name is required",
                "code": "INVALID_NAME"
            })),
        ));
    }

    if trimmed_name.len() > MAX_AGENT_NAME_LEN {
        record_registration_metric(&state, "error", "NAME_TOO_LONG").await;
        log_registration_audit(
            &state,
            &request,
            None,
            None,
            client_ip.as_deref(),
            user_agent.as_deref(),
            request_id.as_deref(),
            Some("name exceeds maximum length".to_string()),
        )
        .await;
        return Err((
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Json(serde_json::json!({
                "success": false,
                "error": "name exceeds maximum length",
                "code": "NAME_TOO_LONG"
            })),
        ));
    }

    if let Some(description) = request.description.as_deref() {
        if description.len() > MAX_DESCRIPTION_LEN {
            record_registration_metric(&state, "error", "DESCRIPTION_TOO_LONG").await;
            log_registration_audit(
                &state,
                &request,
                None,
                None,
                client_ip.as_deref(),
                user_agent.as_deref(),
                request_id.as_deref(),
                Some("description exceeds maximum length".to_string()),
            )
            .await;
            return Err((
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(serde_json::json!({
                    "success": false,
                    "error": "description exceeds maximum length",
                    "code": "DESCRIPTION_TOO_LONG"
                })),
            ));
        }
    }

    if let Some(store_ids) = request.store_ids.as_deref() {
        if store_ids.len() > MAX_STORE_IDS {
            record_registration_metric(&state, "error", "STORE_IDS_TOO_MANY").await;
            log_registration_audit(
                &state,
                &request,
                None,
                None,
                client_ip.as_deref(),
                user_agent.as_deref(),
                request_id.as_deref(),
                Some("too many store IDs".to_string()),
            )
            .await;
            return Err((
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(serde_json::json!({
                    "success": false,
                    "error": "too many store IDs",
                    "code": "STORE_IDS_TOO_MANY"
                })),
            ));
        }
    }

    if let Some(rate_limit) = request.rate_limit {
        if rate_limit == 0 || rate_limit > MAX_RATE_LIMIT_RPM {
            record_registration_metric(&state, "error", "RATE_LIMIT_INVALID").await;
            log_registration_audit(
                &state,
                &request,
                None,
                None,
                client_ip.as_deref(),
                user_agent.as_deref(),
                request_id.as_deref(),
                Some("rate limit out of range".to_string()),
            )
            .await;
            return Err((
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(serde_json::json!({
                    "success": false,
                    "error": "rate limit out of range",
                    "code": "RATE_LIMIT_INVALID"
                })),
            ));
        }
    }

    if request.tenant_id.is_some() {
        record_registration_metric(&state, "error", "TENANT_ID_NOT_ALLOWED").await;
        log_registration_audit(
            &state,
            &request,
            None,
            None,
            client_ip.as_deref(),
            user_agent.as_deref(),
            request_id.as_deref(),
            Some("tenant_id not allowed".to_string()),
        )
        .await;
        return Err((
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            Json(serde_json::json!({
                "success": false,
                "error": "tenant_id is not allowed for self-service registration",
                "code": "TENANT_ID_NOT_ALLOWED"
            })),
        ));
    }

    if request.admin.unwrap_or(false) {
        record_registration_metric(&state, "error", "ADMIN_NOT_ALLOWED").await;
        log_registration_audit(
            &state,
            &request,
            None,
            None,
            client_ip.as_deref(),
            user_agent.as_deref(),
            request_id.as_deref(),
            Some("admin registration not allowed".to_string()),
        )
        .await;
        return Err((
            StatusCode::FORBIDDEN,
            HeaderMap::new(),
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
        record_registration_metric(&state, "error", "INTERNAL_ERROR").await;
        log_registration_audit(
            &state,
            &request,
            Some(tenant_id),
            Some(agent_id),
            client_ip.as_deref(),
            user_agent.as_deref(),
            request_id.as_deref(),
            Some("failed to store api key".to_string()),
        )
        .await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            HeaderMap::new(),
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

    log_registration_audit(
        &state,
        &request,
        Some(tenant_id),
        Some(agent_id),
        client_ip.as_deref(),
        user_agent.as_deref(),
        request_id.as_deref(),
        None,
    )
    .await;

    record_registration_metric(&state, "success", "REGISTERED").await;

    let mut response_headers = rate_limit_headers;
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    Ok((response_headers, Json(AgentRegistrationResponse {
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
    })))
}

#[allow(clippy::too_many_arguments)]
async fn log_registration_audit(
    state: &AppState,
    request: &AgentRegistrationRequest,
    tenant_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    request_id: Option<&str>,
    error_message: Option<String>,
) {
    let Some(logger) = &state.audit_logger else {
        return;
    };

    let mut builder = AuditLogBuilder::new(
        AuditAction::Custom("agent_registered".to_string()),
        "self_service",
        "public",
    );

    if let Some(tenant_id) = tenant_id {
        builder = builder.tenant_id(tenant_id);
    }
    if let Some(agent_id) = agent_id {
        builder = builder.resource("agent", agent_id.to_string());
    }
    if let Some(ip) = ip_address {
        builder = builder.ip_address(ip.to_string());
    }
    if let Some(ua) = user_agent {
        builder = builder.user_agent(ua.to_string());
    }
    if let Some(req_id) = request_id {
        builder = builder.request_id(req_id.to_string());
    }
    let store_ids: Vec<String> = request
        .store_ids
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|id| id.to_string())
        .collect();
    builder = builder.details(serde_json::json!({
        "name": request.name,
        "description": request.description,
        "requested_tenant_id": request.tenant_id.map(|id| id.to_string()),
        "store_ids": store_ids,
        "read_only": request.read_only.unwrap_or(false),
        "admin": request.admin.unwrap_or(false),
        "rate_limit": request.rate_limit,
    }));
    if let Some(error) = error_message {
        builder = builder.failed(error);
    }
    if logger.log(builder.build()).await.is_ok() {
        state
            .metrics
            .inc_counter(crate::metrics::metric_names::AUDIT_EVENTS_LOGGED)
            .await;
    }
}

async fn record_registration_metric(state: &AppState, outcome: &str, reason: &str) {
    state
        .metrics
        .inc_counter_labeled(
            crate::metrics::metric_names::AGENT_REGISTRATION_TOTAL,
            crate::metrics::Labels::new()
                .with("outcome", outcome)
                .with("reason", reason),
        )
        .await;
}

fn rate_limit_headers_snapshot(limiter: &crate::auth::RateLimiter, key: &str) -> (HeaderMap, u64) {
    let metrics = limiter.metrics();
    let remaining = limiter.remaining(key);
    let reset_after = limiter.reset_after(key);

    let mut headers = HeaderMap::new();
    headers.insert(
        "ratelimit-limit",
        HeaderValue::from_str(&metrics.requests_per_minute.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(
        "ratelimit-remaining",
        HeaderValue::from_str(&remaining.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(
        "ratelimit-reset",
        HeaderValue::from_str(&reset_after.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    (headers, reset_after)
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
    let agent_keys = if auth.is_admin() && auth.tenant_id.is_nil() {
        state
            .api_key_store
            .list_for_agent(&agent_id)
            .await
            .map_err(|e| {
                error!(error = ?e, "Internal error in agent handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "error": "Internal error",
                        "code": "INTERNAL_ERROR"
                    })),
                )
            })?
    } else {
        let keys = state
            .api_key_store
            .list_for_tenant(&auth.tenant_id)
            .await
            .map_err(|e| {
                error!(error = ?e, "Internal error in agent handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "error": "Internal error",
                        "code": "INTERNAL_ERROR"
                    })),
                )
            })?;
        keys.into_iter()
            .filter(|k| k.agent_id == Some(agent_id))
            .collect()
    };

    let agent_key = agent_keys.first().ok_or_else(|| {
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

    let tenant_id = if auth.is_admin() && auth.tenant_id.is_nil() {
        let keys = state
            .api_key_store
            .list_for_agent(&agent_id)
            .await
            .map_err(|e| {
                error!(error = ?e, "Internal error in agent handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "error": "Internal error",
                        "code": "INTERNAL_ERROR"
                    })),
                )
            })?;
        let agent_key = keys.first().ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Agent not found",
                    "code": "NOT_FOUND"
                })),
            )
        })?;
        agent_key.tenant_id
    } else {
        if auth.is_admin() && auth.agent_id != Some(agent_id) {
            let keys = state
                .api_key_store
                .list_for_tenant(&auth.tenant_id)
                .await
                .map_err(|e| {
                    error!(error = ?e, "Internal error in agent handler");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "success": false,
                            "error": "Internal error",
                            "code": "INTERNAL_ERROR"
                        })),
                    )
                })?;
            if !keys.iter().any(|k| k.agent_id == Some(agent_id)) {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "success": false,
                        "error": "Agent not found",
                        "code": "NOT_FOUND"
                    })),
                ));
            }
        }
        auth.tenant_id
    };

    // Generate new API key
    let (plaintext_key, key_hash) = ApiKeyValidator::generate_key(&tenant_id);

    let permissions = if request.admin.unwrap_or(false) && auth.is_admin() {
        Permissions::admin()
    } else if request.read_only.unwrap_or(false) {
        Permissions::read_only()
    } else {
        Permissions::read_write()
    };

    let api_key_record = ApiKeyRecord {
        key_hash: key_hash.clone(),
        tenant_id,
        store_ids: request.store_ids.clone().unwrap_or_default(),
        permissions,
        agent_id: Some(agent_id),
        active: true,
        rate_limit: request.rate_limit,
    };

    if let Err(e) = state.api_key_store.store(&api_key_record).await {
        error!(error = ?e, "Failed to store API key");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": "Internal error",
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

    let agent_keys = if auth.is_admin() && auth.tenant_id.is_nil() {
        state
            .api_key_store
            .list_for_agent(&agent_id)
            .await
            .map_err(|e| {
                error!(error = ?e, "Internal error in agent handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "error": "Internal error",
                        "code": "INTERNAL_ERROR"
                    })),
                )
            })?
    } else {
        let all_keys = state
            .api_key_store
            .list_for_tenant(&auth.tenant_id)
            .await
            .map_err(|e| {
                error!(error = ?e, "Internal error in agent handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "error": "Internal error",
                        "code": "INTERNAL_ERROR"
                    })),
                )
            })?;
        all_keys
            .into_iter()
            .filter(|k| k.agent_id == Some(agent_id))
            .collect()
    };

    let agent_keys: Vec<_> = agent_keys
        .into_iter()
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
    let all_keys = if auth.is_admin() && auth.tenant_id.is_nil() {
        state
            .api_key_store
            .list_for_agent(&agent_id)
            .await
            .map_err(|e| {
                error!(error = ?e, "Internal error in agent handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "error": "Internal error",
                        "code": "INTERNAL_ERROR"
                    })),
                )
            })?
    } else {
        state
            .api_key_store
            .list_for_tenant(&auth.tenant_id)
            .await
            .map_err(|e| {
                error!(error = ?e, "Internal error in agent handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "error": "Internal error",
                        "code": "INTERNAL_ERROR"
                    })),
                )
            })?
    };

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
            error!(error = ?e, "Internal error in agent handler");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Internal error",
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
