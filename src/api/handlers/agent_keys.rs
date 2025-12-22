//! Agent key management handlers.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::api::auth_helpers::ensure_admin;
use crate::api::types::RegisterAgentKeyRequest;
use crate::auth::{AgentKeyEntry, AgentKeyLookup, AgentKeyRegistry, AuthContextExt};
use crate::server::AppState;

/// POST /api/v1/agents/keys - Register an agent public key.
pub async fn register_agent_key(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<RegisterAgentKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Admin-only operation (manages signing keys).
    ensure_admin(&auth, request.tenant_id, Uuid::nil())?;

    // Parse the hex-encoded public key
    let public_key_hex = request
        .public_key
        .strip_prefix("0x")
        .unwrap_or(&request.public_key);
    let public_key_bytes = hex::decode(public_key_hex).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public key hex: {}", e),
        )
    })?;

    if public_key_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Public key must be 32 bytes".to_string(),
        ));
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_key_bytes);

    // Parse validity timestamps if provided
    let valid_from = if let Some(ref ts) = request.valid_from {
        Some(
            chrono::DateTime::parse_from_rfc3339(ts)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid valid_from timestamp: {}", e),
                    )
                })?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let valid_to = if let Some(ref ts) = request.valid_to {
        Some(
            chrono::DateTime::parse_from_rfc3339(ts)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid valid_to timestamp: {}", e),
                    )
                })?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    // Create lookup and entry
    let lookup = AgentKeyLookup {
        tenant_id: request.tenant_id,
        agent_id: request.agent_id,
        key_id: request.key_id,
    };

    let mut entry = AgentKeyEntry::new(public_key);
    entry.valid_from = valid_from;
    entry.valid_to = valid_to;

    // Register the key
    state
        .agent_key_registry
        .register_key(&lookup, entry)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "tenantId": request.tenant_id,
        "agentId": request.agent_id,
        "keyId": request.key_id,
        "message": "Agent key registered successfully"
    })))
}
