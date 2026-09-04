//! Administrative API for server-enforced agent event capabilities.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use tracing::{instrument, warn};
use uuid::Uuid;

use crate::api::auth_helpers::ensure_admin;
use crate::api::utils::internal_error;
use crate::auth::AuthContextExt;
use crate::infra::{AgentEventPolicy, AuditAction, AuditLogBuilder};
use crate::server::AppState;

const MAX_RULES: usize = 128;
const MAX_EVENT_RULE_LEN: usize = 256;
const MAX_ENTITY_RULE_LEN: usize = 128;
const MAX_POLICY_PAYLOAD_BYTES: u32 = 10 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct AgentPolicyQuery {
    pub tenant_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertAgentPolicyRequest {
    pub tenant_id: Uuid,
    #[serde(default)]
    pub allowed_event_types: Vec<String>,
    #[serde(default)]
    pub allowed_entity_types: Vec<String>,
    #[serde(default = "default_true")]
    pub require_base_version: bool,
    pub max_payload_bytes: Option<u32>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// GET /api/v1/agents/:agent_id/policy
#[instrument(skip(state, auth), fields(tenant_id = %query.tenant_id, agent_id = %agent_id))]
pub async fn get_agent_policy(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<AgentPolicyQuery>,
) -> Result<Json<AgentEventPolicy>, (StatusCode, String)> {
    ensure_admin(&auth, query.tenant_id, Uuid::nil())?;
    state
        .ves_sequencer
        .agent_policy_store()
        .get(query.tenant_id, agent_id)
        .await
        .map_err(internal_error)?
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "Agent policy not found".to_string()))
}

/// PUT /api/v1/agents/:agent_id/policy
#[instrument(skip(state, auth, request), fields(tenant_id = %request.tenant_id, agent_id = %agent_id))]
pub async fn upsert_agent_policy(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(agent_id): Path<Uuid>,
    Json(mut request): Json<UpsertAgentPolicyRequest>,
) -> Result<Json<AgentEventPolicy>, (StatusCode, String)> {
    ensure_admin(&auth, request.tenant_id, Uuid::nil())?;
    validate_rules(
        "allowedEventTypes",
        &request.allowed_event_types,
        MAX_EVENT_RULE_LEN,
    )?;
    validate_rules(
        "allowedEntityTypes",
        &request.allowed_entity_types,
        MAX_ENTITY_RULE_LEN,
    )?;
    if request.max_payload_bytes == Some(0)
        || request
            .max_payload_bytes
            .is_some_and(|value| value > MAX_POLICY_PAYLOAD_BYTES)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("maxPayloadBytes must be between 1 and {MAX_POLICY_PAYLOAD_BYTES}"),
        ));
    }

    normalize_rules(&mut request.allowed_event_types);
    normalize_rules(&mut request.allowed_entity_types);
    let policy = AgentEventPolicy {
        tenant_id: request.tenant_id,
        agent_id,
        allowed_event_types: request.allowed_event_types,
        allowed_entity_types: request.allowed_entity_types,
        require_base_version: request.require_base_version,
        max_payload_bytes: request.max_payload_bytes.map(|value| value as i32),
        enabled: request.enabled,
    };
    let stored = state
        .ves_sequencer
        .agent_policy_store()
        .upsert(&policy)
        .await
        .map_err(internal_error)?;

    if let Some(logger) = &state.audit_logger {
        let actor = auth
            .agent_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "admin".to_string());
        let entry = AuditLogBuilder::new(AuditAction::AgentPolicyUpdated, &actor, "api_key")
            .tenant_id(request.tenant_id)
            .resource("agent_policy", agent_id.to_string())
            .details(serde_json::json!({
                "enabled": stored.enabled,
                "allowedEventTypes": stored.allowed_event_types,
                "allowedEntityTypes": stored.allowed_entity_types,
                "requireBaseVersion": stored.require_base_version,
                "maxPayloadBytes": stored.max_payload_bytes,
            }))
            .build();
        if let Err(error) = logger.log(entry).await {
            warn!(%error, "failed to audit agent policy update");
        }
    }

    Ok(Json(stored))
}

fn validate_rules(
    name: &str,
    rules: &[String],
    max_rule_len: usize,
) -> Result<(), (StatusCode, String)> {
    if rules.len() > MAX_RULES {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{name} may contain at most {MAX_RULES} rules"),
        ));
    }
    if let Some(rule) = rules.iter().find(|rule| {
        rule.is_empty()
            || rule.len() > max_rule_len
            || (rule.contains('*') && rule.as_str() != "*" && !rule.ends_with('*'))
            || rule.matches('*').count() > 1
    }) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid {name} rule: {rule}"),
        ));
    }
    Ok(())
}

fn normalize_rules(rules: &mut Vec<String>) {
    rules.sort_unstable();
    rules.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_exact_and_suffix_wildcard_rules() {
        assert!(validate_rules(
            "rules",
            &["order.created".into(), "inventory.*".into()],
            MAX_EVENT_RULE_LEN,
        )
        .is_ok());
        assert!(validate_rules("rules", &["order.*.created".into()], MAX_EVENT_RULE_LEN,).is_err());
        assert!(validate_rules("rules", &[String::new()], MAX_EVENT_RULE_LEN).is_err());
    }
}
