//! Database-backed, server-enforced capabilities for agent-authored events.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::VesEventEnvelope;
use crate::infra::Result;

/// Effective write policy for one agent within one tenant.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AgentEventPolicy {
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub allowed_event_types: Vec<String>,
    pub allowed_entity_types: Vec<String>,
    pub require_base_version: bool,
    pub max_payload_bytes: Option<i32>,
    pub enabled: bool,
}

impl AgentEventPolicy {
    /// Validate an event at the authoritative server boundary.
    pub fn validate(&self, event: &VesEventEnvelope) -> std::result::Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if !matches_any(&self.allowed_event_types, event.event_type.as_str()) {
            return Err(format!(
                "event type is not allowed for this agent: {}",
                event.event_type.as_str()
            ));
        }
        if !matches_any(&self.allowed_entity_types, event.entity_type.as_str()) {
            return Err(format!(
                "entity type is not allowed for this agent: {}",
                event.entity_type.as_str()
            ));
        }
        if self.require_base_version
            && !event.event_type.as_str().ends_with(".created")
            && event.base_version.is_none()
        {
            return Err("base_version is required when modifying an existing entity".to_string());
        }
        if let Some(max_payload_bytes) = self.max_payload_bytes {
            let payload_bytes = match (&event.payload, &event.payload_encrypted) {
                (Some(payload), _) => serde_json::to_vec(payload)
                    .map(|bytes| bytes.len())
                    .unwrap_or(usize::MAX),
                (_, Some(payload)) => serde_json::to_vec(payload)
                    .map(|bytes| bytes.len())
                    .unwrap_or(usize::MAX),
                _ => 0,
            };
            if payload_bytes > max_payload_bytes as usize {
                return Err(format!(
                    "payload exceeds this agent's {} byte policy limit",
                    max_payload_bytes
                ));
            }
        }
        Ok(())
    }
}

fn matches_any(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|pattern| {
        pattern == "*"
            || pattern == value
            || pattern
                .strip_suffix('*')
                .is_some_and(|prefix| value.starts_with(prefix))
    })
}

#[derive(Clone)]
pub struct PgAgentEventPolicyStore {
    pool: PgPool,
}

impl PgAgentEventPolicyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get(&self, tenant_id: Uuid, agent_id: Uuid) -> Result<Option<AgentEventPolicy>> {
        Ok(sqlx::query_as(
            r#"
            SELECT tenant_id, agent_id, allowed_event_types, allowed_entity_types,
                   require_base_version, max_payload_bytes, enabled
            FROM agent_event_policies
            WHERE tenant_id = $1 AND agent_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn get_for_agents(
        &self,
        tenant_id: Uuid,
        agent_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, AgentEventPolicy>> {
        if agent_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let policies: Vec<AgentEventPolicy> = sqlx::query_as(
            r#"
            SELECT tenant_id, agent_id, allowed_event_types, allowed_entity_types,
                   require_base_version, max_payload_bytes, enabled
            FROM agent_event_policies
            WHERE tenant_id = $1 AND agent_id = ANY($2) AND enabled = TRUE
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(agent_ids)
        .bind(agent_ids.len() as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(policies
            .into_iter()
            .map(|policy| (policy.agent_id, policy))
            .collect())
    }

    pub async fn upsert(&self, policy: &AgentEventPolicy) -> Result<AgentEventPolicy> {
        Ok(sqlx::query_as(
            r#"
            INSERT INTO agent_event_policies (
                tenant_id, agent_id, allowed_event_types, allowed_entity_types,
                require_base_version, max_payload_bytes, enabled
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
                allowed_event_types = EXCLUDED.allowed_event_types,
                allowed_entity_types = EXCLUDED.allowed_entity_types,
                require_base_version = EXCLUDED.require_base_version,
                max_payload_bytes = EXCLUDED.max_payload_bytes,
                enabled = EXCLUDED.enabled,
                updated_at = NOW()
            RETURNING tenant_id, agent_id, allowed_event_types, allowed_entity_types,
                      require_base_version, max_payload_bytes, enabled
            "#,
        )
        .bind(policy.tenant_id)
        .bind(policy.agent_id)
        .bind(&policy.allowed_event_types)
        .bind(&policy.allowed_entity_types)
        .bind(policy.require_base_version)
        .bind(policy.max_payload_bytes)
        .bind(policy.enabled)
        .fetch_one(&self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_rules_are_prefix_scoped() {
        assert!(matches_any(&["order.*".to_string()], "order.confirmed"));
        assert!(!matches_any(&["order.*".to_string()], "orders.confirmed"));
        assert!(matches_any(&["*".to_string()], "anything"));
        assert!(!matches_any(&[], "order.created"));
    }
}
