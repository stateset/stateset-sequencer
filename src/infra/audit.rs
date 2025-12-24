//! Audit logging for admin operations
//!
//! Provides comprehensive audit logging for:
//! - API key management (create, revoke)
//! - Schema registry changes
//! - Agent key registration
//! - Configuration changes
//! - Admin queries

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use uuid::Uuid;

/// Audit log action types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // API Key Management
    ApiKeyCreated,
    ApiKeyRevoked,
    ApiKeyUpdated,

    // Schema Registry
    SchemaRegistered,
    SchemaUpdated,
    SchemaDeleted,
    SchemaActivated,
    SchemaDeprecated,

    // Agent Keys
    AgentKeyRegistered,
    AgentKeyRotated,
    AgentKeyRevoked,

    // Configuration
    ConfigUpdated,

    // Data Operations (admin)
    EventsPurged,
    CommitmentDeleted,
    DeadLetterRetried,
    DeadLetterPurged,

    // Authentication
    LoginSuccess,
    LoginFailure,
    TokenRefreshed,

    // Other
    Custom(String),
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::ApiKeyCreated => write!(f, "api_key_created"),
            AuditAction::ApiKeyRevoked => write!(f, "api_key_revoked"),
            AuditAction::ApiKeyUpdated => write!(f, "api_key_updated"),
            AuditAction::SchemaRegistered => write!(f, "schema_registered"),
            AuditAction::SchemaUpdated => write!(f, "schema_updated"),
            AuditAction::SchemaDeleted => write!(f, "schema_deleted"),
            AuditAction::SchemaActivated => write!(f, "schema_activated"),
            AuditAction::SchemaDeprecated => write!(f, "schema_deprecated"),
            AuditAction::AgentKeyRegistered => write!(f, "agent_key_registered"),
            AuditAction::AgentKeyRotated => write!(f, "agent_key_rotated"),
            AuditAction::AgentKeyRevoked => write!(f, "agent_key_revoked"),
            AuditAction::ConfigUpdated => write!(f, "config_updated"),
            AuditAction::EventsPurged => write!(f, "events_purged"),
            AuditAction::CommitmentDeleted => write!(f, "commitment_deleted"),
            AuditAction::DeadLetterRetried => write!(f, "dead_letter_retried"),
            AuditAction::DeadLetterPurged => write!(f, "dead_letter_purged"),
            AuditAction::LoginSuccess => write!(f, "login_success"),
            AuditAction::LoginFailure => write!(f, "login_failure"),
            AuditAction::TokenRefreshed => write!(f, "token_refreshed"),
            AuditAction::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique audit log ID
    pub id: Uuid,
    /// When the action occurred
    pub timestamp: DateTime<Utc>,
    /// The action that was performed
    pub action: AuditAction,
    /// Actor who performed the action (user ID, API key hash prefix, etc.)
    pub actor: String,
    /// Actor type (api_key, jwt, system, etc.)
    pub actor_type: String,
    /// Tenant ID if applicable
    pub tenant_id: Option<Uuid>,
    /// Resource type that was affected
    pub resource_type: Option<String>,
    /// Resource ID that was affected
    pub resource_id: Option<String>,
    /// Request ID for correlation
    pub request_id: Option<String>,
    /// IP address of the actor
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Additional details as JSON
    pub details: Option<serde_json::Value>,
    /// Whether the action succeeded
    pub success: bool,
    /// Error message if failed
    pub error_message: Option<String>,
}

/// Builder for creating audit log entries
pub struct AuditLogBuilder {
    action: AuditAction,
    actor: String,
    actor_type: String,
    tenant_id: Option<Uuid>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    request_id: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    details: Option<serde_json::Value>,
    success: bool,
    error_message: Option<String>,
}

impl AuditLogBuilder {
    /// Create a new audit log builder
    pub fn new(action: AuditAction, actor: impl Into<String>, actor_type: impl Into<String>) -> Self {
        Self {
            action,
            actor: actor.into(),
            actor_type: actor_type.into(),
            tenant_id: None,
            resource_type: None,
            resource_id: None,
            request_id: None,
            ip_address: None,
            user_agent: None,
            details: None,
            success: true,
            error_message: None,
        }
    }

    /// Set the tenant ID
    pub fn tenant_id(mut self, tenant_id: Uuid) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Set the resource type and ID
    pub fn resource(mut self, resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Set the request ID
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Set the IP address
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set the user agent
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Set additional details
    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Mark as failed with error message
    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.success = false;
        self.error_message = Some(error.into());
        self
    }

    /// Build the audit log entry
    pub fn build(self) -> AuditLogEntry {
        AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: self.action,
            actor: self.actor,
            actor_type: self.actor_type,
            tenant_id: self.tenant_id,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            request_id: self.request_id,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            details: self.details,
            success: self.success,
            error_message: self.error_message,
        }
    }
}

/// PostgreSQL-backed audit logger
pub struct PgAuditLogger {
    pool: PgPool,
}

impl PgAuditLogger {
    /// Create a new audit logger
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Initialize the audit log table
    pub async fn initialize(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id UUID PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                tenant_id UUID,
                resource_type TEXT,
                resource_id TEXT,
                request_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                details JSONB,
                success BOOLEAN NOT NULL DEFAULT TRUE,
                error_message TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes for common queries
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp DESC)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_tenant ON audit_log (tenant_id)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log (resource_type, resource_id)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Log an audit entry
    pub async fn log(&self, entry: AuditLogEntry) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO audit_log (
                id, timestamp, action, actor, actor_type,
                tenant_id, resource_type, resource_id,
                request_id, ip_address, user_agent,
                details, success, error_message
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8,
                $9, $10, $11,
                $12, $13, $14
            )
            "#,
        )
        .bind(entry.id)
        .bind(entry.timestamp)
        .bind(entry.action.to_string())
        .bind(&entry.actor)
        .bind(&entry.actor_type)
        .bind(entry.tenant_id)
        .bind(&entry.resource_type)
        .bind(&entry.resource_id)
        .bind(&entry.request_id)
        .bind(&entry.ip_address)
        .bind(&entry.user_agent)
        .bind(&entry.details)
        .bind(entry.success)
        .bind(&entry.error_message)
        .execute(&self.pool)
        .await?;

        // Also emit a tracing event
        if entry.success {
            tracing::info!(
                action = %entry.action,
                actor = %entry.actor,
                actor_type = %entry.actor_type,
                resource_type = ?entry.resource_type,
                resource_id = ?entry.resource_id,
                "Audit log entry"
            );
        } else {
            tracing::warn!(
                action = %entry.action,
                actor = %entry.actor,
                actor_type = %entry.actor_type,
                error = ?entry.error_message,
                "Audit log entry (failed)"
            );
        }

        Ok(())
    }

    /// Query audit logs with filters
    pub async fn query(
        &self,
        filters: AuditQueryFilters,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogEntry>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT id, timestamp, action, actor, actor_type,
                   tenant_id, resource_type, resource_id,
                   request_id, ip_address, user_agent,
                   details, success, error_message
            FROM audit_log
            WHERE 1=1
            "#,
        );

        let mut params_count = 0;

        if filters.tenant_id.is_some() {
            params_count += 1;
            query.push_str(&format!(" AND tenant_id = ${}", params_count));
        }
        if filters.actor.is_some() {
            params_count += 1;
            query.push_str(&format!(" AND actor = ${}", params_count));
        }
        if filters.action.is_some() {
            params_count += 1;
            query.push_str(&format!(" AND action = ${}", params_count));
        }
        if filters.resource_type.is_some() {
            params_count += 1;
            query.push_str(&format!(" AND resource_type = ${}", params_count));
        }
        if filters.success_only.unwrap_or(false) {
            query.push_str(" AND success = TRUE");
        }
        if filters.failures_only.unwrap_or(false) {
            query.push_str(" AND success = FALSE");
        }
        if filters.from.is_some() {
            params_count += 1;
            query.push_str(&format!(" AND timestamp >= ${}", params_count));
        }
        if filters.to.is_some() {
            params_count += 1;
            query.push_str(&format!(" AND timestamp <= ${}", params_count));
        }

        query.push_str(&format!(
            " ORDER BY timestamp DESC LIMIT ${} OFFSET ${}",
            params_count + 1,
            params_count + 2
        ));

        // Build and execute the query with dynamic binding
        // For simplicity, using a fixed query with optional conditions
        let rows = sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT id, timestamp, action, actor, actor_type,
                   tenant_id, resource_type, resource_id,
                   request_id, ip_address, user_agent,
                   details, success, error_message
            FROM audit_log
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
              AND ($2::text IS NULL OR actor = $2)
              AND ($3::text IS NULL OR action = $3)
              AND ($4::text IS NULL OR resource_type = $4)
              AND ($5::timestamptz IS NULL OR timestamp >= $5)
              AND ($6::timestamptz IS NULL OR timestamp <= $6)
              AND ($7::boolean IS NULL OR success = $7)
            ORDER BY timestamp DESC
            LIMIT $8 OFFSET $9
            "#,
        )
        .bind(filters.tenant_id)
        .bind(&filters.actor)
        .bind(filters.action.as_ref().map(|a| a.to_string()))
        .bind(&filters.resource_type)
        .bind(filters.from)
        .bind(filters.to)
        .bind(if filters.success_only == Some(true) {
            Some(true)
        } else if filters.failures_only == Some(true) {
            Some(false)
        } else {
            None
        })
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(AuditLogEntry::from).collect())
    }

    /// Count audit log entries
    pub async fn count(&self, tenant_id: Option<Uuid>) -> Result<i64, sqlx::Error> {
        let count: (i64,) = match tenant_id {
            Some(tid) => {
                sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE tenant_id = $1")
                    .bind(tid)
                    .fetch_one(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as("SELECT COUNT(*) FROM audit_log")
                    .fetch_one(&self.pool)
                    .await?
            }
        };

        Ok(count.0)
    }

    /// Cleanup old audit logs
    pub async fn cleanup(&self, older_than_days: i32) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM audit_log
            WHERE timestamp < NOW() - make_interval(days => $1)
            "#,
        )
        .bind(older_than_days)
        .execute(&self.pool)
        .await?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            tracing::info!(deleted = deleted, "Cleaned up old audit log entries");
        }

        Ok(deleted)
    }
}

/// Query filters for audit logs
#[derive(Debug, Default)]
pub struct AuditQueryFilters {
    pub tenant_id: Option<Uuid>,
    pub actor: Option<String>,
    pub action: Option<AuditAction>,
    pub resource_type: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub success_only: Option<bool>,
    pub failures_only: Option<bool>,
}

/// Database row for audit log
#[derive(Debug, sqlx::FromRow)]
struct AuditLogRow {
    id: Uuid,
    timestamp: DateTime<Utc>,
    action: String,
    actor: String,
    actor_type: String,
    tenant_id: Option<Uuid>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    request_id: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    details: Option<serde_json::Value>,
    success: bool,
    error_message: Option<String>,
}

impl From<AuditLogRow> for AuditLogEntry {
    fn from(row: AuditLogRow) -> Self {
        let action = parse_audit_action(&row.action);

        Self {
            id: row.id,
            timestamp: row.timestamp,
            action,
            actor: row.actor,
            actor_type: row.actor_type,
            tenant_id: row.tenant_id,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            request_id: row.request_id,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            details: row.details,
            success: row.success,
            error_message: row.error_message,
        }
    }
}

fn parse_audit_action(s: &str) -> AuditAction {
    match s {
        "api_key_created" => AuditAction::ApiKeyCreated,
        "api_key_revoked" => AuditAction::ApiKeyRevoked,
        "api_key_updated" => AuditAction::ApiKeyUpdated,
        "schema_registered" => AuditAction::SchemaRegistered,
        "schema_updated" => AuditAction::SchemaUpdated,
        "schema_deleted" => AuditAction::SchemaDeleted,
        "schema_activated" => AuditAction::SchemaActivated,
        "schema_deprecated" => AuditAction::SchemaDeprecated,
        "agent_key_registered" => AuditAction::AgentKeyRegistered,
        "agent_key_rotated" => AuditAction::AgentKeyRotated,
        "agent_key_revoked" => AuditAction::AgentKeyRevoked,
        "config_updated" => AuditAction::ConfigUpdated,
        "events_purged" => AuditAction::EventsPurged,
        "commitment_deleted" => AuditAction::CommitmentDeleted,
        "dead_letter_retried" => AuditAction::DeadLetterRetried,
        "dead_letter_purged" => AuditAction::DeadLetterPurged,
        "login_success" => AuditAction::LoginSuccess,
        "login_failure" => AuditAction::LoginFailure,
        "token_refreshed" => AuditAction::TokenRefreshed,
        s if s.starts_with("custom:") => AuditAction::Custom(s[7..].to_string()),
        _ => AuditAction::Custom(s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_display() {
        assert_eq!(AuditAction::ApiKeyCreated.to_string(), "api_key_created");
        assert_eq!(AuditAction::SchemaRegistered.to_string(), "schema_registered");
        assert_eq!(
            AuditAction::Custom("test".to_string()).to_string(),
            "custom:test"
        );
    }

    #[test]
    fn test_audit_log_builder() {
        let entry = AuditLogBuilder::new(
            AuditAction::ApiKeyCreated,
            "admin@example.com",
            "jwt",
        )
        .tenant_id(Uuid::new_v4())
        .resource("api_key", "key-123")
        .ip_address("192.168.1.1")
        .details(serde_json::json!({"permissions": ["read", "write"]}))
        .build();

        assert_eq!(entry.actor, "admin@example.com");
        assert_eq!(entry.actor_type, "jwt");
        assert!(entry.success);
        assert!(entry.resource_type.is_some());
    }

    #[test]
    fn test_audit_log_builder_failed() {
        let entry = AuditLogBuilder::new(
            AuditAction::LoginFailure,
            "unknown",
            "api_key",
        )
        .failed("Invalid credentials")
        .build();

        assert!(!entry.success);
        assert_eq!(entry.error_message, Some("Invalid credentials".to_string()));
    }

    #[test]
    fn test_parse_audit_action() {
        assert!(matches!(
            parse_audit_action("api_key_created"),
            AuditAction::ApiKeyCreated
        ));
        assert!(matches!(
            parse_audit_action("custom:special"),
            AuditAction::Custom(s) if s == "special"
        ));
        assert!(matches!(
            parse_audit_action("unknown_action"),
            AuditAction::Custom(s) if s == "unknown_action"
        ));
    }
}
