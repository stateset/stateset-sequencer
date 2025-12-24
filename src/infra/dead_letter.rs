//! Dead letter queue for failed event projections
//!
//! When event projection fails (due to invariant violations, schema issues, etc.),
//! events are moved to a dead letter queue for later investigation and retry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::{StoreId, TenantId};
use crate::infra::Result;

/// Reason for event being dead-lettered
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadLetterReason {
    /// Schema validation failed
    SchemaValidation,
    /// Invariant violation
    InvariantViolation,
    /// Invalid state transition
    InvalidStateTransition,
    /// Version conflict
    VersionConflict,
    /// Handler error
    HandlerError,
    /// Unknown/other error
    Unknown,
}

impl std::fmt::Display for DeadLetterReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeadLetterReason::SchemaValidation => write!(f, "schema_validation"),
            DeadLetterReason::InvariantViolation => write!(f, "invariant_violation"),
            DeadLetterReason::InvalidStateTransition => write!(f, "invalid_state_transition"),
            DeadLetterReason::VersionConflict => write!(f, "version_conflict"),
            DeadLetterReason::HandlerError => write!(f, "handler_error"),
            DeadLetterReason::Unknown => write!(f, "unknown"),
        }
    }
}

/// A dead-lettered event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterEvent {
    /// Dead letter record ID
    pub id: Uuid,
    /// Original event ID
    pub event_id: Uuid,
    /// Tenant ID
    pub tenant_id: Uuid,
    /// Store ID
    pub store_id: Uuid,
    /// Event type
    pub event_type: String,
    /// Reason for failure
    pub reason: DeadLetterReason,
    /// Error message
    pub error_message: String,
    /// Number of retry attempts
    pub retry_count: i32,
    /// Last retry timestamp
    pub last_retry_at: Option<DateTime<Utc>>,
    /// When the event was dead-lettered
    pub created_at: DateTime<Utc>,
    /// Original event payload (as JSON)
    pub payload: serde_json::Value,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// PostgreSQL-backed dead letter queue
pub struct PgDeadLetterQueue {
    pool: PgPool,
}

impl PgDeadLetterQueue {
    /// Create a new dead letter queue
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Initialize the dead letter queue table
    pub async fn initialize(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS dead_letter_events (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                event_id UUID NOT NULL,
                tenant_id UUID NOT NULL,
                store_id UUID NOT NULL,
                event_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                error_message TEXT NOT NULL,
                retry_count INT NOT NULL DEFAULT 0,
                last_retry_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                payload JSONB NOT NULL,
                metadata JSONB,

                CONSTRAINT uq_dead_letter_event_id UNIQUE (event_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_dead_letter_tenant_store
            ON dead_letter_events (tenant_id, store_id)
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_dead_letter_reason
            ON dead_letter_events (reason)
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_dead_letter_created_at
            ON dead_letter_events (created_at)
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Add an event to the dead letter queue
    pub async fn enqueue(
        &self,
        event_id: Uuid,
        tenant_id: &TenantId,
        store_id: &StoreId,
        event_type: &str,
        reason: DeadLetterReason,
        error_message: &str,
        payload: serde_json::Value,
        metadata: Option<serde_json::Value>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();

        sqlx::query(
            r#"
            INSERT INTO dead_letter_events (
                id, event_id, tenant_id, store_id, event_type,
                reason, error_message, payload, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (event_id) DO UPDATE SET
                reason = EXCLUDED.reason,
                error_message = EXCLUDED.error_message,
                retry_count = dead_letter_events.retry_count + 1,
                last_retry_at = NOW(),
                metadata = COALESCE(EXCLUDED.metadata, dead_letter_events.metadata)
            "#,
        )
        .bind(id)
        .bind(event_id)
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(event_type)
        .bind(reason.to_string())
        .bind(error_message)
        .bind(&payload)
        .bind(&metadata)
        .execute(&self.pool)
        .await?;

        tracing::warn!(
            event_id = %event_id,
            reason = %reason,
            error = %error_message,
            "Event added to dead letter queue"
        );

        Ok(id)
    }

    /// Get a dead letter event by ID
    pub async fn get(&self, id: Uuid) -> Result<Option<DeadLetterEvent>> {
        let row = sqlx::query_as::<_, DeadLetterRow>(
            r#"
            SELECT id, event_id, tenant_id, store_id, event_type,
                   reason, error_message, retry_count, last_retry_at,
                   created_at, payload, metadata
            FROM dead_letter_events
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DeadLetterEvent::from))
    }

    /// Get a dead letter event by original event ID
    pub async fn get_by_event_id(&self, event_id: Uuid) -> Result<Option<DeadLetterEvent>> {
        let row = sqlx::query_as::<_, DeadLetterRow>(
            r#"
            SELECT id, event_id, tenant_id, store_id, event_type,
                   reason, error_message, retry_count, last_retry_at,
                   created_at, payload, metadata
            FROM dead_letter_events
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DeadLetterEvent::from))
    }

    /// List dead letter events for a tenant/store
    pub async fn list(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DeadLetterEvent>> {
        let rows = sqlx::query_as::<_, DeadLetterRow>(
            r#"
            SELECT id, event_id, tenant_id, store_id, event_type,
                   reason, error_message, retry_count, last_retry_at,
                   created_at, payload, metadata
            FROM dead_letter_events
            WHERE tenant_id = $1 AND store_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DeadLetterEvent::from).collect())
    }

    /// List all dead letter events (admin)
    pub async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<DeadLetterEvent>> {
        let rows = sqlx::query_as::<_, DeadLetterRow>(
            r#"
            SELECT id, event_id, tenant_id, store_id, event_type,
                   reason, error_message, retry_count, last_retry_at,
                   created_at, payload, metadata
            FROM dead_letter_events
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DeadLetterEvent::from).collect())
    }

    /// List dead letter events by reason
    pub async fn list_by_reason(
        &self,
        reason: DeadLetterReason,
        limit: i64,
    ) -> Result<Vec<DeadLetterEvent>> {
        let rows = sqlx::query_as::<_, DeadLetterRow>(
            r#"
            SELECT id, event_id, tenant_id, store_id, event_type,
                   reason, error_message, retry_count, last_retry_at,
                   created_at, payload, metadata
            FROM dead_letter_events
            WHERE reason = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(reason.to_string())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DeadLetterEvent::from).collect())
    }

    /// Count dead letter events
    pub async fn count(&self, tenant_id: Option<&TenantId>) -> Result<i64> {
        let count: (i64,) = match tenant_id {
            Some(tid) => {
                sqlx::query_as(
                    "SELECT COUNT(*) FROM dead_letter_events WHERE tenant_id = $1",
                )
                .bind(tid.0)
                .fetch_one(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as("SELECT COUNT(*) FROM dead_letter_events")
                    .fetch_one(&self.pool)
                    .await?
            }
        };

        Ok(count.0)
    }

    /// Delete a dead letter event (after successful retry)
    pub async fn delete(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM dead_letter_events WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete dead letter events older than a duration
    pub async fn cleanup_old(&self, older_than_days: i32) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM dead_letter_events
            WHERE created_at < NOW() - make_interval(days => $1)
            "#,
        )
        .bind(older_than_days)
        .execute(&self.pool)
        .await?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            tracing::info!(deleted = deleted, "Cleaned up old dead letter events");
        }

        Ok(deleted)
    }

    /// Get statistics about dead letter queue
    pub async fn stats(&self) -> Result<DeadLetterStats> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM dead_letter_events")
            .fetch_one(&self.pool)
            .await?;

        let by_reason: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT reason, COUNT(*) as count
            FROM dead_letter_events
            GROUP BY reason
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let oldest: Option<(DateTime<Utc>,)> = sqlx::query_as(
            "SELECT MIN(created_at) FROM dead_letter_events",
        )
        .fetch_optional(&self.pool)
        .await?;

        let highest_retry: (i32,) = sqlx::query_as(
            "SELECT COALESCE(MAX(retry_count), 0) FROM dead_letter_events",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(DeadLetterStats {
            total_count: total.0,
            by_reason: by_reason.into_iter().collect(),
            oldest_event: oldest.and_then(|o| Some(o.0)),
            highest_retry_count: highest_retry.0,
        })
    }
}

/// Statistics about the dead letter queue
#[derive(Debug, Clone, Serialize)]
pub struct DeadLetterStats {
    pub total_count: i64,
    pub by_reason: std::collections::HashMap<String, i64>,
    pub oldest_event: Option<DateTime<Utc>>,
    pub highest_retry_count: i32,
}

/// Database row for dead letter events
#[derive(Debug, sqlx::FromRow)]
struct DeadLetterRow {
    id: Uuid,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    event_type: String,
    reason: String,
    error_message: String,
    retry_count: i32,
    last_retry_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    payload: serde_json::Value,
    metadata: Option<serde_json::Value>,
}

impl From<DeadLetterRow> for DeadLetterEvent {
    fn from(row: DeadLetterRow) -> Self {
        let reason = match row.reason.as_str() {
            "schema_validation" => DeadLetterReason::SchemaValidation,
            "invariant_violation" => DeadLetterReason::InvariantViolation,
            "invalid_state_transition" => DeadLetterReason::InvalidStateTransition,
            "version_conflict" => DeadLetterReason::VersionConflict,
            "handler_error" => DeadLetterReason::HandlerError,
            _ => DeadLetterReason::Unknown,
        };

        Self {
            id: row.id,
            event_id: row.event_id,
            tenant_id: row.tenant_id,
            store_id: row.store_id,
            event_type: row.event_type,
            reason,
            error_message: row.error_message,
            retry_count: row.retry_count,
            last_retry_at: row.last_retry_at,
            created_at: row.created_at,
            payload: row.payload,
            metadata: row.metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dead_letter_reason_display() {
        assert_eq!(
            DeadLetterReason::SchemaValidation.to_string(),
            "schema_validation"
        );
        assert_eq!(
            DeadLetterReason::InvariantViolation.to_string(),
            "invariant_violation"
        );
        assert_eq!(
            DeadLetterReason::InvalidStateTransition.to_string(),
            "invalid_state_transition"
        );
        assert_eq!(
            DeadLetterReason::VersionConflict.to_string(),
            "version_conflict"
        );
        assert_eq!(DeadLetterReason::HandlerError.to_string(), "handler_error");
        assert_eq!(DeadLetterReason::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_dead_letter_event_serialization() {
        let event = DeadLetterEvent {
            id: Uuid::new_v4(),
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            event_type: "order.created".to_string(),
            reason: DeadLetterReason::SchemaValidation,
            error_message: "Missing required field".to_string(),
            retry_count: 0,
            last_retry_at: None,
            created_at: Utc::now(),
            payload: serde_json::json!({"orderId": "123"}),
            metadata: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("schema_validation"));
        assert!(json.contains("order.created"));
    }
}
