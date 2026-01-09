//! Dead letter queue for failed event projections
//!
//! When event projection fails (due to invariant violations, schema issues, etc.),
//! events are moved to a dead letter queue for later investigation and retry.
//!
//! Features:
//! - Automatic retry scheduling with exponential backoff
//! - Maximum retry limits with configurable thresholds
//! - Priority-based retry ordering
//! - Alerting support for operations teams

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::domain::{StoreId, TenantId};
use crate::infra::Result;

/// Configuration for dead letter queue retry behavior
#[derive(Debug, Clone)]
pub struct DeadLetterRetryConfig {
    /// Initial delay before first retry attempt
    pub initial_delay: Duration,
    /// Maximum delay between retries (caps exponential growth)
    pub max_delay: Duration,
    /// Multiplier for exponential backoff
    pub multiplier: f64,
    /// Maximum number of retry attempts before marking as permanently failed
    pub max_retries: u32,
    /// Reasons that should not be retried automatically
    pub non_retryable_reasons: Vec<DeadLetterReason>,
}

impl Default for DeadLetterRetryConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(60), // 1 minute
            max_delay: Duration::from_secs(3600),   // 1 hour
            multiplier: 2.0,
            max_retries: 10,
            non_retryable_reasons: vec![
                DeadLetterReason::InvariantViolation,
                DeadLetterReason::InvalidStateTransition,
            ],
        }
    }
}

impl DeadLetterRetryConfig {
    /// Calculate the next retry delay based on attempt count
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay_secs = self.initial_delay.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let capped = delay_secs.min(self.max_delay.as_secs_f64());
        Duration::from_secs_f64(capped)
    }

    /// Check if a reason is retryable
    pub fn is_retryable(&self, reason: &DeadLetterReason) -> bool {
        !self.non_retryable_reasons.contains(reason)
    }
}

/// Parameters for enqueueing a dead letter event
pub struct EnqueueParams<'a> {
    pub event_id: Uuid,
    pub tenant_id: &'a TenantId,
    pub store_id: &'a StoreId,
    pub event_type: &'a str,
    pub reason: DeadLetterReason,
    pub error_message: &'a str,
    pub payload: serde_json::Value,
    pub metadata: Option<serde_json::Value>,
}

/// Reason for event being dead-lettered
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Status of a dead letter event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadLetterStatus {
    /// Pending retry (scheduled for future retry)
    Pending,
    /// Currently being retried
    Retrying,
    /// Permanently failed (exceeded max retries or non-retryable)
    Failed,
    /// Successfully processed
    Resolved,
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

impl std::fmt::Display for DeadLetterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeadLetterStatus::Pending => write!(f, "pending"),
            DeadLetterStatus::Retrying => write!(f, "retrying"),
            DeadLetterStatus::Failed => write!(f, "failed"),
            DeadLetterStatus::Resolved => write!(f, "resolved"),
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
    /// Current status
    pub status: DeadLetterStatus,
    /// Error message
    pub error_message: String,
    /// Number of retry attempts
    pub retry_count: i32,
    /// Maximum retry attempts allowed
    pub max_retries: i32,
    /// Last retry timestamp
    pub last_retry_at: Option<DateTime<Utc>>,
    /// When the event was dead-lettered
    pub created_at: DateTime<Utc>,
    /// Next scheduled retry time (None if not retryable or resolved)
    pub next_retry_at: Option<DateTime<Utc>>,
    /// Original event payload (as JSON)
    pub payload: serde_json::Value,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

impl DeadLetterEvent {
    /// Check if this event can be retried
    pub fn can_retry(&self) -> bool {
        self.status == DeadLetterStatus::Pending && self.retry_count < self.max_retries
    }

    /// Check if this event is due for retry
    pub fn is_due_for_retry(&self) -> bool {
        if !self.can_retry() {
            return false;
        }
        match self.next_retry_at {
            Some(next) => Utc::now() >= next,
            None => true,
        }
    }

    /// Check if retry limit has been exceeded
    pub fn has_exceeded_retries(&self) -> bool {
        self.retry_count >= self.max_retries
    }
}

/// PostgreSQL-backed dead letter queue
pub struct PgDeadLetterQueue {
    pool: PgPool,
    config: DeadLetterRetryConfig,
}

impl PgDeadLetterQueue {
    /// Create a new dead letter queue with default config
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            config: DeadLetterRetryConfig::default(),
        }
    }

    /// Create with custom retry config
    pub fn with_config(pool: PgPool, config: DeadLetterRetryConfig) -> Self {
        Self { pool, config }
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
                status TEXT NOT NULL DEFAULT 'pending',
                error_message TEXT NOT NULL,
                retry_count INT NOT NULL DEFAULT 0,
                max_retries INT NOT NULL DEFAULT 10,
                last_retry_at TIMESTAMPTZ,
                next_retry_at TIMESTAMPTZ,
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

        // Add index for scheduled retry queries
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_dead_letter_next_retry
            ON dead_letter_events (status, next_retry_at)
            WHERE status = 'pending'
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Add an event to the dead letter queue
    pub async fn enqueue(&self, params: EnqueueParams<'_>) -> Result<Uuid> {
        let id = Uuid::new_v4();

        // Determine initial status and retry schedule
        let is_retryable = self.config.is_retryable(&params.reason);
        let status = if is_retryable {
            DeadLetterStatus::Pending
        } else {
            DeadLetterStatus::Failed
        };

        let next_retry_at = if is_retryable {
            let delay = self.config.delay_for_attempt(0);
            Some(Utc::now() + ChronoDuration::from_std(delay).unwrap_or(ChronoDuration::minutes(1)))
        } else {
            None
        };

        sqlx::query(
            r#"
            INSERT INTO dead_letter_events (
                id, event_id, tenant_id, store_id, event_type,
                reason, status, error_message, max_retries, next_retry_at, payload, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (event_id) DO UPDATE SET
                reason = EXCLUDED.reason,
                error_message = EXCLUDED.error_message,
                retry_count = dead_letter_events.retry_count + 1,
                last_retry_at = NOW(),
                next_retry_at = CASE
                    WHEN dead_letter_events.retry_count + 1 < dead_letter_events.max_retries
                         AND EXCLUDED.status = 'pending'
                    THEN NOW() + make_interval(secs => power(2, dead_letter_events.retry_count + 1) * 60)
                    ELSE NULL
                END,
                status = CASE
                    WHEN dead_letter_events.retry_count + 1 >= dead_letter_events.max_retries
                    THEN 'failed'
                    ELSE dead_letter_events.status
                END,
                metadata = COALESCE(EXCLUDED.metadata, dead_letter_events.metadata)
            "#,
        )
        .bind(id)
        .bind(params.event_id)
        .bind(params.tenant_id.0)
        .bind(params.store_id.0)
        .bind(params.event_type)
        .bind(params.reason.to_string())
        .bind(status.to_string())
        .bind(params.error_message)
        .bind(self.config.max_retries as i32)
        .bind(next_retry_at)
        .bind(&params.payload)
        .bind(&params.metadata)
        .execute(&self.pool)
        .await?;

        tracing::warn!(
            event_id = %params.event_id,
            reason = %params.reason,
            status = %status,
            retryable = is_retryable,
            error = %params.error_message,
            "Event added to dead letter queue"
        );

        Ok(id)
    }

    /// Get a dead letter event by ID
    pub async fn get(&self, id: Uuid) -> Result<Option<DeadLetterEvent>> {
        let row = sqlx::query_as::<_, DeadLetterRow>(
            r#"
            SELECT id, event_id, tenant_id, store_id, event_type,
                   reason, status, error_message, retry_count, max_retries,
                   last_retry_at, next_retry_at, created_at, payload, metadata
            FROM dead_letter_events
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(DeadLetterEvent::from))
    }

    /// Fetch events that are due for retry
    pub async fn fetch_due_for_retry(&self, limit: i64) -> Result<Vec<DeadLetterEvent>> {
        let rows = sqlx::query_as::<_, DeadLetterRow>(
            r#"
            SELECT id, event_id, tenant_id, store_id, event_type,
                   reason, status, error_message, retry_count, max_retries,
                   last_retry_at, next_retry_at, created_at, payload, metadata
            FROM dead_letter_events
            WHERE status = 'pending'
              AND retry_count < max_retries
              AND (next_retry_at IS NULL OR next_retry_at <= NOW())
            ORDER BY next_retry_at ASC NULLS FIRST, created_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(DeadLetterEvent::from).collect())
    }

    /// Mark an event as being retried (claim it for processing)
    pub async fn mark_retrying(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE dead_letter_events
            SET status = 'retrying',
                last_retry_at = NOW()
            WHERE id = $1
              AND status = 'pending'
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark a retry as successful (resolve the event)
    pub async fn mark_resolved(&self, id: Uuid) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE dead_letter_events
            SET status = 'resolved',
                next_retry_at = NULL
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        tracing::info!(dead_letter_id = %id, "Dead letter event resolved");
        Ok(())
    }

    /// Mark a retry as failed and schedule next attempt
    pub async fn mark_retry_failed(&self, id: Uuid, error: &str) -> Result<()> {
        // Calculate next retry time based on retry count
        sqlx::query(
            r#"
            UPDATE dead_letter_events
            SET status = CASE
                    WHEN retry_count + 1 >= max_retries THEN 'failed'
                    ELSE 'pending'
                END,
                retry_count = retry_count + 1,
                error_message = $2,
                next_retry_at = CASE
                    WHEN retry_count + 1 < max_retries
                    THEN NOW() + make_interval(secs => power(2, retry_count + 1) * 60)
                    ELSE NULL
                END
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(error)
        .execute(&self.pool)
        .await?;

        tracing::warn!(dead_letter_id = %id, error = %error, "Dead letter retry failed");
        Ok(())
    }

    /// Mark an event as permanently failed
    pub async fn mark_permanently_failed(&self, id: Uuid, reason: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE dead_letter_events
            SET status = 'failed',
                next_retry_at = NULL,
                error_message = $2
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        tracing::error!(dead_letter_id = %id, reason = %reason, "Dead letter event permanently failed");
        Ok(())
    }

    /// Get count of events that exceeded retry threshold (for alerting)
    pub async fn count_exceeded_threshold(&self, threshold: i32) -> Result<i64> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM dead_letter_events
            WHERE retry_count >= $1
              AND status != 'resolved'
            "#,
        )
        .bind(threshold)
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0)
    }

    /// Get a dead letter event by original event ID
    pub async fn get_by_event_id(&self, event_id: Uuid) -> Result<Option<DeadLetterEvent>> {
        let row = sqlx::query_as::<_, DeadLetterRow>(
            r#"
            SELECT id, event_id, tenant_id, store_id, event_type,
                   reason, status, error_message, retry_count, max_retries,
                   last_retry_at, next_retry_at, created_at, payload, metadata
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
                   reason, status, error_message, retry_count, max_retries,
                   last_retry_at, next_retry_at, created_at, payload, metadata
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
                   reason, status, error_message, retry_count, max_retries,
                   last_retry_at, next_retry_at, created_at, payload, metadata
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
                   reason, status, error_message, retry_count, max_retries,
                   last_retry_at, next_retry_at, created_at, payload, metadata
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

    /// List dead letter events by status
    pub async fn list_by_status(
        &self,
        status: DeadLetterStatus,
        limit: i64,
    ) -> Result<Vec<DeadLetterEvent>> {
        let rows = sqlx::query_as::<_, DeadLetterRow>(
            r#"
            SELECT id, event_id, tenant_id, store_id, event_type,
                   reason, status, error_message, retry_count, max_retries,
                   last_retry_at, next_retry_at, created_at, payload, metadata
            FROM dead_letter_events
            WHERE status = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(status.to_string())
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

        let pending: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM dead_letter_events WHERE status = 'pending'",
        )
        .fetch_one(&self.pool)
        .await?;

        let failed: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM dead_letter_events WHERE status = 'failed'",
        )
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

        let by_status: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT status, COUNT(*) as count
            FROM dead_letter_events
            GROUP BY status
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

        let due_for_retry: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM dead_letter_events
            WHERE status = 'pending'
              AND retry_count < max_retries
              AND (next_retry_at IS NULL OR next_retry_at <= NOW())
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(DeadLetterStats {
            total_count: total.0,
            pending_count: pending.0,
            failed_count: failed.0,
            by_reason: by_reason.into_iter().collect(),
            by_status: by_status.into_iter().collect(),
            oldest_event: oldest.map(|o| o.0),
            highest_retry_count: highest_retry.0,
            due_for_retry_count: due_for_retry.0,
        })
    }
}

/// Statistics about the dead letter queue
#[derive(Debug, Clone, Serialize)]
pub struct DeadLetterStats {
    pub total_count: i64,
    pub pending_count: i64,
    pub failed_count: i64,
    pub by_reason: std::collections::HashMap<String, i64>,
    pub by_status: std::collections::HashMap<String, i64>,
    pub oldest_event: Option<DateTime<Utc>>,
    pub highest_retry_count: i32,
    pub due_for_retry_count: i64,
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
    status: String,
    error_message: String,
    retry_count: i32,
    max_retries: i32,
    last_retry_at: Option<DateTime<Utc>>,
    next_retry_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    payload: serde_json::Value,
    metadata: Option<serde_json::Value>,
}

fn parse_reason(s: &str) -> DeadLetterReason {
    match s {
        "schema_validation" => DeadLetterReason::SchemaValidation,
        "invariant_violation" => DeadLetterReason::InvariantViolation,
        "invalid_state_transition" => DeadLetterReason::InvalidStateTransition,
        "version_conflict" => DeadLetterReason::VersionConflict,
        "handler_error" => DeadLetterReason::HandlerError,
        _ => DeadLetterReason::Unknown,
    }
}

fn parse_status(s: &str) -> DeadLetterStatus {
    match s {
        "pending" => DeadLetterStatus::Pending,
        "retrying" => DeadLetterStatus::Retrying,
        "failed" => DeadLetterStatus::Failed,
        "resolved" => DeadLetterStatus::Resolved,
        _ => DeadLetterStatus::Pending,
    }
}

impl From<DeadLetterRow> for DeadLetterEvent {
    fn from(row: DeadLetterRow) -> Self {
        Self {
            id: row.id,
            event_id: row.event_id,
            tenant_id: row.tenant_id,
            store_id: row.store_id,
            event_type: row.event_type,
            reason: parse_reason(&row.reason),
            status: parse_status(&row.status),
            error_message: row.error_message,
            retry_count: row.retry_count,
            max_retries: row.max_retries,
            last_retry_at: row.last_retry_at,
            next_retry_at: row.next_retry_at,
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
            status: DeadLetterStatus::Pending,
            error_message: "Missing required field".to_string(),
            retry_count: 0,
            max_retries: 10,
            last_retry_at: None,
            next_retry_at: None,
            created_at: Utc::now(),
            payload: serde_json::json!({"orderId": "123"}),
            metadata: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("schema_validation"));
        assert!(json.contains("order.created"));
        assert!(json.contains("pending"));
    }

    #[test]
    fn test_dead_letter_retry_config() {
        let config = DeadLetterRetryConfig::default();
        assert!(config.is_retryable(&DeadLetterReason::SchemaValidation));
        assert!(config.is_retryable(&DeadLetterReason::VersionConflict));
        assert!(!config.is_retryable(&DeadLetterReason::InvariantViolation));
        assert!(!config.is_retryable(&DeadLetterReason::InvalidStateTransition));

        let delay = config.delay_for_attempt(0);
        assert_eq!(delay, config.initial_delay);

        let delay2 = config.delay_for_attempt(1);
        assert!(delay2 > delay);
    }

    #[test]
    fn test_dead_letter_event_can_retry() {
        let event = DeadLetterEvent {
            id: Uuid::new_v4(),
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            event_type: "order.created".to_string(),
            reason: DeadLetterReason::SchemaValidation,
            status: DeadLetterStatus::Pending,
            error_message: "Missing required field".to_string(),
            retry_count: 0,
            max_retries: 10,
            last_retry_at: None,
            next_retry_at: None,
            created_at: Utc::now(),
            payload: serde_json::json!({"orderId": "123"}),
            metadata: None,
        };

        assert!(event.can_retry());
        assert!(!event.has_exceeded_retries());

        let failed_event = DeadLetterEvent {
            retry_count: 10,
            status: DeadLetterStatus::Failed,
            ..event
        };
        assert!(!failed_event.can_retry());
        assert!(failed_event.has_exceeded_retries());
    }
}
