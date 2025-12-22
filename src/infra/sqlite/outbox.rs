//! SQLite Outbox implementation for local agent event capture
//!
//! The outbox pattern allows CLI agents to:
//! 1. Apply mutations locally in a single atomic transaction
//! 2. Append events to the outbox
//! 3. Later push events to the remote sequencer

use chrono::{DateTime, Utc};
use sqlx::{sqlite::SqlitePool, FromRow};
use uuid::Uuid;

use crate::domain::{
    AgentId, EntityType, EventEnvelope, EventType, Hash256, SequencedEvent, StoreId, SyncState,
    TenantId,
};
use crate::infra::{Result, SequencerError};

/// SQLite-based outbox for local event capture
pub struct SqliteOutbox {
    pool: SqlitePool,
}

impl SqliteOutbox {
    /// Create a new SQLite outbox with the given connection pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new SQLite outbox from a database path
    pub async fn from_path(path: &str) -> Result<Self> {
        let pool = SqlitePool::connect(path).await?;
        Ok(Self { pool })
    }

    /// Initialize the database schema
    pub async fn initialize(&self) -> Result<()> {
        crate::migrations::run_sqlite(&self.pool)
            .await
            .map_err(|e| SequencerError::SchemaValidation(e.to_string()))
    }

    /// Append an event to the local outbox
    pub async fn append(&self, event: &EventEnvelope) -> Result<i64> {
        let payload_json = serde_json::to_string(&event.payload)
            .map_err(|e| SequencerError::Internal(e.to_string()))?;
        let payload_hash_hex = hex::encode(event.payload_hash);

        let result = sqlx::query(
            r#"
            INSERT INTO outbox (
                event_id, command_id, tenant_id, store_id,
                entity_type, entity_id, event_type,
                payload, payload_hash, base_version,
                created_at, source_agent, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.event_id.to_string())
        .bind(event.command_id.map(|id| id.to_string()))
        .bind(event.tenant_id.0.to_string())
        .bind(event.store_id.0.to_string())
        .bind(event.entity_type.as_str())
        .bind(&event.entity_id)
        .bind(event.event_type.as_str())
        .bind(&payload_json)
        .bind(&payload_hash_hex)
        .bind(event.base_version.map(|v| v as i64))
        .bind(event.created_at.to_rfc3339())
        .bind(event.source_agent.0.to_string())
        .bind(event.signature.as_ref())
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Append multiple events atomically
    pub async fn append_batch(&self, events: &[EventEnvelope]) -> Result<Vec<i64>> {
        let mut tx = self.pool.begin().await?;
        let mut ids = Vec::with_capacity(events.len());

        for event in events {
            let payload_json = serde_json::to_string(&event.payload)
                .map_err(|e| SequencerError::Internal(e.to_string()))?;
            let payload_hash_hex = hex::encode(event.payload_hash);

            let result = sqlx::query(
                r#"
                INSERT INTO outbox (
                    event_id, command_id, tenant_id, store_id,
                    entity_type, entity_id, event_type,
                    payload, payload_hash, base_version,
                    created_at, source_agent, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(event.event_id.to_string())
            .bind(event.command_id.map(|id| id.to_string()))
            .bind(event.tenant_id.0.to_string())
            .bind(event.store_id.0.to_string())
            .bind(event.entity_type.as_str())
            .bind(&event.entity_id)
            .bind(event.event_type.as_str())
            .bind(&payload_json)
            .bind(&payload_hash_hex)
            .bind(event.base_version.map(|v| v as i64))
            .bind(event.created_at.to_rfc3339())
            .bind(event.source_agent.0.to_string())
            .bind(event.signature.as_ref())
            .execute(&mut *tx)
            .await?;

            ids.push(result.last_insert_rowid());
        }

        tx.commit().await?;
        Ok(ids)
    }

    /// Get all unpushed events (events not yet sent to remote)
    pub async fn get_unpushed(&self) -> Result<Vec<OutboxEvent>> {
        let rows = sqlx::query_as::<_, OutboxEventRow>(
            r#"
            SELECT id, event_id, command_id, tenant_id, store_id,
                   entity_type, entity_id, event_type,
                   payload, payload_hash, base_version,
                   created_at, source_agent, signature,
                   pushed_at, acked_at, remote_sequence
            FROM outbox
            WHERE pushed_at IS NULL
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(OutboxEvent::try_from).collect()
    }

    /// Get unpushed events with limit
    pub async fn get_unpushed_batch(&self, limit: u32) -> Result<Vec<OutboxEvent>> {
        let rows = sqlx::query_as::<_, OutboxEventRow>(
            r#"
            SELECT id, event_id, command_id, tenant_id, store_id,
                   entity_type, entity_id, event_type,
                   payload, payload_hash, base_version,
                   created_at, source_agent, signature,
                   pushed_at, acked_at, remote_sequence
            FROM outbox
            WHERE pushed_at IS NULL
            ORDER BY id ASC
            LIMIT ?
            "#,
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(OutboxEvent::try_from).collect()
    }

    /// Mark events as pushed (sent to remote, awaiting ack)
    pub async fn mark_pushed(&self, event_ids: &[Uuid]) -> Result<()> {
        if event_ids.is_empty() {
            return Ok(());
        }

        let now = Utc::now().to_rfc3339();
        let placeholders: Vec<&str> = event_ids.iter().map(|_| "?").collect();
        let query = format!(
            "UPDATE outbox SET pushed_at = ? WHERE event_id IN ({})",
            placeholders.join(", ")
        );

        let mut q = sqlx::query(&query).bind(&now);
        for id in event_ids {
            q = q.bind(id.to_string());
        }

        q.execute(&self.pool).await?;
        Ok(())
    }

    /// Mark events as acknowledged (confirmed by remote with sequence numbers)
    pub async fn mark_acked(&self, acks: &[(Uuid, u64)]) -> Result<()> {
        if acks.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;
        let now = Utc::now().to_rfc3339();

        for (event_id, sequence) in acks {
            sqlx::query("UPDATE outbox SET acked_at = ?, remote_sequence = ? WHERE event_id = ?")
                .bind(&now)
                .bind(*sequence as i64)
                .bind(event_id.to_string())
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Get count of unpushed events
    pub async fn unpushed_count(&self) -> Result<u64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM outbox WHERE pushed_at IS NULL")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0 as u64)
    }

    /// Get count of unacked events (pushed but not confirmed)
    pub async fn unacked_count(&self) -> Result<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM outbox WHERE pushed_at IS NOT NULL AND acked_at IS NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 as u64)
    }

    /// Prune acknowledged events older than given duration
    pub async fn prune_acked(&self, older_than: chrono::Duration) -> Result<u64> {
        let cutoff = (Utc::now() - older_than).to_rfc3339();
        let result = sqlx::query("DELETE FROM outbox WHERE acked_at IS NOT NULL AND acked_at < ?")
            .bind(&cutoff)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Get sync state value
    pub async fn get_sync_state(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM sync_state WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.0))
    }

    /// Set sync state value
    pub async fn set_sync_state(&self, key: &str, value: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            INSERT INTO sync_state (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(&now)
        .bind(value)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get full sync state
    pub async fn get_full_sync_state(&self) -> Result<SyncState> {
        let agent_id = self
            .get_sync_state("agent_id")
            .await?
            .and_then(|s| Uuid::parse_str(&s).ok())
            .map(AgentId::from_uuid)
            .unwrap_or_else(AgentId::new);

        let last_pushed = self
            .get_sync_state("last_pushed_sequence")
            .await?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let last_pulled = self
            .get_sync_state("last_pulled_sequence")
            .await?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let head = self
            .get_sync_state("head_sequence")
            .await?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let last_sync_at = self
            .get_sync_state("last_sync_at")
            .await?
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        Ok(SyncState {
            agent_id,
            last_pushed_sequence: last_pushed,
            last_pulled_sequence: last_pulled,
            head_sequence: head,
            last_sync_at,
        })
    }

    /// Update full sync state
    pub async fn update_full_sync_state(&self, state: &SyncState) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now().to_rfc3339();

        for (key, value) in [
            ("agent_id", state.agent_id.0.to_string()),
            (
                "last_pushed_sequence",
                state.last_pushed_sequence.to_string(),
            ),
            (
                "last_pulled_sequence",
                state.last_pulled_sequence.to_string(),
            ),
            ("head_sequence", state.head_sequence.to_string()),
            ("last_sync_at", state.last_sync_at.to_rfc3339()),
        ] {
            sqlx::query(
                r#"
                INSERT INTO sync_state (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?
                "#,
            )
            .bind(key)
            .bind(&value)
            .bind(&now)
            .bind(&value)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Store a pulled event (from remote)
    pub async fn store_pulled_event(&self, event: &SequencedEvent) -> Result<()> {
        let payload_json = serde_json::to_string(&event.envelope.payload)
            .map_err(|e| SequencerError::Internal(e.to_string()))?;
        let payload_hash_hex = hex::encode(event.envelope.payload_hash);

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO pulled_events (
                sequence_number, event_id, command_id,
                tenant_id, store_id,
                entity_type, entity_id, event_type,
                payload, payload_hash, base_version,
                created_at, sequenced_at, source_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.envelope.sequence_number.unwrap_or(0) as i64)
        .bind(event.envelope.event_id.to_string())
        .bind(event.envelope.command_id.map(|id| id.to_string()))
        .bind(event.envelope.tenant_id.0.to_string())
        .bind(event.envelope.store_id.0.to_string())
        .bind(event.envelope.entity_type.as_str())
        .bind(&event.envelope.entity_id)
        .bind(event.envelope.event_type.as_str())
        .bind(&payload_json)
        .bind(&payload_hash_hex)
        .bind(event.envelope.base_version.map(|v| v as i64))
        .bind(event.envelope.created_at.to_rfc3339())
        .bind(event.sequenced_at.to_rfc3339())
        .bind(event.envelope.source_agent.0.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store multiple pulled events
    pub async fn store_pulled_events(&self, events: &[SequencedEvent]) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        for event in events {
            let payload_json = serde_json::to_string(&event.envelope.payload)
                .map_err(|e| SequencerError::Internal(e.to_string()))?;
            let payload_hash_hex = hex::encode(event.envelope.payload_hash);

            sqlx::query(
                r#"
                INSERT OR REPLACE INTO pulled_events (
                    sequence_number, event_id, command_id,
                    tenant_id, store_id,
                    entity_type, entity_id, event_type,
                    payload, payload_hash, base_version,
                    created_at, sequenced_at, source_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(event.envelope.sequence_number.unwrap_or(0) as i64)
            .bind(event.envelope.event_id.to_string())
            .bind(event.envelope.command_id.map(|id| id.to_string()))
            .bind(event.envelope.tenant_id.0.to_string())
            .bind(event.envelope.store_id.0.to_string())
            .bind(event.envelope.entity_type.as_str())
            .bind(&event.envelope.entity_id)
            .bind(event.envelope.event_type.as_str())
            .bind(&payload_json)
            .bind(&payload_hash_hex)
            .bind(event.envelope.base_version.map(|v| v as i64))
            .bind(event.envelope.created_at.to_rfc3339())
            .bind(event.sequenced_at.to_rfc3339())
            .bind(event.envelope.source_agent.0.to_string())
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Get entity version
    pub async fn get_entity_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &EntityType,
        entity_id: &str,
    ) -> Result<Option<u64>> {
        let row: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT version FROM entity_versions
            WHERE tenant_id = ? AND store_id = ? AND entity_type = ? AND entity_id = ?
            "#,
        )
        .bind(tenant_id.0.to_string())
        .bind(store_id.0.to_string())
        .bind(entity_type.as_str())
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.0 as u64))
    }

    /// Update entity version
    pub async fn update_entity_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &EntityType,
        entity_id: &str,
        new_version: u64,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            INSERT INTO entity_versions (tenant_id, store_id, entity_type, entity_id, version, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, store_id, entity_type, entity_id)
            DO UPDATE SET version = ?, updated_at = ?
            "#,
        )
        .bind(tenant_id.0.to_string())
        .bind(store_id.0.to_string())
        .bind(entity_type.as_str())
        .bind(entity_id)
        .bind(new_version as i64)
        .bind(&now)
        .bind(new_version as i64)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// Raw row from outbox table
#[derive(Debug, FromRow)]
struct OutboxEventRow {
    id: i64,
    event_id: String,
    command_id: Option<String>,
    tenant_id: String,
    store_id: String,
    entity_type: String,
    entity_id: String,
    event_type: String,
    payload: String,
    payload_hash: String,
    base_version: Option<i64>,
    created_at: String,
    source_agent: String,
    signature: Option<Vec<u8>>,
    pushed_at: Option<String>,
    acked_at: Option<String>,
    remote_sequence: Option<i64>,
}

/// Outbox event with parsed fields
#[derive(Debug, Clone)]
pub struct OutboxEvent {
    pub local_id: i64,
    pub envelope: EventEnvelope,
    pub pushed_at: Option<DateTime<Utc>>,
    pub acked_at: Option<DateTime<Utc>>,
    pub remote_sequence: Option<u64>,
}

impl TryFrom<OutboxEventRow> for OutboxEvent {
    type Error = SequencerError;

    fn try_from(row: OutboxEventRow) -> Result<Self> {
        let event_id = Uuid::parse_str(&row.event_id)
            .map_err(|e| SequencerError::Internal(format!("Invalid event_id: {}", e)))?;

        let command_id = row
            .command_id
            .map(|s| Uuid::parse_str(&s))
            .transpose()
            .map_err(|e| SequencerError::Internal(format!("Invalid command_id: {}", e)))?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| SequencerError::Internal(format!("Invalid tenant_id: {}", e)))?;

        let store_id = Uuid::parse_str(&row.store_id)
            .map_err(|e| SequencerError::Internal(format!("Invalid store_id: {}", e)))?;

        let source_agent = Uuid::parse_str(&row.source_agent)
            .map_err(|e| SequencerError::Internal(format!("Invalid source_agent: {}", e)))?;

        let payload: serde_json::Value = serde_json::from_str(&row.payload)
            .map_err(|e| SequencerError::Internal(format!("Invalid payload JSON: {}", e)))?;

        let payload_hash: Hash256 = hex::decode(&row.payload_hash)
            .map_err(|e| SequencerError::Internal(format!("Invalid payload_hash: {}", e)))?
            .try_into()
            .map_err(|_| SequencerError::Internal("Invalid payload_hash length".to_string()))?;

        let created_at = DateTime::parse_from_rfc3339(&row.created_at)
            .map_err(|e| SequencerError::Internal(format!("Invalid created_at: {}", e)))?
            .with_timezone(&Utc);

        let pushed_at = row
            .pushed_at
            .map(|s| DateTime::parse_from_rfc3339(&s))
            .transpose()
            .map_err(|e| SequencerError::Internal(format!("Invalid pushed_at: {}", e)))?
            .map(|dt| dt.with_timezone(&Utc));

        let acked_at = row
            .acked_at
            .map(|s| DateTime::parse_from_rfc3339(&s))
            .transpose()
            .map_err(|e| SequencerError::Internal(format!("Invalid acked_at: {}", e)))?
            .map(|dt| dt.with_timezone(&Utc));

        Ok(OutboxEvent {
            local_id: row.id,
            envelope: EventEnvelope {
                event_id,
                command_id,
                tenant_id: TenantId::from_uuid(tenant_id),
                store_id: StoreId::from_uuid(store_id),
                entity_type: EntityType::from(row.entity_type.as_str()),
                entity_id: row.entity_id,
                event_type: EventType::from(row.event_type.as_str()),
                payload,
                payload_hash,
                base_version: row.base_version.map(|v| v as u64),
                created_at,
                sequence_number: row.remote_sequence.map(|s| s as u64),
                source_agent: AgentId::from_uuid(source_agent),
                signature: row.signature,
            },
            pushed_at,
            acked_at,
            remote_sequence: row.remote_sequence.map(|s| s as u64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_db() -> SqliteOutbox {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        let outbox = SqliteOutbox::new(pool);
        outbox.initialize().await.unwrap();
        outbox
    }

    #[tokio::test]
    async fn test_append_and_get_unpushed() {
        let outbox = create_test_db().await;

        let event = EventEnvelope::new(
            TenantId::new(),
            StoreId::new(),
            EntityType::order(),
            "order-123",
            EventType::from("order.created"),
            serde_json::json!({"customer_id": "cust-456"}),
            AgentId::new(),
        );

        let id = outbox.append(&event).await.unwrap();
        assert!(id > 0);

        let unpushed = outbox.get_unpushed().await.unwrap();
        assert_eq!(unpushed.len(), 1);
        assert_eq!(unpushed[0].envelope.event_id, event.event_id);
    }

    #[tokio::test]
    async fn test_mark_pushed_and_acked() {
        let outbox = create_test_db().await;

        let event = EventEnvelope::new(
            TenantId::new(),
            StoreId::new(),
            EntityType::product(),
            "prod-789",
            EventType::from("product.updated"),
            serde_json::json!({"price": 29.99}),
            AgentId::new(),
        );

        outbox.append(&event).await.unwrap();

        // Should be 1 unpushed
        assert_eq!(outbox.unpushed_count().await.unwrap(), 1);

        // Mark as pushed
        outbox.mark_pushed(&[event.event_id]).await.unwrap();
        assert_eq!(outbox.unpushed_count().await.unwrap(), 0);
        assert_eq!(outbox.unacked_count().await.unwrap(), 1);

        // Mark as acked with sequence number
        outbox.mark_acked(&[(event.event_id, 42)]).await.unwrap();
        assert_eq!(outbox.unacked_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_sync_state() {
        let outbox = create_test_db().await;

        // Default values
        let state = outbox.get_full_sync_state().await.unwrap();
        assert_eq!(state.last_pushed_sequence, 0);
        assert_eq!(state.last_pulled_sequence, 0);

        // Update state
        let mut new_state = state;
        new_state.last_pushed_sequence = 100;
        new_state.last_pulled_sequence = 95;
        new_state.head_sequence = 100;
        outbox.update_full_sync_state(&new_state).await.unwrap();

        // Verify
        let loaded = outbox.get_full_sync_state().await.unwrap();
        assert_eq!(loaded.last_pushed_sequence, 100);
        assert_eq!(loaded.last_pulled_sequence, 95);
        assert_eq!(loaded.head_sequence, 100);
    }
}
