//! PostgreSQL Event Store implementation
//!
//! Provides append-only encrypted event storage for the production sequencer.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPool, FromRow};
use std::sync::Arc;
use uuid::Uuid;

use crate::domain::{
    AgentId, EntityType, EventEnvelope, EventType, Hash256, SequencedEvent, StoreId, TenantId,
};
use crate::infra::{EventStore, PayloadEncryption, Result, SequencerError};

/// PostgreSQL-based event store
pub struct PgEventStore {
    pool: PgPool,
    payload_encryption: Arc<PayloadEncryption>,
}

impl PgEventStore {
    /// Create a new PostgreSQL event store
    pub fn new(pool: PgPool, payload_encryption: Arc<PayloadEncryption>) -> Self {
        Self {
            pool,
            payload_encryption,
        }
    }

    /// Create from connection string
    pub async fn from_url(url: &str) -> Result<Self> {
        let pool = PgPool::connect(url).await?;
        Ok(Self::new(pool, Arc::new(PayloadEncryption::disabled())))
    }

    /// Create from connection string with explicit encryption configuration.
    pub async fn from_url_with_encryption(
        url: &str,
        payload_encryption: Arc<PayloadEncryption>,
    ) -> Result<Self> {
        let pool = PgPool::connect(url).await?;
        Ok(Self::new(pool, payload_encryption))
    }

    /// Get the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn decode_row(&self, row: EventRow) -> Result<SequencedEvent> {
        let aad = PayloadEncryption::aad_for_row(
            &row.tenant_id,
            &row.store_id,
            &row.event_id,
            row.sequence_number as u64,
            &row.entity_type,
            &row.entity_id,
            &row.event_type,
        );

        let plaintext = self
            .payload_encryption
            .decrypt_payload(&row.tenant_id, &aad, &row.payload_encrypted)
            .await?;

        let payload: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|e| SequencerError::Internal(format!("Invalid payload: {}", e)))?;

        let payload_hash: Hash256 = row
            .payload_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("Invalid payload_hash length".to_string()))?;

        Ok(SequencedEvent {
            envelope: EventEnvelope {
                event_id: row.event_id,
                command_id: row.command_id,
                tenant_id: TenantId::from_uuid(row.tenant_id),
                store_id: StoreId::from_uuid(row.store_id),
                entity_type: EntityType::from(row.entity_type.as_str()),
                entity_id: row.entity_id,
                event_type: EventType::from(row.event_type.as_str()),
                payload,
                payload_hash,
                base_version: row.base_version.map(|v| v as u64),
                created_at: row.created_at,
                sequence_number: Some(row.sequence_number as u64),
                source_agent: AgentId::from_uuid(row.source_agent),
                signature: row.signature,
            },
            sequenced_at: row.sequenced_at,
        })
    }
}

#[async_trait]
impl EventStore for PgEventStore {
    async fn append(&self, events: Vec<SequencedEvent>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;

        for event in events {
            let env = &event.envelope;

            let payload_bytes = serde_json::to_vec(&env.payload)
                .map_err(|e| SequencerError::Internal(e.to_string()))?;
            let aad = PayloadEncryption::aad_for_event(env, event.sequence_number());
            let payload_encrypted = self
                .payload_encryption
                .encrypt_payload(&env.tenant_id.0, &aad, &payload_bytes)
                .await?;

            sqlx::query(
                r#"
                INSERT INTO events (
                    event_id, command_id, sequence_number,
                    tenant_id, store_id,
                    entity_type, entity_id, event_type,
                    payload_encrypted, payload_hash,
                    base_version, source_agent, signature,
                    created_at, sequenced_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (event_id) DO NOTHING
                "#,
            )
            .bind(env.event_id)
            .bind(env.command_id)
            .bind(env.sequence_number.unwrap_or(0) as i64)
            .bind(env.tenant_id.0)
            .bind(env.store_id.0)
            .bind(env.entity_type.as_str())
            .bind(&env.entity_id)
            .bind(env.event_type.as_str())
            .bind(&payload_encrypted)
            .bind(&env.payload_hash[..])
            .bind(env.base_version.map(|v| v as i64))
            .bind(env.source_agent.0)
            .bind(env.signature.as_ref())
            .bind(env.created_at)
            .bind(event.sequenced_at)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn read_range(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<Vec<SequencedEvent>> {
        let rows = sqlx::query_as::<_, EventRow>(
            r#"
            SELECT event_id, command_id, sequence_number,
                   tenant_id, store_id,
                   entity_type, entity_id, event_type,
                   payload_encrypted, payload_hash,
                   base_version, source_agent, signature,
                   created_at, sequenced_at
            FROM events
            WHERE tenant_id = $1 AND store_id = $2
              AND sequence_number >= $3 AND sequence_number <= $4
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(start as i64)
        .bind(end as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(self.decode_row(row).await?);
        }
        Ok(events)
    }

    async fn read_entity(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &EntityType,
        entity_id: &str,
    ) -> Result<Vec<SequencedEvent>> {
        let rows = sqlx::query_as::<_, EventRow>(
            r#"
            SELECT event_id, command_id, sequence_number,
                   tenant_id, store_id,
                   entity_type, entity_id, event_type,
                   payload_encrypted, payload_hash,
                   base_version, source_agent, signature,
                   created_at, sequenced_at
            FROM events
            WHERE tenant_id = $1 AND store_id = $2
              AND entity_type = $3 AND entity_id = $4
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(entity_type.as_str())
        .bind(entity_id)
        .fetch_all(&self.pool)
        .await?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(self.decode_row(row).await?);
        }
        Ok(events)
    }

    async fn read_by_id(&self, event_id: Uuid) -> Result<Option<SequencedEvent>> {
        let row = sqlx::query_as::<_, EventRow>(
            r#"
            SELECT event_id, command_id, sequence_number,
                   tenant_id, store_id,
                   entity_type, entity_id, event_type,
                   payload_encrypted, payload_hash,
                   base_version, source_agent, signature,
                   created_at, sequenced_at
            FROM events
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(self.decode_row(row).await?)),
            None => Ok(None),
        }
    }

    async fn event_exists(&self, event_id: Uuid) -> Result<bool> {
        let row: (bool,) =
            sqlx::query_as("SELECT EXISTS(SELECT 1 FROM events WHERE event_id = $1)")
                .bind(event_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0)
    }

    async fn command_exists(&self, command_id: Uuid) -> Result<bool> {
        let row: (bool,) =
            sqlx::query_as("SELECT EXISTS(SELECT 1 FROM events WHERE command_id = $1)")
                .bind(command_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0)
    }
}

/// Additional methods not in the trait
impl PgEventStore {
    /// Get events by type within a sequence range
    pub async fn read_by_type(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        event_type: &EventType,
        start: u64,
        end: u64,
    ) -> Result<Vec<SequencedEvent>> {
        let rows = sqlx::query_as::<_, EventRow>(
            r#"
            SELECT event_id, command_id, sequence_number,
                   tenant_id, store_id,
                   entity_type, entity_id, event_type,
                   payload_encrypted, payload_hash,
                   base_version, source_agent, signature,
                   created_at, sequenced_at
            FROM events
            WHERE tenant_id = $1 AND store_id = $2
              AND event_type = $3
              AND sequence_number >= $4 AND sequence_number <= $5
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(event_type.as_str())
        .bind(start as i64)
        .bind(end as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(self.decode_row(row).await?);
        }
        Ok(events)
    }

    /// Get payload hashes for a sequence range (for Merkle tree construction)
    pub async fn get_payload_hashes(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<Vec<(u64, Hash256)>> {
        let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT sequence_number, payload_hash
            FROM events
            WHERE tenant_id = $1 AND store_id = $2
              AND sequence_number >= $3 AND sequence_number <= $4
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(start as i64)
        .bind(end as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(seq, hash)| {
                let hash_arr: Hash256 = hash
                    .try_into()
                    .map_err(|_| SequencerError::Internal("Invalid hash length".to_string()))?;
                Ok((seq as u64, hash_arr))
            })
            .collect()
    }

    /// Count events in a sequence range
    pub async fn count_range(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<u64> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM events
            WHERE tenant_id = $1 AND store_id = $2
              AND sequence_number >= $3 AND sequence_number <= $4
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(start as i64)
        .bind(end as i64)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0 as u64)
    }

    /// Get leaf inputs for a sequence range (for Merkle tree construction).
    pub async fn get_leaf_inputs(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<Vec<LeafInput>> {
        let rows: Vec<(i64, Vec<u8>, String, String)> = sqlx::query_as(
            r#"
            SELECT sequence_number, payload_hash, entity_type, entity_id
            FROM events
            WHERE tenant_id = $1 AND store_id = $2
              AND sequence_number >= $3 AND sequence_number <= $4
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(start as i64)
        .bind(end as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(seq, hash, entity_type, entity_id)| {
                let hash_arr: Hash256 = hash
                    .try_into()
                    .map_err(|_| SequencerError::Internal("Invalid hash length".to_string()))?;
                Ok(LeafInput {
                    sequence_number: seq as u64,
                    payload_hash: hash_arr,
                    entity_type,
                    entity_id,
                })
            })
            .collect()
    }
}

/// Inputs needed to compute a commitment leaf hash.
#[derive(Debug, Clone)]
pub struct LeafInput {
    pub sequence_number: u64,
    pub payload_hash: Hash256,
    pub entity_type: String,
    pub entity_id: String,
}

/// Raw row from events table
#[derive(Debug, FromRow)]
struct EventRow {
    event_id: Uuid,
    command_id: Option<Uuid>,
    sequence_number: i64,
    tenant_id: Uuid,
    store_id: Uuid,
    entity_type: String,
    entity_id: String,
    event_type: String,
    payload_encrypted: Vec<u8>,
    payload_hash: Vec<u8>,
    base_version: Option<i64>,
    source_agent: Uuid,
    signature: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
    sequenced_at: DateTime<Utc>,
}
