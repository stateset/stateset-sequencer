//! PostgreSQL Sequencer implementation
//!
//! Provides canonical ordering of events with monotonic sequence numbers.
//! This is the core component that ensures deterministic event ordering.
//!
//! # Ordering Guarantees
//!
//! - **Gap-Free**: Sequence numbers are contiguous with no gaps
//! - **Monotonic**: Each number is strictly greater than the previous
//! - **Per-Stream**: Sequences are scoped to (tenant_id, store_id) pairs
//! - **Linearizable**: Total ordering via PostgreSQL transactions
//!
//! # Atomicity
//!
//! Sequence assignment uses `SELECT FOR UPDATE` on the `sequence_counters` table:
//! ```sql
//! BEGIN;
//! SELECT current_sequence FROM sequence_counters
//!     WHERE tenant_id = $1 AND store_id = $2 FOR UPDATE;
//! -- increment and insert event atomically
//! COMMIT;
//! ```
//!
//! This ensures that even with multiple concurrent requests, each event
//! receives a unique, sequential number within its stream.
//!
//! # Idempotency
//!
//! Events are deduplicated by:
//! - `event_id`: Globally unique, rejects exact duplicates
//! - `command_id`: Intent-level dedup, same command = same effect

use async_trait::async_trait;
use chrono::Utc;
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Transaction};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

use crate::domain::{
    AgentId, EntityType, EventBatch, EventEnvelope, IngestReceipt, RejectedEvent, RejectionReason,
    SequencedEvent, StoreId, SyncState, TenantId,
};
use crate::infra::{IngestService, PayloadEncryption, Result, Sequencer, SequencerError};

use super::PgEventStore;

/// PostgreSQL-based sequencer service
pub struct PgSequencer {
    pool: PgPool,
    event_store: PgEventStore,
    payload_encryption: Arc<PayloadEncryption>,
}

impl PgSequencer {
    /// Create a new PostgreSQL sequencer
    pub fn new(pool: PgPool, payload_encryption: Arc<PayloadEncryption>) -> Self {
        let event_store = PgEventStore::new(pool.clone(), payload_encryption.clone());
        Self {
            pool,
            event_store,
            payload_encryption,
        }
    }

    async fn lock_sequence_counter(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<u64> {
        // Ensure the counter row exists.
        sqlx::query(
            r#"
            INSERT INTO sequence_counters (tenant_id, store_id, current_sequence, updated_at)
            VALUES ($1, $2, 0, NOW())
            ON CONFLICT (tenant_id, store_id) DO NOTHING
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .execute(&mut **tx)
        .await?;

        // Lock the row so sequencing is linearizable per (tenant_id, store_id).
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT current_sequence
            FROM sequence_counters
            WHERE tenant_id = $1 AND store_id = $2
            FOR UPDATE
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_one(&mut **tx)
        .await?;

        Ok(row.0 as u64)
    }

    async fn set_sequence_counter(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        head: u64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE sequence_counters
            SET current_sequence = $3,
                updated_at = NOW()
            WHERE tenant_id = $1 AND store_id = $2
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(head as i64)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    /// Get multiple sequence numbers atomically
    async fn get_sequence_range(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        count: u32,
    ) -> Result<(u64, u64)> {
        if count == 0 {
            let head = self.head(tenant_id, store_id).await?;
            return Ok((head, head));
        }

        let row: (i64,) = sqlx::query_as(
            r#"
            INSERT INTO sequence_counters (tenant_id, store_id, current_sequence, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (tenant_id, store_id)
            DO UPDATE SET
                current_sequence = sequence_counters.current_sequence + $3,
                updated_at = NOW()
            RETURNING current_sequence
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(count as i64)
        .fetch_one(&self.pool)
        .await?;

        let end = row.0 as u64;
        let start = end - count as u64 + 1;
        Ok((start, end))
    }

    async fn fetch_existing_event_ids_tx(
        tx: &mut Transaction<'_, Postgres>,
        events: &[EventEnvelope],
    ) -> Result<HashSet<Uuid>> {
        let event_ids: Vec<Uuid> = events.iter().map(|e| e.event_id).collect();

        if event_ids.is_empty() {
            return Ok(HashSet::new());
        }

        let rows: Vec<(Uuid,)> =
            sqlx::query_as(r#"SELECT event_id FROM events WHERE event_id = ANY($1)"#)
                .bind(&event_ids)
                .fetch_all(&mut **tx)
                .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Validate event schema and payload hash
    fn validate_event(&self, event: &EventEnvelope) -> Option<RejectedEvent> {
        // Verify payload hash
        if !event.verify_payload_hash() {
            return Some(RejectedEvent {
                event_id: event.event_id,
                reason: RejectionReason::InvalidPayloadHash,
                message: "Payload hash does not match payload".to_string(),
            });
        }

        let entity_type = event.entity_type.as_str();
        if entity_type.is_empty() || entity_type.len() > 64 {
            return Some(RejectedEvent {
                event_id: event.event_id,
                reason: RejectionReason::SchemaValidation,
                message: "entity_type must be 1-64 characters".to_string(),
            });
        }

        if event.entity_id.is_empty() || event.entity_id.len() > 256 {
            return Some(RejectedEvent {
                event_id: event.event_id,
                reason: RejectionReason::SchemaValidation,
                message: "entity_id must be 1-256 characters".to_string(),
            });
        }

        let event_type = event.event_type.as_str();
        if event_type.is_empty() || event_type.len() > 64 {
            return Some(RejectedEvent {
                event_id: event.event_id,
                reason: RejectionReason::SchemaValidation,
                message: "event_type must be 1-64 characters".to_string(),
            });
        }

        None
    }

    async fn insert_event_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event: &SequencedEvent,
    ) -> Result<bool> {
        let env = &event.envelope;

        let payload_bytes = serde_json::to_vec(&env.payload)
            .map_err(|e| SequencerError::Internal(e.to_string()))?;

        let aad = PayloadEncryption::aad_for_event(env, event.sequence_number());
        let payload_encrypted = self
            .payload_encryption
            .encrypt_payload(&env.tenant_id.0, &aad, &payload_bytes)
            .await?;

        let result = sqlx::query(
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
        .execute(&mut **tx)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    async fn bump_entity_version_tx(
        tx: &mut Transaction<'_, Postgres>,
        event: &SequencedEvent,
    ) -> Result<()> {
        let env = &event.envelope;
        sqlx::query(
            r#"
            INSERT INTO entity_versions (
                tenant_id, store_id, entity_type, entity_id, version, updated_at
            ) VALUES ($1, $2, $3, $4, 1, NOW())
            ON CONFLICT (tenant_id, store_id, entity_type, entity_id)
            DO UPDATE SET
                version = entity_versions.version + 1,
                updated_at = NOW()
            "#,
        )
        .bind(env.tenant_id.0)
        .bind(env.store_id.0)
        .bind(env.entity_type.as_str())
        .bind(&env.entity_id)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    /// Get the current entity version within a transaction (for OCC at ingest time)
    async fn get_entity_version_tx(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &EntityType,
        entity_id: &str,
    ) -> Result<Option<u64>> {
        let row: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT version
            FROM entity_versions
            WHERE tenant_id = $1 AND store_id = $2 AND entity_type = $3 AND entity_id = $4
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(entity_type.as_str())
        .bind(entity_id)
        .fetch_optional(&mut **tx)
        .await?;

        Ok(row.map(|(v,)| v as u64))
    }

    async fn fetch_existing_command_id_tx(
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let row: Option<(Option<Uuid>,)> =
            sqlx::query_as("SELECT command_id FROM events WHERE event_id = $1")
                .bind(event_id)
                .fetch_optional(&mut **tx)
                .await?;
        Ok(row.and_then(|(cmd_id,)| cmd_id))
    }

    async fn release_command_id_tx(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        command_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM event_command_dedupe
            WHERE tenant_id = $1 AND store_id = $2 AND command_id = $3
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(command_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Sequencer for PgSequencer {
    #[instrument(skip(self, events), fields(event_count = events.len()))]
    async fn sequence(&self, events: Vec<EventEnvelope>) -> Result<Vec<SequencedEvent>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        // All events should be for the same tenant/store
        let tenant_id = &events[0].tenant_id;
        let store_id = &events[0].store_id;

        // Get sequence range
        let (start, _end) = self
            .get_sequence_range(tenant_id, store_id, events.len() as u32)
            .await?;

        // Assign sequence numbers
        let sequenced: Vec<SequencedEvent> = events
            .into_iter()
            .enumerate()
            .map(|(i, env)| SequencedEvent::new(env, start + i as u64))
            .collect();

        Ok(sequenced)
    }

    #[instrument(skip(self), fields(tenant_id = %tenant_id.0, store_id = %store_id.0))]
    async fn head(&self, tenant_id: &TenantId, store_id: &StoreId) -> Result<u64> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT current_sequence FROM sequence_counters WHERE tenant_id = $1 AND store_id = $2",
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.0 as u64).unwrap_or(0))
    }
}

#[async_trait]
impl IngestService for PgSequencer {
    #[instrument(skip(self, batch), fields(
        batch_size = batch.len(),
        tenant_id = batch.events.first().map(|e| e.tenant_id.0.to_string()).unwrap_or_default(),
        store_id = batch.events.first().map(|e| e.store_id.0.to_string()).unwrap_or_default()
    ))]
    async fn ingest(&self, batch: EventBatch) -> Result<IngestReceipt> {
        if batch.is_empty() {
            // Return empty receipt for empty batch
            let head = if let Some(first) = batch.events.first() {
                self.head(&first.tenant_id, &first.store_id).await?
            } else {
                0
            };

            return Ok(IngestReceipt {
                batch_id: Uuid::new_v4(),
                events_accepted: 0,
                events_rejected: Vec::new(),
                assigned_sequence_start: None,
                assigned_sequence_end: None,
                head_sequence: head,
            });
        }

        let batch_id = Uuid::new_v4();
        let tenant_id = batch.events[0].tenant_id.clone();
        let store_id = batch.events[0].store_id.clone();

        // Enforce single-tenant/store batches at the sequencer boundary.
        for e in &batch.events {
            if e.tenant_id.0 != tenant_id.0 || e.store_id.0 != store_id.0 {
                return Err(SequencerError::SchemaValidation(
                    "All events in a batch must share the same tenant_id and store_id".to_string(),
                ));
            }
        }

        let mut tx = self.pool.begin().await?;

        // Serialize ingest per (tenant_id, store_id) and keep counters + inserts atomic.
        let mut head = Self::lock_sequence_counter(&mut tx, &tenant_id, &store_id).await?;
        let existing_event_ids = Self::fetch_existing_event_ids_tx(&mut tx, &batch.events).await?;

        let mut rejected = Vec::new();
        let mut candidates = Vec::new();
        let mut command_ids = HashSet::new();
        let mut seen_event_ids = HashSet::new();
        let mut seen_command_ids = HashSet::new();

        // Validate each event (schema + payload hash + duplicates).
        for event in batch.events {
            if !seen_event_ids.insert(event.event_id) {
                rejected.push(RejectedEvent {
                    event_id: event.event_id,
                    reason: RejectionReason::DuplicateEventId,
                    message: format!("Event {} duplicated in batch", event.event_id),
                });
                continue;
            }

            if existing_event_ids.contains(&event.event_id) {
                rejected.push(RejectedEvent {
                    event_id: event.event_id,
                    reason: RejectionReason::DuplicateEventId,
                    message: format!("Event {} already exists", event.event_id),
                });
                continue;
            }

            if let Some(rejection) = self.validate_event(&event) {
                rejected.push(rejection);
                continue;
            }

            if let Some(cmd_id) = event.command_id {
                if !seen_command_ids.insert(cmd_id) {
                    rejected.push(RejectedEvent {
                        event_id: event.event_id,
                        reason: RejectionReason::DuplicateCommandId,
                        message: format!("Command {} duplicated in batch", cmd_id),
                    });
                    continue;
                }
                command_ids.insert(cmd_id);
            }

            candidates.push(event);
        }

        // Reserve command_ids atomically to prevent concurrent duplicates.
        let mut duplicate_command_ids = HashSet::new();
        let mut reserved_command_ids = HashSet::new();
        for cmd_id in &command_ids {
            let result = sqlx::query(
                r#"
                INSERT INTO event_command_dedupe (tenant_id, store_id, command_id)
                VALUES ($1, $2, $3)
                ON CONFLICT DO NOTHING
                "#,
            )
            .bind(tenant_id.0)
            .bind(store_id.0)
            .bind(cmd_id)
            .execute(&mut *tx)
            .await?;

            if result.rows_affected() == 0 {
                duplicate_command_ids.insert(*cmd_id);
            } else {
                reserved_command_ids.insert(*cmd_id);
            }
        }

        let mut valid_events = Vec::new();
        for event in candidates {
            if let Some(cmd_id) = event.command_id {
                if duplicate_command_ids.contains(&cmd_id) {
                    rejected.push(RejectedEvent {
                        event_id: event.event_id,
                        reason: RejectionReason::DuplicateCommandId,
                        message: format!("Command {} already processed", cmd_id),
                    });
                    continue;
                }
            }
            valid_events.push(event);
        }

        if valid_events.is_empty() {
            let head = self.head(&tenant_id, &store_id).await?;
            return Ok(IngestReceipt {
                batch_id,
                events_accepted: 0,
                events_rejected: rejected,
                assigned_sequence_start: None,
                assigned_sequence_end: None,
                head_sequence: head,
            });
        }

        let mut assigned_sequence_start: Option<u64> = None;
        let mut assigned_sequence_end: Option<u64> = None;
        let mut events_accepted: u32 = 0;

        for event in valid_events {
            // Check base_version for optimistic concurrency control at ingest time
            if let Some(expected_version) = event.base_version {
                let current_version = Self::get_entity_version_tx(
                    &mut tx,
                    &event.tenant_id,
                    &event.store_id,
                    &event.entity_type,
                    &event.entity_id,
                )
                .await?;
                let actual_version = current_version.unwrap_or(0);

                if expected_version != actual_version {
                    // Release command_id reservation if we had one
                    if let Some(cmd_id) = event.command_id {
                        if reserved_command_ids.contains(&cmd_id) {
                            Self::release_command_id_tx(&mut tx, &tenant_id, &store_id, cmd_id)
                                .await?;
                        }
                    }

                    rejected.push(RejectedEvent {
                        event_id: event.event_id,
                        reason: RejectionReason::VersionConflict,
                        message: format!(
                            "Version conflict: expected {}, actual {}",
                            expected_version, actual_version
                        ),
                    });
                    continue;
                }
            }

            let next_seq = head.saturating_add(1);
            let sequenced = SequencedEvent::new(event, next_seq);

            // Insert; if we raced a duplicate event_id (global), reject without advancing.
            let inserted = self.insert_event_tx(&mut tx, &sequenced).await?;
            if !inserted {
                if let Some(cmd_id) = sequenced.envelope.command_id {
                    if reserved_command_ids.contains(&cmd_id) {
                        let existing_cmd_id =
                            Self::fetch_existing_command_id_tx(&mut tx, sequenced.event_id())
                                .await?;
                        if existing_cmd_id != Some(cmd_id) {
                            Self::release_command_id_tx(
                                &mut tx,
                                &tenant_id,
                                &store_id,
                                cmd_id,
                            )
                            .await?;
                        }
                    }
                }
                rejected.push(RejectedEvent {
                    event_id: sequenced.event_id(),
                    reason: RejectionReason::DuplicateEventId,
                    message: format!("Event {} already exists", sequenced.event_id()),
                });
                continue;
            }

            Self::bump_entity_version_tx(&mut tx, &sequenced).await?;
            head = next_seq;
            events_accepted += 1;
            assigned_sequence_start.get_or_insert(next_seq);
            assigned_sequence_end = Some(next_seq);
        }

        if events_accepted > 0 {
            Self::set_sequence_counter(&mut tx, &tenant_id, &store_id, head).await?;
        }

        tx.commit().await?;

        Ok(IngestReceipt {
            batch_id,
            events_accepted,
            events_rejected: rejected,
            assigned_sequence_start,
            assigned_sequence_end,
            head_sequence: head,
        })
    }

    async fn get_sync_state(&self, agent_id: &AgentId) -> Result<SyncState> {
        let row: Option<(Uuid, Uuid, i64, i64, chrono::DateTime<Utc>)> = sqlx::query_as(
            r#"
            SELECT tenant_id, store_id, last_pushed_sequence, last_pulled_sequence, last_sync_at
            FROM agent_sync_state
            WHERE agent_id = $1
            "#,
        )
        .bind(agent_id.0)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((tenant_id, store_id, pushed, pulled, last_sync)) => {
                let head = self
                    .head(
                        &TenantId::from_uuid(tenant_id),
                        &StoreId::from_uuid(store_id),
                    )
                    .await?;
                Ok(SyncState {
                    agent_id: agent_id.clone(),
                    tenant_id: TenantId::from_uuid(tenant_id),
                    store_id: StoreId::from_uuid(store_id),
                    last_pushed_sequence: pushed as u64,
                    last_pulled_sequence: pulled as u64,
                    head_sequence: head,
                    last_sync_at: last_sync,
                })
            }
            None => Ok(SyncState::new(
                agent_id.clone(),
                TenantId::from_uuid(Uuid::nil()),
                StoreId::from_uuid(Uuid::nil()),
            )),
        }
    }

    async fn update_sync_state(&self, state: &SyncState) -> Result<()> {
        if state.tenant_id.0.is_nil() || state.store_id.0.is_nil() {
            return Err(SequencerError::SchemaValidation(
                "SyncState requires tenant_id and store_id".to_string(),
            ));
        }

        sqlx::query(
            r#"
            INSERT INTO agent_sync_state (
                agent_id, tenant_id, store_id,
                last_pushed_sequence, last_pulled_sequence, last_sync_at
            ) VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (agent_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                store_id = EXCLUDED.store_id,
                last_pushed_sequence = EXCLUDED.last_pushed_sequence,
                last_pulled_sequence = EXCLUDED.last_pulled_sequence,
                last_sync_at = EXCLUDED.last_sync_at
            "#,
        )
        .bind(state.agent_id.0)
        .bind(state.tenant_id.0)
        .bind(state.store_id.0)
        .bind(state.last_pushed_sequence as i64)
        .bind(state.last_pulled_sequence as i64)
        .bind(state.last_sync_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// Additional methods for the sequencer
impl PgSequencer {
    /// Register an agent with its tenant/store
    pub async fn register_agent(
        &self,
        agent_id: &AgentId,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO agent_sync_state (agent_id, tenant_id, store_id, last_sync_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (agent_id) DO UPDATE SET
                tenant_id = $2,
                store_id = $3,
                last_sync_at = NOW()
            "#,
        )
        .bind(agent_id.0)
        .bind(tenant_id.0)
        .bind(store_id.0)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get the event store
    pub fn event_store(&self) -> &PgEventStore {
        &self.event_store
    }

    /// Initialize the database schema
    pub async fn initialize(&self) -> Result<()> {
        // Create sequence_counters table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sequence_counters (
                tenant_id UUID NOT NULL,
                store_id UUID NOT NULL,
                current_sequence BIGINT NOT NULL DEFAULT 0,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (tenant_id, store_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create events table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                event_id UUID PRIMARY KEY,
                command_id UUID,
                sequence_number BIGINT NOT NULL,
                tenant_id UUID NOT NULL,
                store_id UUID NOT NULL,
                entity_type VARCHAR(64) NOT NULL,
                entity_id VARCHAR(256) NOT NULL,
                event_type VARCHAR(64) NOT NULL,
                payload_encrypted BYTEA NOT NULL,
                payload_hash BYTEA NOT NULL,
                base_version BIGINT,
                source_agent UUID NOT NULL,
                signature BYTEA,
                created_at TIMESTAMPTZ NOT NULL,
                sequenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_events_sequence UNIQUE (tenant_id, store_id, sequence_number)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_events_tenant_store_seq ON events (tenant_id, store_id, sequence_number)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_events_entity ON events (tenant_id, store_id, entity_type, entity_id, sequence_number)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_events_command ON events (command_id) WHERE command_id IS NOT NULL",
        )
        .execute(&self.pool)
        .await?;

        // Create command dedupe table (intent-level idempotency)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS event_command_dedupe (
                tenant_id UUID NOT NULL,
                store_id UUID NOT NULL,
                command_id UUID NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (tenant_id, store_id, command_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Best-effort backfill from existing events (safe for dev usage).
        sqlx::query(
            r#"
            INSERT INTO event_command_dedupe (tenant_id, store_id, command_id)
            SELECT tenant_id, store_id, command_id
            FROM events
            WHERE command_id IS NOT NULL
            ON CONFLICT DO NOTHING
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create agent_sync_state table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS agent_sync_state (
                agent_id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                store_id UUID NOT NULL,
                last_pushed_sequence BIGINT NOT NULL DEFAULT 0,
                last_pulled_sequence BIGINT NOT NULL DEFAULT 0,
                last_sync_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                metadata JSONB
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create entity_versions table for tracking entity versions (used by commitment engine)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS entity_versions (
                tenant_id UUID NOT NULL,
                store_id UUID NOT NULL,
                entity_type VARCHAR(64) NOT NULL,
                entity_id VARCHAR(256) NOT NULL,
                version BIGINT NOT NULL DEFAULT 0,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (tenant_id, store_id, entity_type, entity_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
