//! VES v1.0 Compliant Sequencer
//!
//! Provides event sequencing with:
//! - Agent signature verification per VES v1.0 Section 8
//! - Payload hash validation
//! - Idempotent event ingestion
//! - Sequencer receipts

use chrono::Utc;
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Transaction};
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{AgentKeyError, AgentKeyLookup, AgentKeyRegistry};
use crate::crypto::{compute_receipt_hash, AgentSigningKey, Hash256, Signature64};
use crate::domain::{
    AgentId, AgentKeyId, EntityType, EventType, PayloadKind, SequencedVesEvent, StoreId, TenantId,
    VesEventEnvelope, VES_VERSION,
};
use crate::infra::{Result, SequencerError};

/// Database row for VES events (needed because SQLx tuples max at 16 elements)
#[derive(sqlx::FromRow)]
struct VesEventRow {
    event_id: Uuid,
    command_id: Option<Uuid>,
    ves_version: i32,
    tenant_id: Uuid,
    store_id: Uuid,
    source_agent_id: Uuid,
    agent_key_id: i32,
    entity_type: String,
    entity_id: String,
    event_type: String,
    created_at: chrono::DateTime<Utc>,
    created_at_str: Option<String>,
    sequenced_at: chrono::DateTime<Utc>,
    payload_kind: i32,
    payload: Option<serde_json::Value>,
    payload_encrypted: Option<serde_json::Value>,
    payload_plain_hash: Vec<u8>,
    payload_cipher_hash: Vec<u8>,
    agent_signature: Vec<u8>,
    sequence_number: i64,
    base_version: Option<i64>,
}

/// Rejection reason for VES events
#[derive(Debug, Clone)]
pub enum VesRejectionReason {
    /// Event ID already exists
    DuplicateEventId,
    /// Command ID already processed
    DuplicateCommandId,
    /// Payload hash mismatch
    InvalidPayloadHash,
    /// Cipher hash mismatch (for encrypted events)
    InvalidCipherHash,
    /// Agent signature verification failed
    InvalidSignature,
    /// Agent key not found or revoked
    AgentKeyInvalid(String),
    /// VES version not supported
    UnsupportedVersion,
    /// Schema validation failed
    SchemaValidation(String),
}

impl std::fmt::Display for VesRejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateEventId => write!(f, "duplicate_event_id"),
            Self::DuplicateCommandId => write!(f, "duplicate_command_id"),
            Self::InvalidPayloadHash => write!(f, "invalid_payload_hash"),
            Self::InvalidCipherHash => write!(f, "invalid_cipher_hash"),
            Self::InvalidSignature => write!(f, "invalid_signature"),
            Self::AgentKeyInvalid(msg) => write!(f, "agent_key_invalid: {}", msg),
            Self::UnsupportedVersion => write!(f, "unsupported_version"),
            Self::SchemaValidation(msg) => write!(f, "schema_validation: {}", msg),
        }
    }
}

/// Rejected VES event
#[derive(Debug, Clone)]
pub struct VesRejectedEvent {
    pub event_id: Uuid,
    pub reason: VesRejectionReason,
    pub message: String,
}

/// Sequencer receipt per VES v1.0 Section 6.4
#[derive(Debug, Clone)]
pub struct VesSequencerReceipt {
    /// Sequencer identifier
    pub sequencer_id: Uuid,
    /// Event ID
    pub event_id: Uuid,
    /// Assigned sequence number
    pub sequence_number: u64,
    /// When the sequencer accepted the event
    pub sequenced_at: chrono::DateTime<Utc>,
    /// Hash of the receipt per VES v1.0
    pub receipt_hash: Hash256,
    /// Signature algorithm
    pub signature_alg: String,
    /// Sequencer signature over receipt_hash
    pub sequencer_signature: Signature64,
}

/// VES ingest receipt
#[derive(Debug, Clone)]
pub struct VesIngestReceipt {
    pub batch_id: Uuid,
    pub events_accepted: u32,
    pub events_rejected: Vec<VesRejectedEvent>,
    pub assigned_sequence_start: Option<u64>,
    pub assigned_sequence_end: Option<u64>,
    pub head_sequence: u64,
    /// Individual receipts for each accepted event
    pub receipts: Vec<VesSequencerReceipt>,
}

/// VES v1.0 compliant sequencer with signature validation
pub struct VesSequencer<R: AgentKeyRegistry> {
    pool: PgPool,
    key_registry: Arc<R>,
    sequencer_id: Uuid,
    /// Optional sequencer signing key for receipts
    sequencer_signing_key: Option<AgentSigningKey>,
}

impl<R: AgentKeyRegistry> VesSequencer<R> {
    /// Create a new VES sequencer
    pub fn new(pool: PgPool, key_registry: Arc<R>) -> Self {
        Self {
            pool,
            key_registry,
            sequencer_id: Uuid::new_v4(),
            sequencer_signing_key: None,
        }
    }

    /// Create with a specific sequencer ID
    pub fn with_sequencer_id(mut self, id: Uuid) -> Self {
        self.sequencer_id = id;
        self
    }

    /// Set the sequencer signing key for receipts
    pub fn with_signing_key(mut self, key: AgentSigningKey) -> Self {
        self.sequencer_signing_key = Some(key);
        self
    }

    async fn lock_sequence_counter(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<u64> {
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
        &self,
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

    /// Get current head sequence
    pub async fn head(&self, tenant_id: &TenantId, store_id: &StoreId) -> Result<u64> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT current_sequence FROM sequence_counters WHERE tenant_id = $1 AND store_id = $2",
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.0 as u64).unwrap_or(0))
    }

    async fn get_existing_sequence(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
    ) -> Result<Option<u64>> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT sequence_number FROM ves_events WHERE event_id = $1")
                .bind(event_id)
                .fetch_optional(&mut **tx)
                .await?;

        Ok(row.map(|(seq,)| seq as u64))
    }

    async fn get_existing_receipt(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
    ) -> Result<Option<VesSequencerReceipt>> {
        let row: Option<(Uuid, i64, chrono::DateTime<Utc>, Vec<u8>, Option<Vec<u8>>)> =
            sqlx::query_as(
                r#"
                SELECT sequencer_id, sequence_number, sequenced_at, receipt_hash, sequencer_signature
                FROM ves_sequencer_receipts
                WHERE event_id = $1
                "#,
            )
            .bind(event_id)
            .fetch_optional(&mut **tx)
            .await?;

        let Some((sequencer_id, sequence_number, sequenced_at, receipt_hash, sequencer_signature)) =
            row
        else {
            return Ok(None);
        };

        let receipt_hash: Hash256 = receipt_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid receipt_hash".into()))?;

        let sequencer_signature: Signature64 = sequencer_signature
            .unwrap_or_else(|| vec![0u8; 64])
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid sequencer_signature".into()))?;

        Ok(Some(VesSequencerReceipt {
            sequencer_id,
            event_id,
            sequence_number: sequence_number as u64,
            sequenced_at,
            receipt_hash,
            signature_alg: "ed25519".to_string(),
            sequencer_signature,
        }))
    }

    /// Validate an event per VES v1.0 Section 9
    async fn validate_event(&self, event: &VesEventEnvelope) -> Option<VesRejectedEvent> {
        // 1. Validate VES version
        if event.ves_version != VES_VERSION {
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason: VesRejectionReason::UnsupportedVersion,
                message: format!(
                    "Expected VES version {}, got {}",
                    VES_VERSION, event.ves_version
                ),
            });
        }

        // 2. Validate payload hash
        if !event.verify_payload_hash() {
            let reason = if event.is_plaintext() {
                VesRejectionReason::InvalidPayloadHash
            } else {
                VesRejectionReason::InvalidCipherHash
            };
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason,
                message: "Payload hash verification failed".to_string(),
            });
        }

        // 3. Lookup agent key
        let lookup =
            AgentKeyLookup::new(&event.tenant_id, &event.source_agent_id, event.agent_key_id);

        // Per VES v1.0 Section 9.2: evaluate against sequenced_at time
        let validation_time = Utc::now();

        let verifying_key = match self
            .key_registry
            .get_verifying_key_at(&lookup, validation_time)
            .await
        {
            Ok(key) => key,
            Err(e) => {
                let message = match &e {
                    AgentKeyError::KeyNotFound { .. } => "Agent key not found".to_string(),
                    AgentKeyError::KeyRevoked => "Agent key has been revoked".to_string(),
                    AgentKeyError::KeyExpired => "Agent key has expired".to_string(),
                    AgentKeyError::KeyNotYetValid => "Agent key is not yet valid".to_string(),
                    _ => e.to_string(),
                };
                return Some(VesRejectedEvent {
                    event_id: event.event_id,
                    reason: VesRejectionReason::AgentKeyInvalid(message.clone()),
                    message,
                });
            }
        };

        // 4. Verify agent signature
        // Debug: Log the signing hash and signature for debugging
        let signing_hash = event.compute_signing_hash();
        tracing::debug!(
            event_id = %event.event_id,
            tenant_id = %event.tenant_id,
            store_id = %event.store_id,
            source_agent_id = %event.source_agent_id,
            agent_key_id = %event.agent_key_id,
            entity_type = %event.entity_type,
            entity_id = %event.entity_id,
            event_type = %event.event_type,
            created_at = %event.created_at,
            payload_kind = ?event.payload_kind,
            payload_plain_hash = %hex::encode(&event.payload_plain_hash),
            payload_cipher_hash = %hex::encode(&event.payload_cipher_hash),
            computed_signing_hash = %hex::encode(&signing_hash),
            agent_signature = %hex::encode(&event.agent_signature),
            "VES signature verification"
        );

        if let Err(e) = event.verify_signature(&verifying_key) {
            tracing::warn!(
                event_id = %event.event_id,
                error = ?e,
                "VES signature verification failed"
            );
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason: VesRejectionReason::InvalidSignature,
                message: format!("Agent signature verification failed: {:?}", e),
            });
        }

        None
    }

    async fn store_event_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event: &SequencedVesEvent,
    ) -> Result<bool> {
        let env = &event.envelope;

        // Parse created_at from string to DateTime (for database storage)
        let created_at_dt = chrono::DateTime::parse_from_rfc3339(&env.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let sequenced_at_dt = env.sequenced_at.unwrap_or_else(Utc::now);

        let event_signing_hash = event.compute_signing_hash();

        // Serialize payload or encrypted payload
        let (payload_json, encrypted_json) = if env.is_plaintext() {
            (
                env.payload
                    .as_ref()
                    .map(|p| serde_json::to_value(p).unwrap_or_default()),
                None::<serde_json::Value>,
            )
        } else {
            (
                None,
                env.payload_encrypted
                    .as_ref()
                    .map(|p| serde_json::to_value(p).unwrap_or_default()),
            )
        };

        let result = sqlx::query(
            r#"
            INSERT INTO ves_events (
                event_id, command_id, ves_version,
                tenant_id, store_id,
                source_agent_id, agent_key_id,
                entity_type, entity_id, event_type,
                created_at, created_at_str, sequenced_at,
                payload_kind, payload, payload_encrypted,
                payload_plain_hash, payload_cipher_hash, event_signing_hash,
                agent_signature,
                sequence_number, base_version
            ) VALUES (
                $1, $2, $3,
                $4, $5,
                $6, $7,
                $8, $9, $10,
                $11, $12, $13,
                $14, $15, $16,
                $17, $18, $19,
                $20,
                $21, $22
            )
            ON CONFLICT (event_id) DO NOTHING
            "#,
        )
        .bind(env.event_id)
        .bind(env.command_id)
        .bind(env.ves_version as i32)
        .bind(env.tenant_id.0)
        .bind(env.store_id.0)
        .bind(env.source_agent_id.0)
        .bind(env.agent_key_id.as_u32() as i32)
        .bind(env.entity_type.as_str())
        .bind(&env.entity_id)
        .bind(env.event_type.as_str())
        .bind(created_at_dt)
        .bind(&env.created_at)
        .bind(sequenced_at_dt)
        .bind(env.payload_kind.as_u32() as i32)
        .bind(payload_json)
        .bind(encrypted_json)
        .bind(env.payload_plain_hash.as_slice())
        .bind(env.payload_cipher_hash.as_slice())
        .bind(event_signing_hash.as_slice())
        .bind(env.agent_signature.as_slice())
        .bind(event.sequence_number() as i64)
        .bind(env.base_version.map(|v| v as i64))
        .execute(&mut **tx)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    async fn store_receipt_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        receipt: &VesSequencerReceipt,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO ves_sequencer_receipts (
                event_id, sequencer_id, sequence_number, sequenced_at, receipt_hash, sequencer_signature
            )
            SELECT $1, $2, $3, $4, $5, $6
            WHERE NOT EXISTS (
                SELECT 1 FROM ves_sequencer_receipts WHERE event_id = $1
            )
            "#,
        )
        .bind(receipt.event_id)
        .bind(receipt.sequencer_id)
        .bind(receipt.sequence_number as i64)
        .bind(receipt.sequenced_at)
        .bind(receipt.receipt_hash.as_slice())
        .bind(receipt.sequencer_signature.as_slice())
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    /// Generate a sequencer receipt for an event
    fn generate_receipt(&self, event: &SequencedVesEvent) -> VesSequencerReceipt {
        let event_signing_hash = event.compute_signing_hash();

        // Compute receipt hash per VES v1.0 Section 8.4
        let receipt_hash = compute_receipt_hash(
            &event.tenant_id().0,
            &event.store_id().0,
            &event.event_id(),
            event.sequence_number(),
            &event_signing_hash,
        );

        // Sign the receipt if we have a signing key
        let sequencer_signature = if let Some(ref key) = self.sequencer_signing_key {
            key.sign(&receipt_hash)
        } else {
            [0u8; 64] // Zero signature if no key
        };

        VesSequencerReceipt {
            sequencer_id: self.sequencer_id,
            event_id: event.event_id(),
            sequence_number: event.sequence_number(),
            sequenced_at: event.envelope.sequenced_at.unwrap_or_else(Utc::now),
            receipt_hash,
            signature_alg: "ed25519".to_string(),
            sequencer_signature,
        }
    }

    /// Ingest a batch of VES events
    pub async fn ingest(&self, events: Vec<VesEventEnvelope>) -> Result<VesIngestReceipt> {
        if events.is_empty() {
            return Ok(VesIngestReceipt {
                batch_id: Uuid::new_v4(),
                events_accepted: 0,
                events_rejected: Vec::new(),
                assigned_sequence_start: None,
                assigned_sequence_end: None,
                head_sequence: 0,
                receipts: Vec::new(),
            });
        }

        let batch_id = Uuid::new_v4();
        let tenant_id = events[0].tenant_id.clone();
        let store_id = events[0].store_id.clone();

        // Enforce single-tenant/store batches.
        for e in &events {
            if e.tenant_id.0 != tenant_id.0 || e.store_id.0 != store_id.0 {
                return Err(SequencerError::SchemaValidation(
                    "All VES events in a batch must share the same tenant_id and store_id"
                        .to_string(),
                ));
            }
        }

        let mut tx = self.pool.begin().await?;
        let mut head = self
            .lock_sequence_counter(&mut tx, &tenant_id, &store_id)
            .await?;

        let mut rejected = Vec::new();
        let mut receipts = Vec::new();
        let mut assigned_sequence_start: Option<u64> = None;
        let mut assigned_sequence_end: Option<u64> = None;
        let mut new_events_accepted: u32 = 0;

        // Command dedupe is intent-level: allow multiple events per command within this batch,
        // but reject if the command_id already exists from a prior ingestion.
        let command_ids: Vec<Uuid> = events.iter().filter_map(|e| e.command_id).collect();
        let existing_command_ids: HashSet<Uuid> = if command_ids.is_empty() {
            HashSet::new()
        } else {
            let rows: Vec<(Uuid,)> =
                sqlx::query_as(r#"SELECT command_id FROM ves_events WHERE command_id = ANY($1)"#)
                    .bind(&command_ids)
                    .fetch_all(&mut *tx)
                    .await?;
            rows.into_iter().map(|(id,)| id).collect()
        };

        // Validate each event
        for event in events {
            // Idempotency: if event exists, return the stored receipt.
            if let Some(_seq) = self.get_existing_sequence(&mut tx, event.event_id).await? {
                if let Some(receipt) = self.get_existing_receipt(&mut tx, event.event_id).await? {
                    receipts.push(receipt);
                    continue;
                }

                rejected.push(VesRejectedEvent {
                    event_id: event.event_id,
                    reason: VesRejectionReason::DuplicateEventId,
                    message: "Event already exists but receipt not found".to_string(),
                });
                continue;
            }

            // Check for duplicate command_id
            if let Some(cmd_id) = event.command_id {
                if existing_command_ids.contains(&cmd_id) {
                    rejected.push(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::DuplicateCommandId,
                        message: format!("Command {} already processed", cmd_id),
                    });
                    continue;
                }
            }

            // Validate signature and hashes
            if let Some(rejection) = self.validate_event(&event).await {
                rejected.push(rejection);
                continue;
            }

            let next_seq = head.saturating_add(1);
            let sequenced = SequencedVesEvent::new(event, next_seq);

            let inserted = self.store_event_tx(&mut tx, &sequenced).await?;
            if !inserted {
                rejected.push(VesRejectedEvent {
                    event_id: sequenced.event_id(),
                    reason: VesRejectionReason::DuplicateEventId,
                    message: format!("Event {} already exists", sequenced.event_id()),
                });
                continue;
            }

            let receipt = self.generate_receipt(&sequenced);
            self.store_receipt_tx(&mut tx, &receipt).await?;

            head = next_seq;
            new_events_accepted += 1;
            assigned_sequence_start.get_or_insert(next_seq);
            assigned_sequence_end = Some(next_seq);
            receipts.push(receipt);
        }

        if new_events_accepted > 0 {
            self.set_sequence_counter(&mut tx, &tenant_id, &store_id, head)
                .await?;
        }

        tx.commit().await?;

        Ok(VesIngestReceipt {
            batch_id,
            events_accepted: receipts.len() as u32,
            events_rejected: rejected,
            assigned_sequence_start,
            assigned_sequence_end,
            head_sequence: head,
            receipts,
        })
    }

    /// Initialize VES events table
    pub async fn initialize(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ves_events (
                event_id UUID PRIMARY KEY,
                command_id UUID,
                ves_version INTEGER NOT NULL DEFAULT 1,
                tenant_id UUID NOT NULL,
                store_id UUID NOT NULL,
                source_agent_id UUID NOT NULL,
                agent_key_id INTEGER NOT NULL,
                entity_type VARCHAR(64) NOT NULL,
                entity_id VARCHAR(256) NOT NULL,
                event_type VARCHAR(64) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                created_at_str TEXT NOT NULL,
                sequenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                payload_kind INTEGER NOT NULL DEFAULT 0,
                payload JSONB,
                payload_encrypted JSONB,
                payload_plain_hash BYTEA NOT NULL,
                payload_cipher_hash BYTEA NOT NULL,
                event_signing_hash BYTEA NOT NULL,
                agent_signature BYTEA NOT NULL,
                sequence_number BIGINT NOT NULL,
                base_version BIGINT,
                CONSTRAINT uq_ves_events_sequence UNIQUE (tenant_id, store_id, sequence_number)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Add columns if the table pre-dates VES commitment/proof support.
        sqlx::query("ALTER TABLE ves_events ADD COLUMN IF NOT EXISTS created_at_str TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE ves_events ADD COLUMN IF NOT EXISTS event_signing_hash BYTEA")
            .execute(&self.pool)
            .await?;

        // Create indexes
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_ves_events_tenant_store_seq ON ves_events (tenant_id, store_id, sequence_number)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_ves_events_entity ON ves_events (tenant_id, store_id, entity_type, entity_id)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_ves_events_command ON ves_events (command_id) WHERE command_id IS NOT NULL",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_ves_events_agent ON ves_events (tenant_id, source_agent_id)",
        )
        .execute(&self.pool)
        .await?;

        // Receipts table (one receipt per event).
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ves_sequencer_receipts (
                event_id UUID PRIMARY KEY REFERENCES ves_events(event_id),
                sequencer_id UUID NOT NULL,
                sequence_number BIGINT NOT NULL,
                sequenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                receipt_hash BYTEA NOT NULL,
                sequencer_signature BYTEA
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_ves_receipts_sequenced_at ON ves_sequencer_receipts (sequenced_at)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get events by sequence range
    pub async fn get_events(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        after_sequence: u64,
        limit: u32,
    ) -> Result<Vec<SequencedVesEvent>> {
        let rows: Vec<VesEventRow> = sqlx::query_as(
            r#"
            SELECT
                event_id, command_id, ves_version,
                tenant_id, store_id,
                source_agent_id, agent_key_id,
                entity_type, entity_id, event_type,
                created_at, created_at_str, sequenced_at,
                payload_kind, payload, payload_encrypted,
                payload_plain_hash, payload_cipher_hash,
                agent_signature,
                sequence_number, base_version
            FROM ves_events
            WHERE tenant_id = $1 AND store_id = $2 AND sequence_number > $3
            ORDER BY sequence_number ASC
            LIMIT $4
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(after_sequence as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut events = Vec::with_capacity(rows.len());

        for row in rows {
            let plain_hash: Hash256 = row
                .payload_plain_hash
                .try_into()
                .map_err(|_| SequencerError::Internal("invalid plain hash".into()))?;
            let cipher_hash: Hash256 = row
                .payload_cipher_hash
                .try_into()
                .map_err(|_| SequencerError::Internal("invalid cipher hash".into()))?;
            let signature: Signature64 = row
                .agent_signature
                .try_into()
                .map_err(|_| SequencerError::Internal("invalid signature".into()))?;

            let payload_kind =
                PayloadKind::from_u32(row.payload_kind as u32).unwrap_or(PayloadKind::Plaintext);

            let payload_encrypted = if let Some(enc_json) = row.payload_encrypted {
                serde_json::from_value(enc_json).ok()
            } else {
                None
            };

            let envelope = VesEventEnvelope {
                ves_version: row.ves_version as u32,
                event_id: row.event_id,
                tenant_id: TenantId::from_uuid(row.tenant_id),
                store_id: StoreId::from_uuid(row.store_id),
                source_agent_id: AgentId::from_uuid(row.source_agent_id),
                agent_key_id: AgentKeyId::new(row.agent_key_id as u32),
                entity_type: EntityType::new(row.entity_type),
                entity_id: row.entity_id,
                event_type: EventType::new(row.event_type),
                created_at: row
                    .created_at_str
                    .unwrap_or_else(|| row.created_at.to_rfc3339()),
                payload_kind,
                payload: row.payload,
                payload_encrypted,
                payload_plain_hash: plain_hash,
                payload_cipher_hash: cipher_hash,
                agent_signature: signature,
                sequence_number: Some(row.sequence_number as u64),
                sequenced_at: Some(row.sequenced_at),
                command_id: row.command_id,
                base_version: row.base_version.map(|v| v as u64),
            };

            events.push(SequencedVesEvent { envelope });
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    // Integration tests would require a PostgreSQL instance
    // See tests/ves_sequencer_integration_test.rs
}
