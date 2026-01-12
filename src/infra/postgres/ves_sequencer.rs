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

#[derive(sqlx::FromRow)]
struct ExistingVesEvent {
    tenant_id: Uuid,
    store_id: Uuid,
}

/// Row data for an existing sequencer receipt
#[derive(sqlx::FromRow)]
struct ExistingReceiptRow {
    sequencer_id: Uuid,
    sequence_number: i64,
    sequenced_at: chrono::DateTime<Utc>,
    receipt_hash: Vec<u8>,
    sequencer_signature: Option<Vec<u8>>,
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
    /// Version conflict (optimistic concurrency at sequencer)
    VersionConflict { expected: u64, actual: u64 },
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
            Self::VersionConflict { expected, actual } => {
                write!(f, "version_conflict: expected {}, actual {}", expected, actual)
            }
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
    pub sequencer_signature: Option<Signature64>,
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
            INSERT INTO ves_sequence_counters (tenant_id, store_id, current_sequence, updated_at)
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
            FROM ves_sequence_counters
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
            UPDATE ves_sequence_counters
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
            "SELECT current_sequence FROM ves_sequence_counters WHERE tenant_id = $1 AND store_id = $2",
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.0 as u64).unwrap_or(0))
    }

    async fn get_existing_event(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
    ) -> Result<Option<ExistingVesEvent>> {
        let row: Option<ExistingVesEvent> = sqlx::query_as(
            "SELECT tenant_id, store_id FROM ves_events WHERE event_id = $1",
        )
        .bind(event_id)
        .fetch_optional(&mut **tx)
        .await?;

        Ok(row)
    }

    async fn get_existing_receipt(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
    ) -> Result<Option<VesSequencerReceipt>> {
        let row: Option<ExistingReceiptRow> = sqlx::query_as(
            r#"
            SELECT sequencer_id, sequence_number, sequenced_at, receipt_hash, sequencer_signature
            FROM ves_sequencer_receipts
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&mut **tx)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let receipt_hash: Hash256 = row
            .receipt_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid receipt_hash".into()))?;

        let sequencer_signature = match row.sequencer_signature {
            Some(bytes) => {
                let sig: Signature64 = bytes
                    .try_into()
                    .map_err(|_| SequencerError::Internal("invalid sequencer_signature".into()))?;
                if sig.iter().all(|b| *b == 0) {
                    None
                } else {
                    Some(sig)
                }
            }
            None => None,
        };
        let signature_alg = if sequencer_signature.is_some() {
            "ed25519".to_string()
        } else {
            "none".to_string()
        };

        Ok(Some(VesSequencerReceipt {
            sequencer_id: row.sequencer_id,
            event_id,
            sequence_number: row.sequence_number as u64,
            sequenced_at: row.sequenced_at,
            receipt_hash,
            signature_alg,
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

        let entity_type = event.entity_type.as_str();
        if entity_type.is_empty() || entity_type.len() > 64 {
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason: VesRejectionReason::SchemaValidation("entity_type".to_string()),
                message: "entity_type must be 1-64 characters".to_string(),
            });
        }

        if event.entity_id.is_empty() || event.entity_id.len() > 256 {
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason: VesRejectionReason::SchemaValidation("entity_id".to_string()),
                message: "entity_id must be 1-256 characters".to_string(),
            });
        }

        let event_type = event.event_type.as_str();
        if event_type.is_empty() || event_type.len() > 64 {
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason: VesRejectionReason::SchemaValidation("event_type".to_string()),
                message: "event_type must be 1-64 characters".to_string(),
            });
        }

        if chrono::DateTime::parse_from_rfc3339(event.created_at_rfc3339()).is_err() {
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason: VesRejectionReason::SchemaValidation("created_at".to_string()),
                message: "created_at must be RFC3339".to_string(),
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
            payload_plain_hash = %hex::encode(event.payload_plain_hash),
            payload_cipher_hash = %hex::encode(event.payload_cipher_hash),
            computed_signing_hash = %hex::encode(signing_hash),
            agent_signature = %hex::encode(event.agent_signature),
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
            .map_err(|e| {
                SequencerError::SchemaValidation(format!("created_at must be RFC3339: {}", e))
            })?;
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
        .bind(
            receipt
                .sequencer_signature
                .as_ref()
                .map(|sig| sig.as_slice()),
        )
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    async fn fetch_existing_command_id_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let row: Option<(Option<Uuid>,)> =
            sqlx::query_as("SELECT command_id FROM ves_events WHERE event_id = $1")
                .bind(event_id)
                .fetch_optional(&mut **tx)
                .await?;
        Ok(row.and_then(|(cmd_id,)| cmd_id))
    }

    async fn release_command_id_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        command_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM ves_command_dedupe
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

    /// Bump entity version within a transaction
    async fn bump_entity_version_tx(
        tx: &mut Transaction<'_, Postgres>,
        event: &SequencedVesEvent,
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
        let (signature_alg, sequencer_signature) = if let Some(ref key) = self.sequencer_signing_key
        {
            ("ed25519".to_string(), Some(key.sign(&receipt_hash)))
        } else {
            ("none".to_string(), None)
        };

        VesSequencerReceipt {
            sequencer_id: self.sequencer_id,
            event_id: event.event_id(),
            sequence_number: event.sequence_number(),
            sequenced_at: event.envelope.sequenced_at.unwrap_or_else(Utc::now),
            receipt_hash,
            signature_alg,
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

        let mut pending = Vec::new();
        let mut seen_event_ids = HashSet::new();

        // Idempotency: return stored receipts for already-seen events.
        for event in events {
            if !seen_event_ids.insert(event.event_id) {
                rejected.push(VesRejectedEvent {
                    event_id: event.event_id,
                    reason: VesRejectionReason::DuplicateEventId,
                    message: format!("Event {} duplicated in batch", event.event_id),
                });
                continue;
            }
            if let Some(existing) = self.get_existing_event(&mut tx, event.event_id).await? {
                if existing.tenant_id != tenant_id.0 || existing.store_id != store_id.0 {
                    rejected.push(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::DuplicateEventId,
                        message: "Event ID already exists".to_string(),
                    });
                    continue;
                }

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

            pending.push(event);
        }

        let mut candidates = Vec::new();
        let mut command_ids = HashSet::new();
        let mut seen_command_ids = HashSet::new();

        for event in pending {
            // Validate signature and hashes
            if let Some(rejection) = self.validate_event(&event).await {
                rejected.push(rejection);
                continue;
            }

            if let Some(cmd_id) = event.command_id {
                if !seen_command_ids.insert(cmd_id) {
                    rejected.push(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::DuplicateCommandId,
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
                INSERT INTO ves_command_dedupe (tenant_id, store_id, command_id)
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
                    rejected.push(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::DuplicateCommandId,
                        message: format!("Command {} already processed", cmd_id),
                    });
                    continue;
                }
            }

            valid_events.push(event);
        }

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
                            self.release_command_id_tx(&mut tx, &tenant_id, &store_id, cmd_id)
                                .await?;
                        }
                    }

                    rejected.push(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::VersionConflict {
                            expected: expected_version,
                            actual: actual_version,
                        },
                        message: format!(
                            "Version conflict: expected {}, actual {}",
                            expected_version, actual_version
                        ),
                    });
                    continue;
                }
            }

            let next_seq = head.saturating_add(1);
            let sequenced = SequencedVesEvent::new(event, next_seq);

            let inserted = self.store_event_tx(&mut tx, &sequenced).await?;
            if !inserted {
                if let Some(cmd_id) = sequenced.envelope.command_id {
                    if reserved_command_ids.contains(&cmd_id) {
                        let existing_cmd_id =
                            self.fetch_existing_command_id_tx(&mut tx, sequenced.event_id())
                                .await?;
                        if existing_cmd_id != Some(cmd_id) {
                            self.release_command_id_tx(&mut tx, &tenant_id, &store_id, cmd_id)
                                .await?;
                        }
                    }
                }
                rejected.push(VesRejectedEvent {
                    event_id: sequenced.event_id(),
                    reason: VesRejectionReason::DuplicateEventId,
                    message: format!("Event {} already exists", sequenced.event_id()),
                });
                continue;
            }

            let receipt = self.generate_receipt(&sequenced);
            self.store_receipt_tx(&mut tx, &receipt).await?;

            // Bump entity version for state root consistency
            Self::bump_entity_version_tx(&mut tx, &sequenced).await?;

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

        // Command dedupe table for VES events (intent-level idempotency)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ves_command_dedupe (
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

        // Best-effort backfill from existing VES events.
        sqlx::query(
            r#"
            INSERT INTO ves_command_dedupe (tenant_id, store_id, command_id)
            SELECT tenant_id, store_id, command_id
            FROM ves_events
            WHERE command_id IS NOT NULL
            ON CONFLICT DO NOTHING
            "#,
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
