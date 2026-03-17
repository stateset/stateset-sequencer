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
use crate::crypto::{
    base64_url_decode, base64_url_encode, compute_receipt_hash, AgentSigningKey, Hash256,
    PayloadEncrypted, Signature64, NONCE_SIZE, TAG_SIZE,
};
use crate::domain::{
    AgentId, AgentKeyId, EntityType, EventType, PayloadKind, SequencedVesEvent, StoreId, TenantId,
    VesEventEnvelope, VES_VERSION, ZERO_HASH,
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

/// Row data for an existing sequencer receipt
#[derive(sqlx::FromRow)]
struct ExistingReceiptRow {
    sequencer_id: Uuid,
    sequence_number: i64,
    sequenced_at: chrono::DateTime<Utc>,
    receipt_hash: Vec<u8>,
    sequencer_signature: Option<Vec<u8>>,
    sequencer_key_version: i32,
}

enum ReplayLookup {
    Missing,
    DifferentContents,
    ExactReplayMissingReceipt,
    ExactReplay(VesSequencerReceipt),
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
                write!(
                    f,
                    "version_conflict: expected {}, actual {}",
                    expected, actual
                )
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

/// Sequencer receipt per VES v1.0 Section 10.3
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
    /// Key rotation index for the signing key (Section 10.5)
    pub sequencer_key_version: u32,
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
    /// Key rotation index for the signing key (monotonic)
    sequencer_key_version: u32,
    /// Enforce strict formatting for VES hex/base64url fields
    strict_format_validation: bool,
}

impl<R: AgentKeyRegistry> VesSequencer<R> {
    const MAX_SEQUENCE: u64 = i64::MAX as u64;

    fn decode_sequence(value: i64) -> Result<u64> {
        u64::try_from(value).map_err(|_| SequencerError::InvariantViolation {
            invariant: "sequence_counter".to_string(),
            message: "sequence counter must be a non-negative BIGINT".to_string(),
        })
    }

    fn encode_sequence(value: u64) -> Result<i64> {
        i64::try_from(value).map_err(|_| SequencerError::InvariantViolation {
            invariant: "sequence_counter".to_string(),
            message: format!("sequence counter must be <= {}", Self::MAX_SEQUENCE),
        })
    }

    fn ensure_sequence_capacity(head: u64, count: usize) -> Result<()> {
        if head > Self::MAX_SEQUENCE {
            return Err(SequencerError::InvariantViolation {
                invariant: "sequence_counter".to_string(),
                message: format!("sequence counter must be <= {}", Self::MAX_SEQUENCE),
            });
        }
        if count == 0 {
            return Ok(());
        }
        let count_u64 = u64::try_from(count).map_err(|_| SequencerError::InvariantViolation {
            invariant: "sequence_counter".to_string(),
            message: "sequence counter increment overflow".to_string(),
        })?;
        let last =
            head.checked_add(count_u64)
                .ok_or_else(|| SequencerError::InvariantViolation {
                    invariant: "sequence_counter".to_string(),
                    message: "sequence counter overflow".to_string(),
                })?;
        if last > Self::MAX_SEQUENCE {
            return Err(SequencerError::InvariantViolation {
                invariant: "sequence_counter".to_string(),
                message: format!("sequence counter must be <= {}", Self::MAX_SEQUENCE),
            });
        }
        Ok(())
    }
    fn decode_event_row(row: VesEventRow) -> Result<SequencedVesEvent> {
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

        let base_version = row
            .base_version
            .map(|v| {
                u64::try_from(v).map_err(|_| SequencerError::InvariantViolation {
                    invariant: "entity_version".to_string(),
                    message: "entity version must be non-negative".to_string(),
                })
            })
            .transpose()?;

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
            sequence_number: Some(Self::decode_sequence(row.sequence_number)?),
            sequenced_at: Some(row.sequenced_at),
            command_id: row.command_id,
            base_version,
        };

        Ok(SequencedVesEvent { envelope })
    }
    fn strict_format_from_env() -> bool {
        std::env::var("VES_STRICT_FORMAT_VALIDATION")
            .ok()
            .map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "" | "0" | "false" | "off"
                )
            })
            .unwrap_or(false)
    }

    fn normalize_range_start(start: u64) -> u64 {
        if start == 0 {
            1
        } else {
            start
        }
    }

    fn ensure_sequence_contiguity(start: u64, events: &[SequencedVesEvent]) -> Result<u64> {
        let mut expected = start;
        let mut last = 0u64;

        for event in events {
            let sequence = event.sequence_number();
            if sequence != expected {
                return Err(SequencerError::InvariantViolation {
                    invariant: "sequence_range".to_string(),
                    message: format!(
                        "non-contiguous event sequence: expected {expected}, got {sequence}"
                    ),
                });
            }
            expected =
                sequence
                    .checked_add(1)
                    .ok_or_else(|| SequencerError::InvariantViolation {
                        invariant: "sequence_range".to_string(),
                        message: "sequence number overflow while validating range".to_string(),
                    })?;
            last = sequence;
        }

        Ok(last)
    }

    async fn head_sequence(&self, tenant_id: &TenantId, store_id: &StoreId) -> Result<u64> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COALESCE(MAX(sequence_number), 0)
            FROM ves_events
            WHERE tenant_id = $1 AND store_id = $2
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_one(&self.pool)
        .await?;

        Self::decode_sequence(row.0)
    }

    /// Create a new VES sequencer
    pub fn new(pool: PgPool, key_registry: Arc<R>) -> Self {
        Self {
            pool,
            key_registry,
            sequencer_id: Uuid::new_v4(),
            sequencer_signing_key: None,
            sequencer_key_version: 0,
            strict_format_validation: Self::strict_format_from_env(),
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

    /// Set the signing key version (monotonic rotation index, Section 10.5)
    pub fn with_signing_key_version(mut self, version: u32) -> Self {
        self.sequencer_key_version = version;
        self
    }

    /// Enable or disable strict format validation for VES payload fields
    pub fn with_strict_format_validation(mut self, enabled: bool) -> Self {
        self.strict_format_validation = enabled;
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

        Self::decode_sequence(row.0)
    }

    async fn set_sequence_counter(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        head: u64,
    ) -> Result<()> {
        let head = Self::encode_sequence(head)?;
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
        .bind(head)
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

        Ok(row
            .map(|r| Self::decode_sequence(r.0))
            .transpose()?
            .unwrap_or(0))
    }

    async fn head_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<u64> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT current_sequence FROM ves_sequence_counters WHERE tenant_id = $1 AND store_id = $2",
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .fetch_optional(&mut **tx)
        .await?;

        Ok(row
            .map(|r| Self::decode_sequence(r.0))
            .transpose()?
            .unwrap_or(0))
    }

    async fn get_existing_event(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
    ) -> Result<Option<SequencedVesEvent>> {
        let row: Option<VesEventRow> = sqlx::query_as(
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
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&mut **tx)
        .await?;

        row.map(Self::decode_event_row).transpose()
    }

    async fn get_existing_receipt(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
    ) -> Result<Option<VesSequencerReceipt>> {
        let row: Option<ExistingReceiptRow> = sqlx::query_as(
            r#"
            SELECT sequencer_id, sequence_number, sequenced_at, receipt_hash, sequencer_signature, sequencer_key_version
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
            sequence_number: Self::decode_sequence(row.sequence_number)?,
            sequenced_at: row.sequenced_at,
            receipt_hash,
            signature_alg,
            sequencer_signature,
            sequencer_key_version: row.sequencer_key_version as u32,
        }))
    }

    async fn classify_replay(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        incoming: &VesEventEnvelope,
    ) -> Result<ReplayLookup> {
        let Some(existing) = self.get_existing_event(tx, incoming.event_id).await? else {
            return Ok(ReplayLookup::Missing);
        };

        if !Self::is_exact_replay(&existing, incoming) {
            return Ok(ReplayLookup::DifferentContents);
        }

        match self.get_existing_receipt(tx, incoming.event_id).await? {
            Some(receipt) => Ok(ReplayLookup::ExactReplay(receipt)),
            None => Ok(ReplayLookup::ExactReplayMissingReceipt),
        }
    }

    fn payloads_match(left: Option<&PayloadEncrypted>, right: Option<&PayloadEncrypted>) -> bool {
        match (left, right) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                left.enc_version == right.enc_version
                    && left.aead == right.aead
                    && left.nonce_b64u == right.nonce_b64u
                    && left.ciphertext_b64u == right.ciphertext_b64u
                    && left.tag_b64u == right.tag_b64u
                    && left.hpke.mode == right.hpke.mode
                    && left.hpke.kem == right.hpke.kem
                    && left.hpke.kdf == right.hpke.kdf
                    && left.hpke.aead == right.hpke.aead
                    && left.recipients.len() == right.recipients.len()
                    && left
                        .recipients
                        .iter()
                        .zip(&right.recipients)
                        .all(|(left, right)| {
                            left.recipient_kid == right.recipient_kid
                                && left.enc_b64u == right.enc_b64u
                                && left.ct_b64u == right.ct_b64u
                        })
            }
            _ => false,
        }
    }

    fn is_exact_replay(existing: &SequencedVesEvent, incoming: &VesEventEnvelope) -> bool {
        existing.envelope.ves_version == incoming.ves_version
            && existing.envelope.event_id == incoming.event_id
            && existing.envelope.tenant_id == incoming.tenant_id
            && existing.envelope.store_id == incoming.store_id
            && existing.envelope.source_agent_id == incoming.source_agent_id
            && existing.envelope.agent_key_id == incoming.agent_key_id
            && existing.envelope.entity_type == incoming.entity_type
            && existing.envelope.entity_id == incoming.entity_id
            && existing.envelope.event_type == incoming.event_type
            && existing.envelope.created_at == incoming.created_at
            && existing.envelope.payload_kind == incoming.payload_kind
            && existing.envelope.payload == incoming.payload
            && Self::payloads_match(
                existing.envelope.payload_encrypted.as_ref(),
                incoming.payload_encrypted.as_ref(),
            )
            && existing.envelope.payload_plain_hash == incoming.payload_plain_hash
            && existing.envelope.payload_cipher_hash == incoming.payload_cipher_hash
            && existing.envelope.agent_signature == incoming.agent_signature
            && existing.envelope.command_id == incoming.command_id
            && existing.envelope.base_version == incoming.base_version
    }

    fn validate_payload_encrypted(
        &self,
        event_id: Uuid,
        encrypted: &PayloadEncrypted,
    ) -> Option<VesRejectedEvent> {
        const EXPECTED_AEAD: &str = "AES-256-GCM";
        const EXPECTED_HPKE_MODE: &str = "base";
        const EXPECTED_HPKE_KEM: &str = "X25519-HKDF-SHA256";
        const EXPECTED_HPKE_KDF: &str = "HKDF-SHA256";
        const RECIPIENT_ENC_SIZE: usize = 32;
        const RECIPIENT_CT_SIZE: usize = 48;

        let reject = |field: &str, message: String| VesRejectedEvent {
            event_id,
            reason: VesRejectionReason::SchemaValidation(field.to_string()),
            message,
        };

        let strict_format = self.strict_format_validation;
        let decode_base64 =
            |field: &str, value: &str| -> std::result::Result<Vec<u8>, VesRejectedEvent> {
                let bytes = base64_url_decode(value)
                    .map_err(|_| reject(field, "must be base64url".to_string()))?;
                if strict_format && base64_url_encode(&bytes) != value {
                    return Err(reject(
                        field,
                        "must be canonical base64url without padding".to_string(),
                    ));
                }
                Ok(bytes)
            };

        if encrypted.enc_version != 1 {
            return Some(reject(
                "payload_encrypted.enc_version",
                "enc_version must be 1".to_string(),
            ));
        }

        if encrypted.aead != EXPECTED_AEAD {
            return Some(reject(
                "payload_encrypted.aead",
                format!("aead must be {}", EXPECTED_AEAD),
            ));
        }

        if encrypted.hpke.mode != EXPECTED_HPKE_MODE {
            return Some(reject(
                "payload_encrypted.hpke.mode",
                format!("hpke.mode must be {}", EXPECTED_HPKE_MODE),
            ));
        }

        if encrypted.hpke.kem != EXPECTED_HPKE_KEM {
            return Some(reject(
                "payload_encrypted.hpke.kem",
                format!("hpke.kem must be {}", EXPECTED_HPKE_KEM),
            ));
        }

        if encrypted.hpke.kdf != EXPECTED_HPKE_KDF {
            return Some(reject(
                "payload_encrypted.hpke.kdf",
                format!("hpke.kdf must be {}", EXPECTED_HPKE_KDF),
            ));
        }

        if encrypted.hpke.aead != EXPECTED_AEAD {
            return Some(reject(
                "payload_encrypted.hpke.aead",
                format!("hpke.aead must be {}", EXPECTED_AEAD),
            ));
        }

        let nonce = match decode_base64("payload_encrypted.nonce_b64u", &encrypted.nonce_b64u) {
            Ok(bytes) => bytes,
            Err(rejection) => return Some(rejection),
        };
        if nonce.len() != NONCE_SIZE {
            return Some(reject(
                "payload_encrypted.nonce_b64u",
                format!("nonce_b64u must decode to {NONCE_SIZE} bytes"),
            ));
        }

        let ciphertext = match decode_base64(
            "payload_encrypted.ciphertext_b64u",
            &encrypted.ciphertext_b64u,
        ) {
            Ok(bytes) => bytes,
            Err(rejection) => return Some(rejection),
        };
        if ciphertext.is_empty() {
            return Some(reject(
                "payload_encrypted.ciphertext_b64u",
                "ciphertext_b64u must not be empty".to_string(),
            ));
        }

        let tag = match decode_base64("payload_encrypted.tag_b64u", &encrypted.tag_b64u) {
            Ok(bytes) => bytes,
            Err(rejection) => return Some(rejection),
        };
        if tag.len() != TAG_SIZE {
            return Some(reject(
                "payload_encrypted.tag_b64u",
                format!("tag_b64u must decode to {TAG_SIZE} bytes"),
            ));
        }

        if encrypted.recipients.is_empty() {
            return Some(reject(
                "payload_encrypted.recipients",
                "recipients must not be empty".to_string(),
            ));
        }

        let mut last_kid: Option<u32> = None;
        for recipient in &encrypted.recipients {
            if let Some(prev) = last_kid {
                if recipient.recipient_kid <= prev {
                    return Some(reject(
                        "payload_encrypted.recipients",
                        "recipients must be sorted by recipient_kid and unique".to_string(),
                    ));
                }
            }
            last_kid = Some(recipient.recipient_kid);

            let enc =
                match decode_base64("payload_encrypted.recipients.enc_b64u", &recipient.enc_b64u) {
                    Ok(bytes) => bytes,
                    Err(rejection) => return Some(rejection),
                };
            if enc.len() != RECIPIENT_ENC_SIZE {
                return Some(reject(
                    "payload_encrypted.recipients.enc_b64u",
                    format!("enc_b64u must decode to {RECIPIENT_ENC_SIZE} bytes"),
                ));
            }

            let ct = match decode_base64("payload_encrypted.recipients.ct_b64u", &recipient.ct_b64u)
            {
                Ok(bytes) => bytes,
                Err(rejection) => return Some(rejection),
            };
            if ct.len() != RECIPIENT_CT_SIZE {
                return Some(reject(
                    "payload_encrypted.recipients.ct_b64u",
                    format!("ct_b64u must decode to {RECIPIENT_CT_SIZE} bytes"),
                ));
            }
        }

        None
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
        if entity_type.is_empty() || entity_type.len() > 128 {
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason: VesRejectionReason::SchemaValidation("entity_type".to_string()),
                message: "entity_type must be 1-128 characters".to_string(),
            });
        }

        if event.entity_id.is_empty() || event.entity_id.len() > 512 {
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason: VesRejectionReason::SchemaValidation("entity_id".to_string()),
                message: "entity_id must be 1-512 characters".to_string(),
            });
        }

        let event_type = event.event_type.as_str();
        if event_type.is_empty() || event_type.len() > 256 {
            return Some(VesRejectedEvent {
                event_id: event.event_id,
                reason: VesRejectionReason::SchemaValidation("event_type".to_string()),
                message: "event_type must be 1-256 characters".to_string(),
            });
        }

        match event.payload_kind {
            PayloadKind::Plaintext => {
                if event.payload.is_none() {
                    return Some(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::SchemaValidation("payload".to_string()),
                        message: "payload is required for plaintext events".to_string(),
                    });
                }

                if event.payload_encrypted.is_some() {
                    return Some(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::SchemaValidation(
                            "payload_encrypted".to_string(),
                        ),
                        message: "payload_encrypted must be omitted for plaintext events"
                            .to_string(),
                    });
                }

                if event.payload_cipher_hash != ZERO_HASH {
                    return Some(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::SchemaValidation(
                            "payload_cipher_hash".to_string(),
                        ),
                        message: "payload_cipher_hash must be zero for plaintext events"
                            .to_string(),
                    });
                }
            }
            PayloadKind::Encrypted => {
                if event.payload.is_some() {
                    return Some(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::SchemaValidation("payload".to_string()),
                        message: "payload must be omitted for encrypted events".to_string(),
                    });
                }

                if event.payload_encrypted.is_none() {
                    return Some(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::SchemaValidation(
                            "payload_encrypted".to_string(),
                        ),
                        message: "payload_encrypted is required for encrypted events".to_string(),
                    });
                }
            }
        }

        if event.payload_kind == PayloadKind::Encrypted {
            if let Some(ref encrypted) = event.payload_encrypted {
                if let Some(rejection) = self.validate_payload_encrypted(event.event_id, encrypted)
                {
                    return Some(rejection);
                }
            }
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
        let sequence_number = Self::encode_sequence(event.sequence_number())?;
        let base_version = env.base_version.map(Self::encode_sequence).transpose()?;

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
        .bind(sequence_number)
        .bind(base_version)
        .execute(&mut **tx)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    async fn store_receipt_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        receipt: &VesSequencerReceipt,
    ) -> Result<()> {
        let sequence_number = Self::encode_sequence(receipt.sequence_number)?;
        sqlx::query(
            r#"
            INSERT INTO ves_sequencer_receipts (
                event_id, sequencer_id, sequence_number, sequenced_at, receipt_hash, sequencer_signature, sequencer_key_version
            )
            SELECT $1, $2, $3, $4, $5, $6, $7
            WHERE NOT EXISTS (
                SELECT 1 FROM ves_sequencer_receipts WHERE event_id = $1
            )
            "#,
        )
        .bind(receipt.event_id)
        .bind(receipt.sequencer_id)
        .bind(sequence_number)
        .bind(receipt.sequenced_at)
        .bind(receipt.receipt_hash.as_slice())
        .bind(
            receipt
                .sequencer_signature
                .as_ref()
                .map(|sig| sig.as_slice()),
        )
        .bind(receipt.sequencer_key_version as i32)
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
            FOR UPDATE
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(entity_type.as_str())
        .bind(entity_id)
        .fetch_optional(&mut **tx)
        .await?;

        row.map(|(v,)| {
            u64::try_from(v).map_err(|_| SequencerError::InvariantViolation {
                invariant: "entity_version".to_string(),
                message: "entity version must be non-negative".to_string(),
            })
        })
        .transpose()
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
            sequencer_key_version: self.sequencer_key_version,
        }
    }

    /// Ingest a batch of VES events
    pub async fn ingest(&self, events: Vec<VesEventEnvelope>) -> Result<VesIngestReceipt> {
        if events.is_empty() {
            return Err(SequencerError::SchemaValidation(
                "events must not be empty".to_string(),
            ));
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
                if existing.tenant_id().0 != tenant_id.0 || existing.store_id().0 != store_id.0 {
                    rejected.push(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::DuplicateEventId,
                        message: "Event ID already exists".to_string(),
                    });
                    continue;
                }

                if !Self::is_exact_replay(&existing, &event) {
                    rejected.push(VesRejectedEvent {
                        event_id: event.event_id,
                        reason: VesRejectionReason::DuplicateEventId,
                        message: "Event ID already exists with different contents".to_string(),
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
                    match self.classify_replay(&mut tx, &event).await? {
                        ReplayLookup::ExactReplay(receipt) => {
                            receipts.push(receipt);
                        }
                        ReplayLookup::ExactReplayMissingReceipt => {
                            rejected.push(VesRejectedEvent {
                                event_id: event.event_id,
                                reason: VesRejectionReason::DuplicateEventId,
                                message: "Event already exists but receipt not found".to_string(),
                            });
                        }
                        ReplayLookup::Missing | ReplayLookup::DifferentContents => {
                            rejected.push(VesRejectedEvent {
                                event_id: event.event_id,
                                reason: VesRejectionReason::DuplicateCommandId,
                                message: format!("Command {} already processed", cmd_id),
                            });
                        }
                    }
                    continue;
                }
            }

            valid_events.push(event);
        }

        let valid_events_len = valid_events.len();
        // Lock sequence counter only after validation/dedupe to minimize lock duration.
        let mut head = if valid_events_len == 0 {
            self.head_tx(&mut tx, &tenant_id, &store_id).await?
        } else {
            let head = self
                .lock_sequence_counter(&mut tx, &tenant_id, &store_id)
                .await?;
            Self::ensure_sequence_capacity(head, valid_events_len)?;
            head
        };

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

            let next_seq =
                head.checked_add(1)
                    .ok_or_else(|| SequencerError::InvariantViolation {
                        invariant: "sequence_counter".to_string(),
                        message: "sequence counter overflow".to_string(),
                    })?;
            let sequenced = SequencedVesEvent::new(event, next_seq);

            let inserted = self.store_event_tx(&mut tx, &sequenced).await?;
            if !inserted {
                let replay = self.classify_replay(&mut tx, &sequenced.envelope).await?;
                if let Some(cmd_id) = sequenced.envelope.command_id {
                    if reserved_command_ids.contains(&cmd_id) {
                        let existing_cmd_id = self
                            .fetch_existing_command_id_tx(&mut tx, sequenced.event_id())
                            .await?;
                        if existing_cmd_id != Some(cmd_id) {
                            self.release_command_id_tx(&mut tx, &tenant_id, &store_id, cmd_id)
                                .await?;
                        }
                    }
                }
                match replay {
                    ReplayLookup::ExactReplay(receipt) => receipts.push(receipt),
                    ReplayLookup::ExactReplayMissingReceipt => rejected.push(VesRejectedEvent {
                        event_id: sequenced.event_id(),
                        reason: VesRejectionReason::DuplicateEventId,
                        message: "Event already exists but receipt not found".to_string(),
                    }),
                    ReplayLookup::Missing | ReplayLookup::DifferentContents => {
                        rejected.push(VesRejectedEvent {
                            event_id: sequenced.event_id(),
                            reason: VesRejectionReason::DuplicateEventId,
                            message: format!("Event {} already exists", sequenced.event_id()),
                        });
                    }
                }
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
            events_accepted: new_events_accepted,
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
                entity_type VARCHAR(128) NOT NULL,
                entity_id VARCHAR(512) NOT NULL,
                event_type VARCHAR(256) NOT NULL,
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
        sqlx::query(
            r#"
            ALTER TABLE ves_events
                ALTER COLUMN entity_type TYPE VARCHAR(128),
                ALTER COLUMN entity_id TYPE VARCHAR(512),
                ALTER COLUMN event_type TYPE VARCHAR(256)
            "#,
        )
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
                sequencer_signature BYTEA,
                sequencer_key_version INTEGER NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE ves_sequencer_receipts ADD COLUMN IF NOT EXISTS sequencer_key_version INTEGER NOT NULL DEFAULT 0",
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
        .bind(Self::encode_sequence(after_sequence)?)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(Self::decode_event_row(row)?);
        }

        Ok(events)
    }

    /// Read events by sequence range (inclusive).
    pub async fn read_range(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<Vec<SequencedVesEvent>> {
        if end < start {
            return Ok(Vec::new());
        }
        let start = Self::normalize_range_start(start);
        if start > end || end == 0 {
            return Ok(Vec::new());
        }

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
            WHERE tenant_id = $1 AND store_id = $2
              AND sequence_number >= $3 AND sequence_number <= $4
            ORDER BY sequence_number ASC
            "#,
        )
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(Self::encode_sequence(start)?)
        .bind(Self::encode_sequence(end)?)
        .fetch_all(&self.pool)
        .await?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(Self::decode_event_row(row)?);
        }

        let head_sequence = self.head_sequence(tenant_id, store_id).await?;
        if events.is_empty() {
            if head_sequence >= start {
                return Err(SequencerError::InvariantViolation {
                    invariant: "sequence_range".to_string(),
                    message: format!("sequence gap in range {start}..={end}: head {head_sequence}"),
                });
            }
            return Ok(events);
        }

        let last_sequence = Self::ensure_sequence_contiguity(start, &events)?;
        if last_sequence < end && head_sequence > last_sequence {
            return Err(SequencerError::InvariantViolation {
                invariant: "sequence_range".to_string(),
                message: format!(
                    "sequence gap in range {start}..={end}: last event {last_sequence}, head {head_sequence}"
                ),
            });
        }

        Ok(events)
    }

    /// Read events for a specific entity (ordered by sequence).
    pub async fn read_entity(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &EntityType,
        entity_id: &str,
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
            events.push(Self::decode_event_row(row)?);
        }

        Ok(events)
    }

    /// Read a single event by ID.
    pub async fn read_by_id(&self, event_id: Uuid) -> Result<Option<SequencedVesEvent>> {
        let row: Option<VesEventRow> = sqlx::query_as(
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
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(Self::decode_event_row).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AgentKeyEntry, AgentKeyLookup, InMemoryAgentKeyRegistry};
    use crate::crypto::{
        base64_url_encode, compute_cipher_hash_from_encrypted, compute_payload_aad,
        AgentSigningKey, EventSigningParams, Hash256, HpkeParams, PayloadAadParams,
        PayloadEncrypted, Recipient, NONCE_SIZE, TAG_SIZE,
    };
    use crate::domain::{EntityType, EventType, PayloadKind, VES_VERSION};
    use chrono::Utc;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    fn sequencer(
        registry: Arc<InMemoryAgentKeyRegistry>,
        strict_format: bool,
    ) -> VesSequencer<InMemoryAgentKeyRegistry> {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/stateset_sequencer")
            .expect("connect_lazy should not fail");

        VesSequencer {
            pool,
            key_registry: registry,
            sequencer_id: Uuid::new_v4(),
            sequencer_signing_key: None,
            sequencer_key_version: 0,
            strict_format_validation: strict_format,
        }
    }

    fn dummy_payload_encrypted() -> PayloadEncrypted {
        PayloadEncrypted {
            enc_version: 1,
            aead: "AES-256-GCM".to_string(),
            nonce_b64u: "AA".to_string(),
            ciphertext_b64u: "AA".to_string(),
            tag_b64u: "AA".to_string(),
            hpke: HpkeParams::default(),
            recipients: vec![Recipient {
                recipient_kid: 1,
                enc_b64u: "AA".to_string(),
                ct_b64u: "AA".to_string(),
            }],
        }
    }

    async fn register_key(
        registry: &InMemoryAgentKeyRegistry,
        event: &VesEventEnvelope,
        signing_key: &AgentSigningKey,
    ) {
        let lookup =
            AgentKeyLookup::new(&event.tenant_id, &event.source_agent_id, event.agent_key_id);
        let entry = AgentKeyEntry::new(signing_key.public_key_bytes());
        registry.register_key(&lookup, entry).await.unwrap();
    }

    fn recipient(kid: u32, fill: u8) -> Recipient {
        let enc = vec![fill; 32];
        let ct = vec![fill; 48];
        Recipient {
            recipient_kid: kid,
            enc_b64u: base64_url_encode(&enc),
            ct_b64u: base64_url_encode(&ct),
        }
    }

    fn valid_payload_encrypted() -> PayloadEncrypted {
        let nonce = vec![1u8; NONCE_SIZE];
        let ciphertext = vec![2u8; 24];
        let tag = vec![3u8; TAG_SIZE];

        PayloadEncrypted {
            enc_version: 1,
            aead: "AES-256-GCM".to_string(),
            nonce_b64u: base64_url_encode(&nonce),
            ciphertext_b64u: base64_url_encode(&ciphertext),
            tag_b64u: base64_url_encode(&tag),
            hpke: HpkeParams::default(),
            recipients: vec![recipient(1, 4)],
        }
    }

    fn build_encrypted_event(
        signing_key: &AgentSigningKey,
        payload_encrypted: PayloadEncrypted,
    ) -> VesEventEnvelope {
        let tenant_id = TenantId::new();
        let store_id = StoreId::new();
        let event_id = Uuid::new_v4();
        let source_agent_id = AgentId::new();
        let agent_key_id = AgentKeyId::default();
        let entity_type = EntityType::order();
        let entity_id = "order-123".to_string();
        let event_type = EventType::from(EventType::ORDER_CREATED);
        let created_at = Utc::now().to_rfc3339();
        let payload_plain_hash: Hash256 = [9u8; 32];

        let aad_params = PayloadAadParams {
            tenant_id: &tenant_id.0,
            store_id: &store_id.0,
            event_id: &event_id,
            source_agent_id: &source_agent_id.0,
            agent_key_id: agent_key_id.as_u32(),
            entity_type: entity_type.as_str(),
            entity_id: &entity_id,
            event_type: event_type.as_str(),
            created_at: &created_at,
            payload_plain_hash: &payload_plain_hash,
        };
        let payload_aad = compute_payload_aad(&aad_params);
        let payload_cipher_hash =
            compute_cipher_hash_from_encrypted(&payload_encrypted, &payload_aad)
                .expect("payload_encrypted should be decodable");

        let signing_params = EventSigningParams {
            ves_version: VES_VERSION,
            tenant_id: &tenant_id.0,
            store_id: &store_id.0,
            event_id: &event_id,
            source_agent_id: &source_agent_id.0,
            agent_key_id: agent_key_id.as_u32(),
            entity_type: entity_type.as_str(),
            entity_id: &entity_id,
            event_type: event_type.as_str(),
            created_at: &created_at,
            payload_kind: PayloadKind::Encrypted.as_u32(),
            payload_plain_hash: &payload_plain_hash,
            payload_cipher_hash: &payload_cipher_hash,
        };
        let agent_signature = signing_key.sign_event(&signing_params);

        VesEventEnvelope {
            ves_version: VES_VERSION,
            event_id,
            tenant_id,
            store_id,
            source_agent_id,
            agent_key_id,
            entity_type,
            entity_id,
            event_type,
            created_at,
            payload_kind: PayloadKind::Encrypted,
            payload: None,
            payload_encrypted: Some(payload_encrypted),
            payload_plain_hash,
            payload_cipher_hash,
            agent_signature,
            sequence_number: None,
            sequenced_at: None,
            command_id: None,
            base_version: None,
        }
    }

    #[tokio::test]
    async fn validate_event_rejects_plaintext_with_encrypted_payload() {
        let signing_key = AgentSigningKey::generate();
        let mut event = VesEventEnvelope::new_plaintext(
            TenantId::new(),
            StoreId::new(),
            AgentId::new(),
            AgentKeyId::default(),
            EntityType::order(),
            "order-123",
            EventType::from(EventType::ORDER_CREATED),
            serde_json::json!({"amount": 100}),
            &signing_key,
        );
        event.payload_encrypted = Some(dummy_payload_encrypted());

        let registry = Arc::new(InMemoryAgentKeyRegistry::new());
        register_key(&registry, &event, &signing_key).await;
        let sequencer = sequencer(registry, false);

        let rejection = sequencer
            .validate_event(&event)
            .await
            .expect("expected rejection");

        match rejection.reason {
            VesRejectionReason::SchemaValidation(field) => {
                assert_eq!(field, "payload_encrypted");
            }
            other => panic!("unexpected rejection: {:?}", other),
        }
    }

    #[tokio::test]
    async fn validate_event_rejects_plaintext_with_cipher_hash() {
        let signing_key = AgentSigningKey::generate();
        let mut event = VesEventEnvelope::new_plaintext(
            TenantId::new(),
            StoreId::new(),
            AgentId::new(),
            AgentKeyId::default(),
            EntityType::order(),
            "order-123",
            EventType::from(EventType::ORDER_CREATED),
            serde_json::json!({"amount": 100}),
            &signing_key,
        );
        event.payload_cipher_hash = [42u8; 32];

        let registry = Arc::new(InMemoryAgentKeyRegistry::new());
        register_key(&registry, &event, &signing_key).await;
        let sequencer = sequencer(registry, false);

        let rejection = sequencer
            .validate_event(&event)
            .await
            .expect("expected rejection");

        match rejection.reason {
            VesRejectionReason::SchemaValidation(field) => {
                assert_eq!(field, "payload_cipher_hash");
            }
            other => panic!("unexpected rejection: {:?}", other),
        }
    }

    #[tokio::test]
    async fn validate_event_rejects_encrypted_with_payload() {
        let signing_key = AgentSigningKey::generate();
        let mut event = VesEventEnvelope::new_plaintext(
            TenantId::new(),
            StoreId::new(),
            AgentId::new(),
            AgentKeyId::default(),
            EntityType::order(),
            "order-123",
            EventType::from(EventType::ORDER_CREATED),
            serde_json::json!({"amount": 100}),
            &signing_key,
        );
        event.payload_kind = PayloadKind::Encrypted;

        let registry = Arc::new(InMemoryAgentKeyRegistry::new());
        register_key(&registry, &event, &signing_key).await;
        let sequencer = sequencer(registry, false);

        let rejection = sequencer
            .validate_event(&event)
            .await
            .expect("expected rejection");

        match rejection.reason {
            VesRejectionReason::SchemaValidation(field) => {
                assert_eq!(field, "payload");
            }
            other => panic!("unexpected rejection: {:?}", other),
        }
    }

    #[tokio::test]
    async fn validate_event_rejects_encrypted_without_payload_encrypted() {
        let signing_key = AgentSigningKey::generate();
        let mut event = VesEventEnvelope::new_plaintext(
            TenantId::new(),
            StoreId::new(),
            AgentId::new(),
            AgentKeyId::default(),
            EntityType::order(),
            "order-123",
            EventType::from(EventType::ORDER_CREATED),
            serde_json::json!({"amount": 100}),
            &signing_key,
        );
        event.payload_kind = PayloadKind::Encrypted;
        event.payload = None;
        event.payload_encrypted = None;

        let registry = Arc::new(InMemoryAgentKeyRegistry::new());
        register_key(&registry, &event, &signing_key).await;
        let sequencer = sequencer(registry, false);

        let rejection = sequencer
            .validate_event(&event)
            .await
            .expect("expected rejection");

        match rejection.reason {
            VesRejectionReason::SchemaValidation(field) => {
                assert_eq!(field, "payload_encrypted");
            }
            other => panic!("unexpected rejection: {:?}", other),
        }
    }

    #[tokio::test]
    async fn validate_event_rejects_encrypted_invalid_hpke_mode() {
        let signing_key = AgentSigningKey::generate();
        let mut payload_encrypted = valid_payload_encrypted();
        payload_encrypted.hpke.mode = "unsupported".to_string();
        let event = build_encrypted_event(&signing_key, payload_encrypted);

        let registry = Arc::new(InMemoryAgentKeyRegistry::new());
        register_key(&registry, &event, &signing_key).await;
        let sequencer = sequencer(registry, false);

        let rejection = sequencer
            .validate_event(&event)
            .await
            .expect("expected rejection");

        match rejection.reason {
            VesRejectionReason::SchemaValidation(field) => {
                assert_eq!(field, "payload_encrypted.hpke.mode");
            }
            other => panic!("unexpected rejection: {:?}", other),
        }
    }

    #[tokio::test]
    async fn validate_event_rejects_encrypted_unsorted_recipients() {
        let signing_key = AgentSigningKey::generate();
        let mut payload_encrypted = valid_payload_encrypted();
        payload_encrypted.recipients = vec![recipient(2, 5), recipient(1, 7)];
        let event = build_encrypted_event(&signing_key, payload_encrypted);

        let registry = Arc::new(InMemoryAgentKeyRegistry::new());
        register_key(&registry, &event, &signing_key).await;
        let sequencer = sequencer(registry, false);

        let rejection = sequencer
            .validate_event(&event)
            .await
            .expect("expected rejection");

        match rejection.reason {
            VesRejectionReason::SchemaValidation(field) => {
                assert_eq!(field, "payload_encrypted.recipients");
            }
            other => panic!("unexpected rejection: {:?}", other),
        }
    }

    #[tokio::test]
    async fn validate_event_rejects_encrypted_invalid_nonce() {
        let signing_key = AgentSigningKey::generate();
        let mut event = build_encrypted_event(&signing_key, valid_payload_encrypted());
        event.payload_encrypted.as_mut().unwrap().nonce_b64u = "!!!".to_string();

        let registry = Arc::new(InMemoryAgentKeyRegistry::new());
        register_key(&registry, &event, &signing_key).await;
        let sequencer = sequencer(registry, false);

        let rejection = sequencer
            .validate_event(&event)
            .await
            .expect("expected rejection");

        match rejection.reason {
            VesRejectionReason::SchemaValidation(field) => {
                assert_eq!(field, "payload_encrypted.nonce_b64u");
            }
            other => panic!("unexpected rejection: {:?}", other),
        }
    }

    #[tokio::test]
    async fn validate_event_rejects_padded_tag_in_strict_mode() {
        let signing_key = AgentSigningKey::generate();
        let mut payload_encrypted = valid_payload_encrypted();
        payload_encrypted.tag_b64u = format!("{}==", payload_encrypted.tag_b64u);
        let event = build_encrypted_event(&signing_key, payload_encrypted);

        let registry = Arc::new(InMemoryAgentKeyRegistry::new());
        register_key(&registry, &event, &signing_key).await;
        let sequencer = sequencer(registry, true);

        let rejection = sequencer
            .validate_event(&event)
            .await
            .expect("expected rejection");

        match rejection.reason {
            VesRejectionReason::SchemaValidation(field) => {
                assert_eq!(field, "payload_encrypted.tag_b64u");
            }
            other => panic!("unexpected rejection: {:?}", other),
        }
    }

    #[test]
    fn sequence_capacity_allows_within_limit() {
        let head = 10;
        let count = 5;
        let result =
            VesSequencer::<InMemoryAgentKeyRegistry>::ensure_sequence_capacity(head, count);
        assert!(result.is_ok());
    }

    #[test]
    fn sequence_capacity_rejects_overflow() {
        let head = VesSequencer::<InMemoryAgentKeyRegistry>::MAX_SEQUENCE;
        let result = VesSequencer::<InMemoryAgentKeyRegistry>::ensure_sequence_capacity(head, 1);
        assert!(result.is_err());
    }

    #[test]
    fn decode_sequence_rejects_negative() {
        let result = VesSequencer::<InMemoryAgentKeyRegistry>::decode_sequence(-1);
        assert!(result.is_err());
    }

    #[test]
    fn normalize_range_start_maps_zero_to_one() {
        assert_eq!(
            VesSequencer::<InMemoryAgentKeyRegistry>::normalize_range_start(0),
            1
        );
    }

    #[test]
    fn ensure_sequence_contiguity_succeeds_for_consecutive_events() {
        let signing_key = AgentSigningKey::generate();
        let events = vec![
            SequencedVesEvent::new(
                build_encrypted_event(&signing_key, valid_payload_encrypted()),
                10,
            ),
            SequencedVesEvent::new(
                build_encrypted_event(&signing_key, valid_payload_encrypted()),
                11,
            ),
        ];

        assert!(
            VesSequencer::<InMemoryAgentKeyRegistry>::ensure_sequence_contiguity(10, &events)
                .is_ok()
        );
    }

    #[test]
    fn ensure_sequence_contiguity_detects_gap() {
        let signing_key = AgentSigningKey::generate();
        let events = vec![
            SequencedVesEvent::new(
                build_encrypted_event(&signing_key, valid_payload_encrypted()),
                10,
            ),
            SequencedVesEvent::new(
                build_encrypted_event(&signing_key, valid_payload_encrypted()),
                12,
            ),
        ];

        assert!(
            VesSequencer::<InMemoryAgentKeyRegistry>::ensure_sequence_contiguity(10, &events)
                .is_err()
        );
    }

    #[test]
    fn exact_replay_matches_identical_event() {
        let signing_key = AgentSigningKey::generate();
        let event = build_encrypted_event(&signing_key, valid_payload_encrypted());
        let existing = SequencedVesEvent::new(event.clone(), 42);

        assert!(VesSequencer::<InMemoryAgentKeyRegistry>::is_exact_replay(
            &existing, &event
        ));
    }

    #[test]
    fn exact_replay_rejects_changed_payload() {
        let signing_key = AgentSigningKey::generate();
        let event = build_encrypted_event(&signing_key, valid_payload_encrypted());
        let existing = SequencedVesEvent::new(event.clone(), 42);

        let mut replay = event.clone();
        replay.payload_cipher_hash = [7u8; 32];

        assert!(!VesSequencer::<InMemoryAgentKeyRegistry>::is_exact_replay(
            &existing, &replay
        ));
    }
}
