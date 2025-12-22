//! Event envelope and related types for StateSet Sequencer
//!
//! This is the canonical event structure for all StateSet operations.
//! The EventEnvelope is the contract between embedded engines and the sequencer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::canonical_json_hash;

use super::{hash256_hex, AgentId, EntityType, EventType, Hash256, StoreId, TenantId};

/// Canonical event envelope for all StateSet operations.
///
/// This structure is Phase 2-compatible, meaning it includes fields
/// that will be used for ZK proof generation in later phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Globally unique event identifier (idempotency at event level)
    pub event_id: Uuid,

    /// Optional idempotency key for "intent" (e.g. CLI command)
    /// Multiple events from one command share the same command_id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_id: Option<Uuid>,

    /// Tenant isolation
    pub tenant_id: TenantId,

    /// Store isolation within tenant
    pub store_id: StoreId,

    /// Entity classification (order, product, inventory, etc.)
    pub entity_type: EntityType,

    /// Entity identifier within the type
    pub entity_id: String,

    /// Event type (created, updated, cancelled, etc.)
    pub event_type: EventType,

    /// Serialized payload (encrypted at rest in server store)
    pub payload: serde_json::Value,

    /// Hash of payload for verification / Merkle leaves / ZK inputs
    /// Computed over canonical JSON encoding (stable key order)
    #[serde(with = "hash256_hex")]
    pub payload_hash: Hash256,

    /// Optimistic concurrency control (entity version at authoring time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_version: Option<u64>,

    /// Client-side timestamp (metadata only; NOT used for ordering)
    pub created_at: DateTime<Utc>,

    /// Canonical ordering assigned by sequencer (monotonic per tenant/store)
    /// None until sequencer assigns it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u64>,

    /// Source agent identifier (cli, prod, agent:orders, etc.)
    pub source_agent: AgentId,

    /// Optional signature over envelope fields for authenticity (Phase 1+)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl EventEnvelope {
    /// Create a new event envelope with automatic payload hashing
    pub fn new(
        tenant_id: TenantId,
        store_id: StoreId,
        entity_type: EntityType,
        entity_id: impl Into<String>,
        event_type: EventType,
        payload: serde_json::Value,
        source_agent: AgentId,
    ) -> Self {
        let payload_hash = Self::compute_payload_hash(&payload);

        Self {
            event_id: Uuid::new_v4(),
            command_id: None,
            tenant_id,
            store_id,
            entity_type,
            entity_id: entity_id.into(),
            event_type,
            payload,
            payload_hash,
            base_version: None,
            created_at: Utc::now(),
            sequence_number: None,
            source_agent,
            signature: None,
        }
    }

    /// Compute SHA-256 hash of payload using canonical JSON encoding
    pub fn compute_payload_hash(payload: &serde_json::Value) -> Hash256 {
        canonical_json_hash(payload)
    }

    /// Set command_id for intent-level deduplication
    pub fn with_command_id(mut self, command_id: Uuid) -> Self {
        self.command_id = Some(command_id);
        self
    }

    /// Set base_version for optimistic concurrency
    pub fn with_base_version(mut self, version: u64) -> Self {
        self.base_version = Some(version);
        self
    }

    /// Get bytes to sign for authenticity verification
    /// Signature covers: event_id | command_id | tenant_id | store_id |
    /// entity_type | entity_id | event_type | payload_hash | base_version | created_at
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.event_id.as_bytes());
        if let Some(cmd_id) = &self.command_id {
            bytes.extend(cmd_id.as_bytes());
        }
        bytes.extend(self.tenant_id.0.as_bytes());
        bytes.extend(self.store_id.0.as_bytes());
        bytes.extend(self.entity_type.as_str().as_bytes());
        bytes.extend(self.entity_id.as_bytes());
        bytes.extend(self.event_type.as_str().as_bytes());
        bytes.extend(&self.payload_hash);
        if let Some(v) = self.base_version {
            bytes.extend(&v.to_le_bytes());
        }
        bytes.extend(self.created_at.timestamp_millis().to_le_bytes());
        bytes
    }

    /// Verify the payload hash matches the payload
    pub fn verify_payload_hash(&self) -> bool {
        let computed = Self::compute_payload_hash(&self.payload);
        computed == self.payload_hash
    }
}

/// Event with assigned sequence number from sequencer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencedEvent {
    /// The event envelope (includes assigned sequence_number)
    pub envelope: EventEnvelope,

    /// Timestamp when sequencer assigned the sequence number
    pub sequenced_at: DateTime<Utc>,
}

impl SequencedEvent {
    pub fn new(mut envelope: EventEnvelope, sequence_number: u64) -> Self {
        envelope.sequence_number = Some(sequence_number);
        Self {
            envelope,
            sequenced_at: Utc::now(),
        }
    }

    // Convenience accessors
    pub fn sequence_number(&self) -> u64 {
        self.envelope.sequence_number.unwrap_or(0)
    }

    pub fn event_id(&self) -> Uuid {
        self.envelope.event_id
    }

    pub fn entity_type(&self) -> &EntityType {
        &self.envelope.entity_type
    }

    pub fn entity_id(&self) -> &str {
        &self.envelope.entity_id
    }

    pub fn event_type(&self) -> &EventType {
        &self.envelope.event_type
    }

    pub fn payload(&self) -> &serde_json::Value {
        &self.envelope.payload
    }

    pub fn base_version(&self) -> Option<u64> {
        self.envelope.base_version
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.envelope.created_at
    }
}

/// Batch of events for ingestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    /// Agent submitting the batch
    pub agent_id: AgentId,

    /// Events in the batch
    pub events: Vec<EventEnvelope>,
}

impl EventBatch {
    pub fn new(agent_id: AgentId, events: Vec<EventEnvelope>) -> Self {
        Self { agent_id, events }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Receipt returned after successful event ingestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestReceipt {
    /// Unique batch identifier
    pub batch_id: Uuid,

    /// Number of events accepted
    pub events_accepted: u32,

    /// Events that were rejected (schema/auth/duplicate)
    pub events_rejected: Vec<RejectedEvent>,

    /// First sequence number assigned (if any events accepted)
    pub assigned_sequence_start: Option<u64>,

    /// Last sequence number assigned (if any events accepted)
    pub assigned_sequence_end: Option<u64>,

    /// Current head sequence for this tenant/store
    pub head_sequence: u64,
}

/// Event that was rejected during ingestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedEvent {
    /// The event that was rejected
    pub event_id: Uuid,

    /// Reason for rejection
    pub reason: RejectionReason,

    /// Human-readable message
    pub message: String,
}

/// Reasons an event can be rejected
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Event ID already exists (duplicate)
    DuplicateEventId,

    /// Command ID already processed (duplicate intent)
    DuplicateCommandId,

    /// Schema validation failed
    SchemaValidation,

    /// Authorization failed
    Unauthorized,

    /// Rate limit exceeded
    RateLimited,

    /// Invalid payload hash
    InvalidPayloadHash,

    /// Other error
    Other,
}

/// Sync state for tracking agent synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    /// Agent identifier
    pub agent_id: AgentId,

    /// Tenant identifier
    pub tenant_id: TenantId,

    /// Store identifier
    pub store_id: StoreId,

    /// Last sequence number pushed to remote
    pub last_pushed_sequence: u64,

    /// Last sequence number pulled from remote
    pub last_pulled_sequence: u64,

    /// Known head from last pull
    pub head_sequence: u64,

    /// Last sync time
    pub last_sync_at: DateTime<Utc>,
}

impl SyncState {
    pub fn new(agent_id: AgentId, tenant_id: TenantId, store_id: StoreId) -> Self {
        Self {
            agent_id,
            tenant_id,
            store_id,
            last_pushed_sequence: 0,
            last_pulled_sequence: 0,
            head_sequence: 0,
            last_sync_at: Utc::now(),
        }
    }

    /// Calculate lag (sequences behind head)
    pub fn lag(&self) -> u64 {
        self.head_sequence.saturating_sub(self.last_pulled_sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_hash_consistency() {
        let payload = serde_json::json!({
            "quantity": 5,
            "sku": "TEST-001"
        });

        let hash1 = EventEnvelope::compute_payload_hash(&payload);
        let hash2 = EventEnvelope::compute_payload_hash(&payload);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_event_envelope_creation() {
        let envelope = EventEnvelope::new(
            TenantId::new(),
            StoreId::new(),
            EntityType::order(),
            "order-123",
            EventType::from(EventType::ORDER_CREATED),
            serde_json::json!({"customer_id": "cust-456"}),
            AgentId::new(),
        );

        assert!(envelope.verify_payload_hash());
        assert!(envelope.sequence_number.is_none());
    }

    #[test]
    fn test_sequenced_event() {
        let envelope = EventEnvelope::new(
            TenantId::new(),
            StoreId::new(),
            EntityType::product(),
            "prod-789",
            EventType::from(EventType::PRODUCT_UPDATED),
            serde_json::json!({"price": 29.99}),
            AgentId::new(),
        );

        let sequenced = SequencedEvent::new(envelope, 42);
        assert_eq!(sequenced.sequence_number(), 42);
    }
}
