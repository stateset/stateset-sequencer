//! VES v1.0 compliant Event Envelope
//!
//! This module provides the canonical event structure per VES v1.0 specification.
//! It includes all required fields for agent signatures and encrypted payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{
    compute_cipher_hash_from_encrypted, compute_event_signing_hash, compute_payload_aad,
    payload_plain_hash, AgentSigningKey, AgentVerifyingKey, EventSigningParams, Hash256,
    PayloadAadParams, PayloadEncrypted, Signature64, SigningError,
};
use crate::domain::{
    hash256_hex_0x, signature64_hex_0x, AgentId, AgentKeyId, EntityType, EventType, PayloadKind,
    StoreId, TenantId, VES_VERSION,
};

/// Zero hash constant for plaintext events (payload_cipher_hash)
pub const ZERO_HASH: Hash256 = [0u8; 32];

/// VES v1.0 compliant Event Envelope
///
/// This structure contains all fields required by the VES specification:
/// - Agent-authored fields (signed)
/// - Payload hashes (plain and cipher)
/// - Agent signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VesEventEnvelope {
    // ========================================================================
    // VES Protocol Fields
    // ========================================================================
    /// VES specification version (must be 1)
    pub ves_version: u32,

    // ========================================================================
    // Identity Fields
    // ========================================================================
    /// Globally unique event identifier
    pub event_id: Uuid,

    /// Tenant identifier (organization/account)
    pub tenant_id: TenantId,

    /// Store identifier within tenant
    pub store_id: StoreId,

    /// Source agent identifier
    pub source_agent_id: AgentId,

    /// Agent signing key identifier (for key rotation)
    pub agent_key_id: AgentKeyId,

    // ========================================================================
    // Entity and Event Classification
    // ========================================================================
    /// Entity type (order, product, inventory, etc.)
    pub entity_type: EntityType,

    /// Entity identifier within type
    pub entity_id: String,

    /// Event type (created, updated, etc.)
    pub event_type: EventType,

    // ========================================================================
    // Timestamp
    // ========================================================================
    /// Client-side timestamp (RFC 3339 string)
    /// This is signed but NOT used for canonical ordering
    /// Stored as String to preserve exact format for signature verification
    pub created_at: String,

    // ========================================================================
    // Payload Fields
    // ========================================================================
    /// Payload kind: 0 = plaintext, 1 = encrypted
    pub payload_kind: PayloadKind,

    /// Plaintext payload (present when payload_kind = 0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,

    /// Encrypted payload structure (present when payload_kind = 1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_encrypted: Option<PayloadEncrypted>,

    /// Hash of canonical plaintext per VES v1.0 Section 5.2
    #[serde(with = "hash256_hex_0x")]
    pub payload_plain_hash: Hash256,

    /// Hash of ciphertext bundle (or zeros for plaintext)
    #[serde(with = "hash256_hex_0x")]
    pub payload_cipher_hash: Hash256,

    // ========================================================================
    // Agent Signature
    // ========================================================================
    /// Ed25519 signature over event_signing_hash
    #[serde(with = "signature64_hex_0x")]
    pub agent_signature: Signature64,

    // ========================================================================
    // Sequencer-Assigned Fields (not agent-signed)
    // ========================================================================
    /// Canonical sequence number (assigned by sequencer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u64>,

    /// Timestamp when sequencer accepted the event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequenced_at: Option<DateTime<Utc>>,

    // ========================================================================
    // Optional Fields
    // ========================================================================
    /// Command ID for intent-level deduplication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_id: Option<Uuid>,

    /// Base version for optimistic concurrency control
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_version: Option<u64>,
}

impl VesEventEnvelope {
    /// Create a new plaintext event envelope
    ///
    /// Automatically computes payload_plain_hash and signs with the provided key
    pub fn new_plaintext(
        tenant_id: TenantId,
        store_id: StoreId,
        source_agent_id: AgentId,
        agent_key_id: AgentKeyId,
        entity_type: EntityType,
        entity_id: impl Into<String>,
        event_type: EventType,
        payload: serde_json::Value,
        signing_key: &AgentSigningKey,
    ) -> Self {
        let event_id = Uuid::new_v4();
        let entity_id = entity_id.into();
        let created_at = Utc::now();
        let created_at_str = created_at.to_rfc3339();

        // Compute payload_plain_hash
        let payload_plain_hash = payload_plain_hash(&payload);
        let payload_cipher_hash = ZERO_HASH;

        // Compute event signing hash
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
            created_at: &created_at_str,
            payload_kind: PayloadKind::Plaintext.as_u32(),
            payload_plain_hash: &payload_plain_hash,
            payload_cipher_hash: &payload_cipher_hash,
        };

        let agent_signature = signing_key.sign_event(&signing_params);

        Self {
            ves_version: VES_VERSION,
            event_id,
            tenant_id,
            store_id,
            source_agent_id,
            agent_key_id,
            entity_type,
            entity_id,
            event_type,
            created_at: created_at_str,
            payload_kind: PayloadKind::Plaintext,
            payload: Some(payload),
            payload_encrypted: None,
            payload_plain_hash,
            payload_cipher_hash,
            agent_signature,
            sequence_number: None,
            sequenced_at: None,
            command_id: None,
            base_version: None,
        }
    }

    /// Create a new encrypted event envelope
    ///
    /// Takes pre-computed encrypted payload and hashes
    pub fn new_encrypted(
        tenant_id: TenantId,
        store_id: StoreId,
        source_agent_id: AgentId,
        agent_key_id: AgentKeyId,
        entity_type: EntityType,
        entity_id: impl Into<String>,
        event_type: EventType,
        payload_encrypted: PayloadEncrypted,
        payload_plain_hash: Hash256,
        payload_cipher_hash: Hash256,
        signing_key: &AgentSigningKey,
    ) -> Self {
        let event_id = Uuid::new_v4();
        let entity_id = entity_id.into();
        let created_at = Utc::now();
        let created_at_str = created_at.to_rfc3339();

        // Compute event signing hash
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
            created_at: &created_at_str,
            payload_kind: PayloadKind::Encrypted.as_u32(),
            payload_plain_hash: &payload_plain_hash,
            payload_cipher_hash: &payload_cipher_hash,
        };

        let agent_signature = signing_key.sign_event(&signing_params);

        Self {
            ves_version: VES_VERSION,
            event_id,
            tenant_id,
            store_id,
            source_agent_id,
            agent_key_id,
            entity_type,
            entity_id,
            event_type,
            created_at: created_at_str,
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

    /// Get created_at string
    pub fn created_at_rfc3339(&self) -> &str {
        &self.created_at
    }

    /// Compute the event signing hash for this envelope
    pub fn compute_signing_hash(&self) -> Hash256 {
        let params = EventSigningParams {
            ves_version: self.ves_version,
            tenant_id: &self.tenant_id.0,
            store_id: &self.store_id.0,
            event_id: &self.event_id,
            source_agent_id: &self.source_agent_id.0,
            agent_key_id: self.agent_key_id.as_u32(),
            entity_type: self.entity_type.as_str(),
            entity_id: &self.entity_id,
            event_type: self.event_type.as_str(),
            created_at: &self.created_at,
            payload_kind: self.payload_kind.as_u32(),
            payload_plain_hash: &self.payload_plain_hash,
            payload_cipher_hash: &self.payload_cipher_hash,
        };

        compute_event_signing_hash(&params)
    }

    /// Verify the agent signature
    pub fn verify_signature(&self, verifying_key: &AgentVerifyingKey) -> Result<(), SigningError> {
        let signing_hash = self.compute_signing_hash();
        verifying_key.verify(&signing_hash, &self.agent_signature)
    }

    /// Verify payload_plain_hash matches payload (for plaintext events)
    pub fn verify_payload_hash(&self) -> bool {
        match self.payload_kind {
            PayloadKind::Plaintext => {
                if let Some(ref payload) = self.payload {
                    let computed = payload_plain_hash(payload);
                    computed == self.payload_plain_hash
                } else {
                    false
                }
            }
            PayloadKind::Encrypted => {
                // Cannot verify without decryption keys
                // But we can verify payload_cipher_hash
                if let Some(ref encrypted) = self.payload_encrypted {
                    // Compute AAD (needs payload_plain_hash from signed envelope)
                    let created_at_str = self.created_at_rfc3339();
                    let aad_params = PayloadAadParams {
                        tenant_id: &self.tenant_id.0,
                        store_id: &self.store_id.0,
                        event_id: &self.event_id,
                        source_agent_id: &self.source_agent_id.0,
                        agent_key_id: self.agent_key_id.as_u32(),
                        entity_type: self.entity_type.as_str(),
                        entity_id: &self.entity_id,
                        event_type: self.event_type.as_str(),
                        created_at: &created_at_str,
                        payload_plain_hash: &self.payload_plain_hash,
                    };
                    let aad = compute_payload_aad(&aad_params);

                    // Compute cipher hash
                    match compute_cipher_hash_from_encrypted(encrypted, &aad) {
                        Ok(computed) => computed == self.payload_cipher_hash,
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
        }
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

    /// Check if this is a plaintext event
    pub fn is_plaintext(&self) -> bool {
        self.payload_kind == PayloadKind::Plaintext
    }

    /// Check if this is an encrypted event
    pub fn is_encrypted(&self) -> bool {
        self.payload_kind == PayloadKind::Encrypted
    }
}

/// Sequenced VES event with assigned sequence number
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencedVesEvent {
    /// The event envelope (includes sequence_number after assignment)
    pub envelope: VesEventEnvelope,
}

impl SequencedVesEvent {
    /// Create from an envelope by assigning sequence number
    pub fn new(mut envelope: VesEventEnvelope, sequence_number: u64) -> Self {
        envelope.sequence_number = Some(sequence_number);
        envelope.sequenced_at = Some(Utc::now());
        Self { envelope }
    }

    pub fn sequence_number(&self) -> u64 {
        self.envelope.sequence_number.unwrap_or(0)
    }

    pub fn event_id(&self) -> Uuid {
        self.envelope.event_id
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.envelope.tenant_id
    }

    pub fn store_id(&self) -> &StoreId {
        &self.envelope.store_id
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

    pub fn payload(&self) -> Option<&serde_json::Value> {
        self.envelope.payload.as_ref()
    }

    pub fn payload_plain_hash(&self) -> &Hash256 {
        &self.envelope.payload_plain_hash
    }

    pub fn agent_signature(&self) -> &Signature64 {
        &self.envelope.agent_signature
    }

    /// Compute the signing hash (needed for Merkle leaf)
    pub fn compute_signing_hash(&self) -> Hash256 {
        self.envelope.compute_signing_hash()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AgentSigningKey;

    #[test]
    fn test_plaintext_event_creation() {
        let signing_key = AgentSigningKey::generate();

        let envelope = VesEventEnvelope::new_plaintext(
            TenantId::new(),
            StoreId::new(),
            AgentId::new(),
            AgentKeyId::default(),
            EntityType::order(),
            "order-123",
            EventType::from(EventType::ORDER_CREATED),
            serde_json::json!({"customer_id": "cust-456", "amount": 100}),
            &signing_key,
        );

        assert_eq!(envelope.ves_version, 1);
        assert!(envelope.is_plaintext());
        assert!(envelope.payload.is_some());
        assert!(envelope.payload_encrypted.is_none());
        assert_eq!(envelope.payload_cipher_hash, ZERO_HASH);

        // Verify payload hash
        assert!(envelope.verify_payload_hash());

        // Verify signature
        let verifying_key = signing_key.public_key();
        assert!(envelope.verify_signature(&verifying_key).is_ok());
    }

    #[test]
    fn test_signature_verification() {
        let signing_key = AgentSigningKey::generate();
        let wrong_key = AgentSigningKey::generate();

        let envelope = VesEventEnvelope::new_plaintext(
            TenantId::new(),
            StoreId::new(),
            AgentId::new(),
            AgentKeyId::default(),
            EntityType::order(),
            "order-123",
            EventType::from(EventType::ORDER_CREATED),
            serde_json::json!({"test": true}),
            &signing_key,
        );

        // Correct key should verify
        let verifying_key = signing_key.public_key();
        assert!(envelope.verify_signature(&verifying_key).is_ok());

        // Wrong key should fail
        let wrong_verifying_key = wrong_key.public_key();
        assert!(envelope.verify_signature(&wrong_verifying_key).is_err());
    }

    #[test]
    fn test_sequenced_event() {
        let signing_key = AgentSigningKey::generate();

        let envelope = VesEventEnvelope::new_plaintext(
            TenantId::new(),
            StoreId::new(),
            AgentId::new(),
            AgentKeyId::default(),
            EntityType::inventory(),
            "inv-001",
            EventType::from(EventType::INVENTORY_ADJUSTED),
            serde_json::json!({"delta": 10}),
            &signing_key,
        );

        let sequenced = SequencedVesEvent::new(envelope, 42);
        assert_eq!(sequenced.sequence_number(), 42);
        assert!(sequenced.envelope.sequenced_at.is_some());
    }

    #[test]
    fn test_event_serialization() {
        let signing_key = AgentSigningKey::generate();

        let envelope = VesEventEnvelope::new_plaintext(
            TenantId::new(),
            StoreId::new(),
            AgentId::new(),
            AgentKeyId::default(),
            EntityType::order(),
            "order-123",
            EventType::from(EventType::ORDER_CREATED),
            serde_json::json!({"test": true}),
            &signing_key,
        );

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&envelope).unwrap();
        println!("Serialized event:\n{}", json);

        // Verify 0x prefixes are present
        assert!(json.contains("\"payload_plain_hash\": \"0x"));
        assert!(json.contains("\"payload_cipher_hash\": \"0x"));
        assert!(json.contains("\"agent_signature\": \"0x"));

        // Deserialize back
        let deserialized: VesEventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_id, envelope.event_id);
        assert_eq!(deserialized.payload_plain_hash, envelope.payload_plain_hash);
        assert_eq!(deserialized.agent_signature, envelope.agent_signature);
    }
}
