//! Core type definitions for StateSet Sequencer
//!
//! VES v1.0 compliant types for event envelopes, signatures, and encryption.

use serde::{Deserialize, Serialize};
use std::fmt;

/// VES specification version
pub const VES_VERSION: u32 = 1;

/// 32-byte hash (SHA-256)
pub type Hash256 = [u8; 32];

/// 64-byte Ed25519 signature
pub type Signature64 = [u8; 64];

/// 32-byte Ed25519 public key
pub type PublicKey32 = [u8; 32];

/// 32-byte X25519 public key (for encryption)
pub type EncryptionPublicKey = [u8; 32];

/// Payload kind indicator per VES v1.0
/// 0 = plaintext payload, 1 = encrypted payload
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde_repr::Serialize_repr, serde_repr::Deserialize_repr,
)]
#[repr(u32)]
pub enum PayloadKind {
    /// Plaintext payload (payload field present, payload_encrypted absent)
    Plaintext = 0,
    /// Encrypted payload (payload absent/null, payload_encrypted present)
    Encrypted = 1,
}

impl PayloadKind {
    pub fn as_u32(&self) -> u32 {
        match self {
            PayloadKind::Plaintext => 0,
            PayloadKind::Encrypted => 1,
        }
    }

    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(PayloadKind::Plaintext),
            1 => Some(PayloadKind::Encrypted),
            _ => None,
        }
    }
}

impl Default for PayloadKind {
    fn default() -> Self {
        PayloadKind::Plaintext
    }
}

/// Agent key identifier for key rotation
/// Each agent can have multiple signing keys identified by this ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentKeyId(pub u32);

impl AgentKeyId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl Default for AgentKeyId {
    fn default() -> Self {
        Self(1)
    }
}

impl fmt::Display for AgentKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Recipient key identifier for encryption key management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecipientKeyId(pub u32);

impl RecipientKeyId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for RecipientKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Serde module for serializing Hash256 as hex strings
pub mod hash256_hex {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes for Hash256"))
    }
}

/// Serde module for optional Hash256 as hex strings
pub mod option_hash256_hex {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes for Hash256"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

/// Serde module for Hash256 with 0x prefix (VES v1.0 compliant)
pub mod hash256_hex_0x {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes for Hash256"))
    }
}

/// Serde module for Signature64 (64-byte Ed25519) with 0x prefix
pub mod signature64_hex_0x {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes for Signature64"))
    }
}

/// Serde module for optional Signature64 with 0x prefix
pub mod option_signature64_hex_0x {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&format!("0x{}", hex::encode(bytes))),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let hex_str = s.strip_prefix("0x").unwrap_or(&s);
                let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
                let arr: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 64 bytes for Signature64"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

/// Serde module for PublicKey32 (32-byte Ed25519 public key) with 0x prefix
pub mod pubkey32_hex_0x {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes for PublicKey32"))
    }
}

/// Tenant identifier (organization/account level)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub uuid::Uuid);

impl TenantId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id)
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Store identifier (within a tenant)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StoreId(pub uuid::Uuid);

impl StoreId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id)
    }
}

impl Default for StoreId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for StoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Agent identifier (source of events)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub uuid::Uuid);

impl AgentId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id)
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Entity type classification
/// Uses a simple string wrapper that handles both known and custom types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityType(pub String);

impl EntityType {
    pub fn new(entity_type: impl Into<String>) -> Self {
        Self(entity_type.into())
    }

    pub fn order() -> Self {
        Self("order".to_string())
    }

    pub fn product() -> Self {
        Self("product".to_string())
    }

    pub fn inventory() -> Self {
        Self("inventory".to_string())
    }

    pub fn customer() -> Self {
        Self("customer".to_string())
    }

    pub fn return_type() -> Self {
        Self("return".to_string())
    }

    pub fn payment() -> Self {
        Self("payment".to_string())
    }

    pub fn shipment() -> Self {
        Self("shipment".to_string())
    }
}

impl EntityType {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for EntityType {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for EntityType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Event type classification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventType(pub String);

impl EventType {
    pub fn new(event_type: impl Into<String>) -> Self {
        Self(event_type.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    // Common event types
    pub const ORDER_CREATED: &'static str = "order.created";
    pub const ORDER_SUBMITTED: &'static str = "order.submitted";
    pub const ORDER_CONFIRMED: &'static str = "order.confirmed";
    pub const ORDER_FULFILLED: &'static str = "order.fulfilled";
    pub const ORDER_CANCELLED: &'static str = "order.cancelled";
    pub const ORDER_REFUNDED: &'static str = "order.refunded";

    pub const PRODUCT_CREATED: &'static str = "product.created";
    pub const PRODUCT_UPDATED: &'static str = "product.updated";
    pub const PRODUCT_ARCHIVED: &'static str = "product.archived";

    pub const INVENTORY_ADJUSTED: &'static str = "inventory.adjusted";
    pub const INVENTORY_RESERVED: &'static str = "inventory.reserved";
    pub const INVENTORY_RESERVATION_CONFIRMED: &'static str = "inventory.reservation_confirmed";
    pub const INVENTORY_RESERVATION_RELEASED: &'static str = "inventory.reservation_released";

    pub const CUSTOMER_CREATED: &'static str = "customer.created";
    pub const CUSTOMER_UPDATED: &'static str = "customer.updated";

    pub const RETURN_REQUESTED: &'static str = "return.requested";
    pub const RETURN_APPROVED: &'static str = "return.approved";
    pub const RETURN_RECEIVED: &'static str = "return.received";
    pub const RETURN_REFUNDED: &'static str = "return.refunded";
    pub const RETURN_REJECTED: &'static str = "return.rejected";

    // System events (emitted by projector)
    pub const EVENT_REJECTED: &'static str = "event.rejected";
    pub const OPERATION_FAILED: &'static str = "operation.failed";
    pub const PROJECTION_CHECKPOINT: &'static str = "projection.checkpoint";
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for EventType {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for EventType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // PayloadKind Tests
    // ============================================================================

    #[test]
    fn test_payload_kind_as_u32() {
        assert_eq!(PayloadKind::Plaintext.as_u32(), 0);
        assert_eq!(PayloadKind::Encrypted.as_u32(), 1);
    }

    #[test]
    fn test_payload_kind_from_u32() {
        assert_eq!(PayloadKind::from_u32(0), Some(PayloadKind::Plaintext));
        assert_eq!(PayloadKind::from_u32(1), Some(PayloadKind::Encrypted));
        assert_eq!(PayloadKind::from_u32(2), None);
        assert_eq!(PayloadKind::from_u32(999), None);
    }

    #[test]
    fn test_payload_kind_default() {
        assert_eq!(PayloadKind::default(), PayloadKind::Plaintext);
    }

    #[test]
    fn test_payload_kind_serialization() {
        let plaintext = PayloadKind::Plaintext;
        let encrypted = PayloadKind::Encrypted;

        let json_plain = serde_json::to_string(&plaintext).unwrap();
        let json_enc = serde_json::to_string(&encrypted).unwrap();

        assert_eq!(json_plain, "0");
        assert_eq!(json_enc, "1");

        let parsed_plain: PayloadKind = serde_json::from_str(&json_plain).unwrap();
        let parsed_enc: PayloadKind = serde_json::from_str(&json_enc).unwrap();

        assert_eq!(parsed_plain, PayloadKind::Plaintext);
        assert_eq!(parsed_enc, PayloadKind::Encrypted);
    }

    // ============================================================================
    // AgentKeyId Tests
    // ============================================================================

    #[test]
    fn test_agent_key_id_new() {
        let key_id = AgentKeyId::new(42);
        assert_eq!(key_id.as_u32(), 42);
        assert_eq!(key_id.0, 42);
    }

    #[test]
    fn test_agent_key_id_default() {
        let key_id = AgentKeyId::default();
        assert_eq!(key_id.as_u32(), 1);
    }

    #[test]
    fn test_agent_key_id_display() {
        let key_id = AgentKeyId::new(123);
        assert_eq!(format!("{}", key_id), "123");
    }

    #[test]
    fn test_agent_key_id_serialization() {
        let key_id = AgentKeyId::new(456);
        let json = serde_json::to_string(&key_id).unwrap();
        let parsed: AgentKeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(key_id, parsed);
    }

    // ============================================================================
    // RecipientKeyId Tests
    // ============================================================================

    #[test]
    fn test_recipient_key_id_new() {
        let key_id = RecipientKeyId::new(99);
        assert_eq!(key_id.as_u32(), 99);
        assert_eq!(key_id.0, 99);
    }

    #[test]
    fn test_recipient_key_id_display() {
        let key_id = RecipientKeyId::new(789);
        assert_eq!(format!("{}", key_id), "789");
    }

    // ============================================================================
    // TenantId Tests
    // ============================================================================

    #[test]
    fn test_tenant_id_new_generates_unique() {
        let id1 = TenantId::new();
        let id2 = TenantId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_tenant_id_from_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let tenant_id = TenantId::from_uuid(uuid);
        assert_eq!(tenant_id.0, uuid);
    }

    #[test]
    fn test_tenant_id_default() {
        let id1 = TenantId::default();
        let id2 = TenantId::default();
        // Default creates new UUIDs each time
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_tenant_id_display() {
        let uuid = uuid::Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let tenant_id = TenantId::from_uuid(uuid);
        assert_eq!(format!("{}", tenant_id), "12345678-1234-1234-1234-123456789abc");
    }

    #[test]
    fn test_tenant_id_serialization() {
        let tenant_id = TenantId::new();
        let json = serde_json::to_string(&tenant_id).unwrap();
        let parsed: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(tenant_id, parsed);
    }

    #[test]
    fn test_tenant_id_hash() {
        use std::collections::HashSet;
        let id1 = TenantId::new();
        let id2 = id1.clone();
        let id3 = TenantId::new();

        let mut set = HashSet::new();
        set.insert(id1.clone());
        set.insert(id2.clone());
        set.insert(id3.clone());

        assert_eq!(set.len(), 2); // id1 and id2 are equal
        assert!(set.contains(&id1));
        assert!(set.contains(&id3));
    }

    // ============================================================================
    // StoreId Tests
    // ============================================================================

    #[test]
    fn test_store_id_new_generates_unique() {
        let id1 = StoreId::new();
        let id2 = StoreId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_store_id_from_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let store_id = StoreId::from_uuid(uuid);
        assert_eq!(store_id.0, uuid);
    }

    #[test]
    fn test_store_id_display() {
        let uuid = uuid::Uuid::parse_str("abcdef12-3456-7890-abcd-ef1234567890").unwrap();
        let store_id = StoreId::from_uuid(uuid);
        assert_eq!(format!("{}", store_id), "abcdef12-3456-7890-abcd-ef1234567890");
    }

    // ============================================================================
    // AgentId Tests
    // ============================================================================

    #[test]
    fn test_agent_id_new_generates_unique() {
        let id1 = AgentId::new();
        let id2 = AgentId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_agent_id_from_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let agent_id = AgentId::from_uuid(uuid);
        assert_eq!(agent_id.0, uuid);
    }

    #[test]
    fn test_agent_id_display() {
        let uuid = uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let agent_id = AgentId::from_uuid(uuid);
        assert_eq!(format!("{}", agent_id), "11111111-2222-3333-4444-555555555555");
    }

    // ============================================================================
    // EntityType Tests
    // ============================================================================

    #[test]
    fn test_entity_type_new() {
        let et = EntityType::new("custom_entity");
        assert_eq!(et.as_str(), "custom_entity");
    }

    #[test]
    fn test_entity_type_factory_methods() {
        assert_eq!(EntityType::order().as_str(), "order");
        assert_eq!(EntityType::product().as_str(), "product");
        assert_eq!(EntityType::inventory().as_str(), "inventory");
        assert_eq!(EntityType::customer().as_str(), "customer");
        assert_eq!(EntityType::return_type().as_str(), "return");
        assert_eq!(EntityType::payment().as_str(), "payment");
        assert_eq!(EntityType::shipment().as_str(), "shipment");
    }

    #[test]
    fn test_entity_type_from_str() {
        let et: EntityType = "my_entity".into();
        assert_eq!(et.as_str(), "my_entity");
    }

    #[test]
    fn test_entity_type_from_string() {
        let et: EntityType = String::from("another_entity").into();
        assert_eq!(et.as_str(), "another_entity");
    }

    #[test]
    fn test_entity_type_display() {
        let et = EntityType::order();
        assert_eq!(format!("{}", et), "order");
    }

    #[test]
    fn test_entity_type_equality() {
        let et1 = EntityType::order();
        let et2 = EntityType::new("order");
        let et3 = EntityType::product();

        assert_eq!(et1, et2);
        assert_ne!(et1, et3);
    }

    #[test]
    fn test_entity_type_serialization() {
        let et = EntityType::order();
        let json = serde_json::to_string(&et).unwrap();
        assert_eq!(json, "\"order\"");

        let parsed: EntityType = serde_json::from_str(&json).unwrap();
        assert_eq!(et, parsed);
    }

    // ============================================================================
    // EventType Tests
    // ============================================================================

    #[test]
    fn test_event_type_new() {
        let et = EventType::new("custom.event");
        assert_eq!(et.as_str(), "custom.event");
    }

    #[test]
    fn test_event_type_constants() {
        assert_eq!(EventType::ORDER_CREATED, "order.created");
        assert_eq!(EventType::ORDER_SUBMITTED, "order.submitted");
        assert_eq!(EventType::ORDER_CONFIRMED, "order.confirmed");
        assert_eq!(EventType::ORDER_FULFILLED, "order.fulfilled");
        assert_eq!(EventType::ORDER_CANCELLED, "order.cancelled");
        assert_eq!(EventType::ORDER_REFUNDED, "order.refunded");

        assert_eq!(EventType::PRODUCT_CREATED, "product.created");
        assert_eq!(EventType::PRODUCT_UPDATED, "product.updated");
        assert_eq!(EventType::PRODUCT_ARCHIVED, "product.archived");

        assert_eq!(EventType::INVENTORY_ADJUSTED, "inventory.adjusted");
        assert_eq!(EventType::INVENTORY_RESERVED, "inventory.reserved");

        assert_eq!(EventType::CUSTOMER_CREATED, "customer.created");
        assert_eq!(EventType::CUSTOMER_UPDATED, "customer.updated");

        assert_eq!(EventType::RETURN_REQUESTED, "return.requested");
        assert_eq!(EventType::RETURN_APPROVED, "return.approved");

        assert_eq!(EventType::EVENT_REJECTED, "event.rejected");
        assert_eq!(EventType::OPERATION_FAILED, "operation.failed");
    }

    #[test]
    fn test_event_type_from_str() {
        let et: EventType = "my.event".into();
        assert_eq!(et.as_str(), "my.event");
    }

    #[test]
    fn test_event_type_from_string() {
        let et: EventType = String::from("another.event").into();
        assert_eq!(et.as_str(), "another.event");
    }

    #[test]
    fn test_event_type_display() {
        let et = EventType::new("test.event");
        assert_eq!(format!("{}", et), "test.event");
    }

    #[test]
    fn test_event_type_serialization() {
        let et = EventType::from(EventType::ORDER_CREATED);
        let json = serde_json::to_string(&et).unwrap();
        assert_eq!(json, "\"order.created\"");

        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(et, parsed);
    }

    // ============================================================================
    // Hash256 Hex Serde Tests
    // ============================================================================

    #[test]
    fn test_hash256_hex_roundtrip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "hash256_hex")]
            hash: Hash256,
        }

        let original = TestStruct {
            hash: [0xab; 32],
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("abababab")); // hex encoded

        let parsed: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_option_hash256_hex_some() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "option_hash256_hex")]
            hash: Option<Hash256>,
        }

        let with_hash = TestStruct {
            hash: Some([0xcd; 32]),
        };

        let json = serde_json::to_string(&with_hash).unwrap();
        let parsed: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(with_hash, parsed);
    }

    #[test]
    fn test_option_hash256_hex_none() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "option_hash256_hex")]
            hash: Option<Hash256>,
        }

        let without_hash = TestStruct { hash: None };

        let json = serde_json::to_string(&without_hash).unwrap();
        let parsed: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(without_hash, parsed);
    }

    #[test]
    fn test_hash256_hex_0x_roundtrip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "hash256_hex_0x")]
            hash: Hash256,
        }

        let original = TestStruct {
            hash: [0xef; 32],
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("0x")); // has 0x prefix

        let parsed: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_hash256_hex_0x_accepts_without_prefix() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "hash256_hex_0x")]
            hash: Hash256,
        }

        // Deserialize without 0x prefix should still work
        let json = r#"{"hash":"0101010101010101010101010101010101010101010101010101010101010101"}"#;
        let parsed: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.hash, [0x01; 32]);
    }

    // ============================================================================
    // Signature64 Hex Serde Tests
    // ============================================================================

    #[test]
    fn test_signature64_hex_0x_roundtrip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "signature64_hex_0x")]
            sig: Signature64,
        }

        let original = TestStruct {
            sig: [0x42; 64],
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("0x")); // has 0x prefix

        let parsed: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_option_signature64_hex_0x() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "option_signature64_hex_0x")]
            sig: Option<Signature64>,
        }

        let with_sig = TestStruct {
            sig: Some([0x99; 64]),
        };
        let without_sig = TestStruct { sig: None };

        let json_with = serde_json::to_string(&with_sig).unwrap();
        let json_without = serde_json::to_string(&without_sig).unwrap();

        let parsed_with: TestStruct = serde_json::from_str(&json_with).unwrap();
        let parsed_without: TestStruct = serde_json::from_str(&json_without).unwrap();

        assert_eq!(with_sig, parsed_with);
        assert_eq!(without_sig, parsed_without);
    }

    // ============================================================================
    // PublicKey32 Hex Serde Tests
    // ============================================================================

    #[test]
    fn test_pubkey32_hex_0x_roundtrip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "pubkey32_hex_0x")]
            key: PublicKey32,
        }

        let original = TestStruct {
            key: [0x77; 32],
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("0x"));

        let parsed: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    // ============================================================================
    // Error Cases for Hex Deserialization
    // ============================================================================

    #[test]
    fn test_hash256_hex_invalid_length() {
        #[derive(serde::Deserialize)]
        struct TestStruct {
            #[serde(with = "hash256_hex")]
            #[allow(dead_code)]
            hash: Hash256,
        }

        // Too short
        let json = r#"{"hash":"abcd"}"#;
        assert!(serde_json::from_str::<TestStruct>(json).is_err());

        // Too long
        let json = r#"{"hash":"abababababababababababababababababababababababababababababababababab"}"#;
        assert!(serde_json::from_str::<TestStruct>(json).is_err());
    }

    #[test]
    fn test_hash256_hex_invalid_chars() {
        #[derive(serde::Deserialize)]
        struct TestStruct {
            #[serde(with = "hash256_hex")]
            #[allow(dead_code)]
            hash: Hash256,
        }

        let json = r#"{"hash":"ghghghghghghghghghghghghghghghghghghghghghghghghghghghghghghghgh"}"#;
        assert!(serde_json::from_str::<TestStruct>(json).is_err());
    }
}
