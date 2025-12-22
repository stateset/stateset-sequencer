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
