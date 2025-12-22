//! Agent Key Registry for VES v1.0
//!
//! Per VES v1.0 Section 9, a conforming deployment MUST provide a registry mapping:
//! (tenant_id, source_agent_id, agent_key_id) -> public_key + status + validity window
//!
//! This module provides:
//! - AgentKeyRegistry trait for key management
//! - InMemoryAgentKeyRegistry for development/testing
//! - Key status and lifecycle management

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::crypto::{AgentVerifyingKey, PublicKey32, SigningError};
use crate::domain::{AgentId, AgentKeyId, TenantId};

/// Status of an agent signing key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Key is active and can be used for signing
    Active,
    /// Key has been revoked and should not accept new signatures
    Revoked,
    /// Key has expired
    Expired,
    /// Key is not yet valid (valid_from in the future)
    NotYetValid,
}

/// Agent key entry in the registry
#[derive(Debug, Clone)]
pub struct AgentKeyEntry {
    /// The Ed25519 public key bytes
    pub public_key: PublicKey32,

    /// Current status of the key
    pub status: KeyStatus,

    /// When the key becomes valid (None = immediately valid)
    pub valid_from: Option<DateTime<Utc>>,

    /// When the key expires (None = never expires)
    pub valid_to: Option<DateTime<Utc>>,

    /// When the key was revoked (if revoked)
    pub revoked_at: Option<DateTime<Utc>>,

    /// Key metadata (description, purpose, etc.)
    pub metadata: Option<String>,

    /// When the key was registered
    pub created_at: DateTime<Utc>,
}

impl AgentKeyEntry {
    /// Create a new active key entry
    pub fn new(public_key: PublicKey32) -> Self {
        Self {
            public_key,
            status: KeyStatus::Active,
            valid_from: None,
            valid_to: None,
            revoked_at: None,
            metadata: None,
            created_at: Utc::now(),
        }
    }

    /// Create a key entry with validity window
    pub fn with_validity(
        public_key: PublicKey32,
        valid_from: DateTime<Utc>,
        valid_to: DateTime<Utc>,
    ) -> Self {
        Self {
            public_key,
            status: KeyStatus::Active,
            valid_from: Some(valid_from),
            valid_to: Some(valid_to),
            revoked_at: None,
            metadata: None,
            created_at: Utc::now(),
        }
    }

    /// Check if the key is valid at the given time
    pub fn is_valid_at(&self, at: DateTime<Utc>) -> bool {
        if self.status == KeyStatus::Revoked {
            return false;
        }

        if let Some(valid_from) = self.valid_from {
            if at < valid_from {
                return false;
            }
        }

        if let Some(valid_to) = self.valid_to {
            if at > valid_to {
                return false;
            }
        }

        if let Some(revoked_at) = self.revoked_at {
            if at >= revoked_at {
                return false;
            }
        }

        true
    }

    /// Get the computed status at a given time
    pub fn status_at(&self, at: DateTime<Utc>) -> KeyStatus {
        if self.status == KeyStatus::Revoked {
            return KeyStatus::Revoked;
        }

        if let Some(valid_from) = self.valid_from {
            if at < valid_from {
                return KeyStatus::NotYetValid;
            }
        }

        if let Some(valid_to) = self.valid_to {
            if at > valid_to {
                return KeyStatus::Expired;
            }
        }

        if let Some(revoked_at) = self.revoked_at {
            if at >= revoked_at {
                return KeyStatus::Revoked;
            }
        }

        KeyStatus::Active
    }
}

/// Error type for agent key operations
#[derive(Debug, thiserror::Error)]
pub enum AgentKeyError {
    #[error("key not found for tenant {tenant_id}, agent {agent_id}, key_id {key_id}")]
    KeyNotFound {
        tenant_id: Uuid,
        agent_id: Uuid,
        key_id: u32,
    },

    #[error("key has been revoked")]
    KeyRevoked,

    #[error("key has expired")]
    KeyExpired,

    #[error("key is not yet valid")]
    KeyNotYetValid,

    #[error("key already exists")]
    KeyAlreadyExists,

    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(#[from] SigningError),

    #[error("internal error: {0}")]
    Internal(String),
}

/// Key lookup identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentKeyLookup {
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub key_id: u32,
}

impl AgentKeyLookup {
    pub fn new(tenant_id: &TenantId, agent_id: &AgentId, key_id: AgentKeyId) -> Self {
        Self {
            tenant_id: tenant_id.0,
            agent_id: agent_id.0,
            key_id: key_id.0,
        }
    }
}

/// Agent Key Registry trait per VES v1.0 Section 9
///
/// Implementations must provide key lookup and management operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait AgentKeyRegistry: Send + Sync {
    /// Get the public key for a (tenant, agent, key_id) triple
    ///
    /// Returns the key entry if found and valid
    async fn get_key(&self, lookup: &AgentKeyLookup) -> Result<AgentKeyEntry, AgentKeyError>;

    /// Get the public key and verify it's valid at a specific time
    ///
    /// Per VES v1.0 Section 9.2, evaluates validity against the provided timestamp.
    /// For sequencer validation, this should be `sequenced_at` time.
    async fn get_valid_key_at(
        &self,
        lookup: &AgentKeyLookup,
        at: DateTime<Utc>,
    ) -> Result<AgentKeyEntry, AgentKeyError>;

    /// Register a new agent public key
    ///
    /// key_id should be incrementing for key rotation
    async fn register_key(
        &self,
        lookup: &AgentKeyLookup,
        entry: AgentKeyEntry,
    ) -> Result<(), AgentKeyError>;

    /// Revoke an agent key
    ///
    /// After revocation, events signed with this key should be rejected.
    async fn revoke_key(&self, lookup: &AgentKeyLookup) -> Result<(), AgentKeyError>;

    /// List all keys for an agent
    async fn list_agent_keys(
        &self,
        tenant_id: &Uuid,
        agent_id: &Uuid,
    ) -> Result<Vec<(u32, AgentKeyEntry)>, AgentKeyError>;

    /// Get the verifying key for signature verification
    async fn get_verifying_key(
        &self,
        lookup: &AgentKeyLookup,
    ) -> Result<AgentVerifyingKey, AgentKeyError> {
        let entry = self.get_key(lookup).await?;
        AgentVerifyingKey::from_bytes(&entry.public_key)
            .map_err(|e| AgentKeyError::SignatureVerificationFailed(e))
    }

    /// Get the verifying key valid at a specific time
    async fn get_verifying_key_at(
        &self,
        lookup: &AgentKeyLookup,
        at: DateTime<Utc>,
    ) -> Result<AgentVerifyingKey, AgentKeyError> {
        let entry = self.get_valid_key_at(lookup, at).await?;
        AgentVerifyingKey::from_bytes(&entry.public_key)
            .map_err(|e| AgentKeyError::SignatureVerificationFailed(e))
    }
}

/// In-memory agent key registry for development and testing
///
/// DO NOT USE IN PRODUCTION - keys should be stored in a secure database
/// or KMS with proper access controls.
pub struct InMemoryAgentKeyRegistry {
    keys: RwLock<HashMap<AgentKeyLookup, AgentKeyEntry>>,
}

impl InMemoryAgentKeyRegistry {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Create with pre-registered keys (for testing)
    pub fn with_keys(keys: Vec<(AgentKeyLookup, AgentKeyEntry)>) -> Self {
        let registry = Self::new();
        {
            let mut map = registry.keys.write().unwrap();
            for (lookup, entry) in keys {
                map.insert(lookup, entry);
            }
        }
        registry
    }
}

impl Default for InMemoryAgentKeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AgentKeyRegistry for InMemoryAgentKeyRegistry {
    async fn get_key(&self, lookup: &AgentKeyLookup) -> Result<AgentKeyEntry, AgentKeyError> {
        let keys = self.keys.read().unwrap();
        keys.get(lookup)
            .cloned()
            .ok_or_else(|| AgentKeyError::KeyNotFound {
                tenant_id: lookup.tenant_id,
                agent_id: lookup.agent_id,
                key_id: lookup.key_id,
            })
    }

    async fn get_valid_key_at(
        &self,
        lookup: &AgentKeyLookup,
        at: DateTime<Utc>,
    ) -> Result<AgentKeyEntry, AgentKeyError> {
        let entry = self.get_key(lookup).await?;

        match entry.status_at(at) {
            KeyStatus::Active => Ok(entry),
            KeyStatus::Revoked => Err(AgentKeyError::KeyRevoked),
            KeyStatus::Expired => Err(AgentKeyError::KeyExpired),
            KeyStatus::NotYetValid => Err(AgentKeyError::KeyNotYetValid),
        }
    }

    async fn register_key(
        &self,
        lookup: &AgentKeyLookup,
        entry: AgentKeyEntry,
    ) -> Result<(), AgentKeyError> {
        let mut keys = self.keys.write().unwrap();
        if keys.contains_key(lookup) {
            return Err(AgentKeyError::KeyAlreadyExists);
        }
        keys.insert(lookup.clone(), entry);
        Ok(())
    }

    async fn revoke_key(&self, lookup: &AgentKeyLookup) -> Result<(), AgentKeyError> {
        let mut keys = self.keys.write().unwrap();
        let entry = keys
            .get_mut(lookup)
            .ok_or_else(|| AgentKeyError::KeyNotFound {
                tenant_id: lookup.tenant_id,
                agent_id: lookup.agent_id,
                key_id: lookup.key_id,
            })?;

        entry.status = KeyStatus::Revoked;
        entry.revoked_at = Some(Utc::now());
        Ok(())
    }

    async fn list_agent_keys(
        &self,
        tenant_id: &Uuid,
        agent_id: &Uuid,
    ) -> Result<Vec<(u32, AgentKeyEntry)>, AgentKeyError> {
        let keys = self.keys.read().unwrap();
        let result: Vec<_> = keys
            .iter()
            .filter(|(lookup, _)| lookup.tenant_id == *tenant_id && lookup.agent_id == *agent_id)
            .map(|(lookup, entry)| (lookup.key_id, entry.clone()))
            .collect();
        Ok(result)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AgentSigningKey;

    #[tokio::test]
    async fn test_register_and_get_key() {
        let registry = InMemoryAgentKeyRegistry::new();

        let signing_key = AgentSigningKey::generate();
        let public_key = signing_key.public_key_bytes();

        let lookup = AgentKeyLookup {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            key_id: 1,
        };

        let entry = AgentKeyEntry::new(public_key);
        registry.register_key(&lookup, entry.clone()).await.unwrap();

        let retrieved = registry.get_key(&lookup).await.unwrap();
        assert_eq!(retrieved.public_key, public_key);
        assert_eq!(retrieved.status, KeyStatus::Active);
    }

    #[tokio::test]
    async fn test_key_not_found() {
        let registry = InMemoryAgentKeyRegistry::new();

        let lookup = AgentKeyLookup {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            key_id: 1,
        };

        let result = registry.get_key(&lookup).await;
        assert!(matches!(result, Err(AgentKeyError::KeyNotFound { .. })));
    }

    #[tokio::test]
    async fn test_key_revocation() {
        let registry = InMemoryAgentKeyRegistry::new();

        let signing_key = AgentSigningKey::generate();
        let lookup = AgentKeyLookup {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            key_id: 1,
        };

        let entry = AgentKeyEntry::new(signing_key.public_key_bytes());
        registry.register_key(&lookup, entry).await.unwrap();

        // Key should be valid
        let result = registry.get_valid_key_at(&lookup, Utc::now()).await;
        assert!(result.is_ok());

        // Revoke the key
        registry.revoke_key(&lookup).await.unwrap();

        // Key should now be invalid
        let result = registry.get_valid_key_at(&lookup, Utc::now()).await;
        assert!(matches!(result, Err(AgentKeyError::KeyRevoked)));
    }

    #[tokio::test]
    async fn test_key_validity_window() {
        let registry = InMemoryAgentKeyRegistry::new();

        let signing_key = AgentSigningKey::generate();
        let lookup = AgentKeyLookup {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            key_id: 1,
        };

        let now = Utc::now();
        let valid_from = now + chrono::Duration::hours(1);
        let valid_to = now + chrono::Duration::hours(2);

        let entry =
            AgentKeyEntry::with_validity(signing_key.public_key_bytes(), valid_from, valid_to);
        registry.register_key(&lookup, entry).await.unwrap();

        // Key should not be valid yet
        let result = registry.get_valid_key_at(&lookup, now).await;
        assert!(matches!(result, Err(AgentKeyError::KeyNotYetValid)));

        // Key should be valid during window
        let during = valid_from + chrono::Duration::minutes(30);
        let result = registry.get_valid_key_at(&lookup, during).await;
        assert!(result.is_ok());

        // Key should be expired after window
        let after = valid_to + chrono::Duration::hours(1);
        let result = registry.get_valid_key_at(&lookup, after).await;
        assert!(matches!(result, Err(AgentKeyError::KeyExpired)));
    }

    #[tokio::test]
    async fn test_list_agent_keys() {
        let registry = InMemoryAgentKeyRegistry::new();

        let tenant_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();

        // Register multiple keys for same agent
        for key_id in 1..=3 {
            let signing_key = AgentSigningKey::generate();
            let lookup = AgentKeyLookup {
                tenant_id,
                agent_id,
                key_id,
            };
            let entry = AgentKeyEntry::new(signing_key.public_key_bytes());
            registry.register_key(&lookup, entry).await.unwrap();
        }

        let keys = registry
            .list_agent_keys(&tenant_id, &agent_id)
            .await
            .unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[tokio::test]
    async fn test_get_verifying_key() {
        let registry = InMemoryAgentKeyRegistry::new();

        let signing_key = AgentSigningKey::generate();
        let lookup = AgentKeyLookup {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            key_id: 1,
        };

        let entry = AgentKeyEntry::new(signing_key.public_key_bytes());
        registry.register_key(&lookup, entry).await.unwrap();

        let verifying_key = registry.get_verifying_key(&lookup).await.unwrap();

        // Test signature verification
        let message = [42u8; 32];
        let signature = signing_key.sign(&message);
        assert!(verifying_key.verify(&message, &signature).is_ok());
    }
}
