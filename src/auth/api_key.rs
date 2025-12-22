//! API Key authentication
//!
//! Simple API key authentication for Phase 0.
//! Keys are formatted as: `ss_<tenant_prefix>_<random>`

use super::{AuthContext, AuthError, Permissions};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

/// API key prefix
pub const API_KEY_PREFIX: &str = "ss_";

/// API key metadata stored in database
#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    /// Hash of the API key (never store plaintext)
    pub key_hash: String,

    /// Tenant this key belongs to
    pub tenant_id: Uuid,

    /// Stores this key can access (empty = all)
    pub store_ids: Vec<Uuid>,

    /// Permissions granted by this key
    pub permissions: Permissions,

    /// Optional agent ID for agent-specific keys
    pub agent_id: Option<Uuid>,

    /// Whether the key is active
    pub active: bool,

    /// Rate limit (requests per minute)
    pub rate_limit: Option<u32>,
}

/// API key validator
pub struct ApiKeyValidator {
    /// In-memory key store (for development)
    /// In production, this would query the database
    keys: RwLock<HashMap<String, ApiKeyRecord>>,
}

impl ApiKeyValidator {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a new API key
    ///
    /// Returns (plaintext_key, key_hash)
    pub fn generate_key(tenant_id: &Uuid) -> (String, String) {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Generate random bytes
        let random_bytes: [u8; 24] = rng.gen();
        let random_part = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            random_bytes,
        );

        // Create key with prefix and tenant hint
        let tenant_prefix = &tenant_id.to_string()[..8];
        let plaintext_key = format!("{}{}{}", API_KEY_PREFIX, tenant_prefix, random_part);

        // Hash for storage
        let key_hash = Self::hash_key(&plaintext_key);

        (plaintext_key, key_hash)
    }

    /// Hash an API key for storage
    pub fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Register a new API key
    pub fn register_key(&self, record: ApiKeyRecord) {
        let mut keys = self.keys.write().unwrap();
        keys.insert(record.key_hash.clone(), record);
    }

    /// Validate an API key and return auth context
    pub fn validate(&self, key: &str) -> Result<AuthContext, AuthError> {
        // Check key format
        if !key.starts_with(API_KEY_PREFIX) {
            return Err(AuthError::InvalidApiKey);
        }

        // Hash the key
        let key_hash = Self::hash_key(key);

        // Look up the key
        let keys = self.keys.read().unwrap();
        let record = keys.get(&key_hash).ok_or(AuthError::InvalidApiKey)?;

        // Check if key is active
        if !record.active {
            return Err(AuthError::InvalidApiKey);
        }

        Ok(AuthContext {
            tenant_id: record.tenant_id,
            store_ids: record.store_ids.clone(),
            agent_id: record.agent_id,
            permissions: record.permissions.clone(),
        })
    }

    /// Revoke an API key
    pub fn revoke(&self, key_hash: &str) {
        let mut keys = self.keys.write().unwrap();
        if let Some(record) = keys.get_mut(key_hash) {
            record.active = false;
        }
    }
}

impl Default for ApiKeyValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Database-backed API key store trait
#[async_trait::async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Get API key record by hash
    async fn get_by_hash(&self, key_hash: &str) -> Result<Option<ApiKeyRecord>, AuthError>;

    /// Store a new API key record
    async fn store(&self, record: &ApiKeyRecord) -> Result<(), AuthError>;

    /// Revoke an API key
    async fn revoke(&self, key_hash: &str) -> Result<(), AuthError>;

    /// List API keys for a tenant
    async fn list_for_tenant(&self, tenant_id: &Uuid) -> Result<Vec<ApiKeyRecord>, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let tenant_id = Uuid::new_v4();
        let (key, hash) = ApiKeyValidator::generate_key(&tenant_id);

        assert!(key.starts_with(API_KEY_PREFIX));
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_validate_key() {
        let validator = ApiKeyValidator::new();
        let tenant_id = Uuid::new_v4();

        let (key, hash) = ApiKeyValidator::generate_key(&tenant_id);

        validator.register_key(ApiKeyRecord {
            key_hash: hash,
            tenant_id,
            store_ids: vec![],
            permissions: Permissions::read_write(),
            agent_id: None,
            active: true,
            rate_limit: None,
        });

        let context = validator.validate(&key).unwrap();
        assert_eq!(context.tenant_id, tenant_id);
        assert!(context.can_read());
        assert!(context.can_write());
    }

    #[test]
    fn test_invalid_key() {
        let validator = ApiKeyValidator::new();

        let result = validator.validate("invalid_key");
        assert!(result.is_err());
    }

    #[test]
    fn test_revoked_key() {
        let validator = ApiKeyValidator::new();
        let tenant_id = Uuid::new_v4();

        let (key, hash) = ApiKeyValidator::generate_key(&tenant_id);

        validator.register_key(ApiKeyRecord {
            key_hash: hash.clone(),
            tenant_id,
            store_ids: vec![],
            permissions: Permissions::read_write(),
            agent_id: None,
            active: true,
            rate_limit: None,
        });

        // Key works initially
        assert!(validator.validate(&key).is_ok());

        // Revoke it
        validator.revoke(&hash);

        // Key no longer works
        assert!(validator.validate(&key).is_err());
    }
}
