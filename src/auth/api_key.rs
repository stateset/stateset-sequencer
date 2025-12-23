//! API Key authentication
//!
//! Simple API key authentication for Phase 0.
//! Keys are formatted as: `ss_<tenant_prefix>_<random>`

use super::{AuthContext, AuthError, Permissions};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;
use sqlx::postgres::PgPool;

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

impl ApiKeyRecord {
    pub fn to_auth_context(&self) -> AuthContext {
        AuthContext {
            tenant_id: self.tenant_id,
            store_ids: self.store_ids.clone(),
            agent_id: self.agent_id,
            permissions: self.permissions.clone(),
        }
    }
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

        Ok(record.to_auth_context())
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

    /// Whether any active API keys exist
    async fn has_any_active(&self) -> Result<bool, AuthError>;
}

/// PostgreSQL-backed API key store
pub struct PgApiKeyStore {
    pool: PgPool,
}

impl PgApiKeyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    key_hash: String,
    tenant_id: Uuid,
    store_ids: Vec<Uuid>,
    can_read: bool,
    can_write: bool,
    can_admin: bool,
    agent_id: Option<Uuid>,
    active: bool,
    rate_limit: Option<i32>,
}

impl ApiKeyRow {
    fn to_record(self) -> ApiKeyRecord {
        ApiKeyRecord {
            key_hash: self.key_hash,
            tenant_id: self.tenant_id,
            store_ids: self.store_ids,
            permissions: Permissions {
                read: self.can_read,
                write: self.can_write,
                admin: self.can_admin,
            },
            agent_id: self.agent_id,
            active: self.active,
            rate_limit: self.rate_limit.map(|v| v as u32),
        }
    }
}

#[async_trait::async_trait]
impl ApiKeyStore for PgApiKeyStore {
    async fn get_by_hash(&self, key_hash: &str) -> Result<Option<ApiKeyRecord>, AuthError> {
        let row = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT key_hash, tenant_id, store_ids, can_read, can_write, can_admin,
                   agent_id, active, rate_limit
            FROM api_keys
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::InvalidApiKey)?;

        Ok(row.map(ApiKeyRow::to_record))
    }

    async fn store(&self, record: &ApiKeyRecord) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO api_keys (
                key_hash, tenant_id, store_ids,
                can_read, can_write, can_admin,
                agent_id, active, rate_limit,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3,
                $4, $5, $6,
                $7, $8, $9,
                NOW(), NOW()
            )
            ON CONFLICT (key_hash) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                store_ids = EXCLUDED.store_ids,
                can_read = EXCLUDED.can_read,
                can_write = EXCLUDED.can_write,
                can_admin = EXCLUDED.can_admin,
                agent_id = EXCLUDED.agent_id,
                active = EXCLUDED.active,
                rate_limit = EXCLUDED.rate_limit,
                updated_at = NOW()
            "#,
        )
        .bind(&record.key_hash)
        .bind(record.tenant_id)
        .bind(&record.store_ids)
        .bind(record.permissions.read)
        .bind(record.permissions.write)
        .bind(record.permissions.admin)
        .bind(record.agent_id)
        .bind(record.active)
        .bind(record.rate_limit.map(|v| v as i32))
        .execute(&self.pool)
        .await
        .map_err(|_| AuthError::InvalidApiKey)?;

        Ok(())
    }

    async fn revoke(&self, key_hash: &str) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE api_keys
            SET active = FALSE,
                updated_at = NOW()
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .execute(&self.pool)
        .await
        .map_err(|_| AuthError::InvalidApiKey)?;

        Ok(())
    }

    async fn list_for_tenant(&self, tenant_id: &Uuid) -> Result<Vec<ApiKeyRecord>, AuthError> {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT key_hash, tenant_id, store_ids, can_read, can_write, can_admin,
                   agent_id, active, rate_limit
            FROM api_keys
            WHERE tenant_id = $1
            ORDER BY updated_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AuthError::InvalidApiKey)?;

        Ok(rows.into_iter().map(ApiKeyRow::to_record).collect())
    }

    async fn has_any_active(&self) -> Result<bool, AuthError> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM api_keys WHERE active = TRUE LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::InvalidApiKey)?;

        Ok(row.is_some())
    }
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
