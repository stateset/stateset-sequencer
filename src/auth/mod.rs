//! Authentication and authorization for StateSet Sequencer
//!
//! This module provides a flexible authentication system supporting multiple
//! credential types for different use cases.
//!
//! # Authentication Methods
//!
//! - **API Keys**: SHA-256 hashed keys stored in database, scoped to tenant/store
//! - **JWT Tokens**: HMAC-validated tokens with configurable issuer/audience
//! - **Agent Keys**: Ed25519 public keys for VES v1.0 event signature verification
//!
//! # Authorization Model
//!
//! Permissions are granted at three levels:
//! - `read`: Query events, commitments, and proofs
//! - `write`: Ingest new events
//! - `admin`: Manage agent keys, schemas, and anchoring
//!
//! # Rate Limiting
//!
//! Per-tenant rate limiting with configurable limits:
//! - Sliding window algorithm
//! - LRU eviction for bounded memory
//! - Configurable via `RATE_LIMIT_*` environment variables
//!
//! # Configuration
//!
//! - `AUTH_MODE`: `required` (default) or `disabled` for development
//! - `BOOTSTRAP_ADMIN_API_KEY`: Initial admin key for setup
//! - `JWT_SECRET`: HMAC secret for JWT validation

mod agent_keys;
mod api_key;
mod jwt;
mod middleware;

pub use agent_keys::*;
pub use api_key::*;
pub use jwt::*;
pub use middleware::*;

use uuid::Uuid;

/// Authentication context extracted from request
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Tenant ID from auth token
    pub tenant_id: Uuid,

    /// Store IDs this auth allows access to (empty = all stores for tenant)
    pub store_ids: Vec<Uuid>,

    /// Agent ID (if authenticated as an agent)
    pub agent_id: Option<Uuid>,

    /// Allowed operations
    pub permissions: Permissions,
}

/// Permission flags for operations
#[derive(Debug, Clone, Default)]
pub struct Permissions {
    /// Can read events
    pub read: bool,

    /// Can write events (ingest)
    pub write: bool,

    /// Can manage agents
    pub admin: bool,
}

impl Permissions {
    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            admin: false,
        }
    }

    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            admin: false,
        }
    }

    pub fn admin() -> Self {
        Self {
            read: true,
            write: true,
            admin: true,
        }
    }
}

impl AuthContext {
    /// Check if this auth context allows access to a specific store
    pub fn can_access_store(&self, store_id: &Uuid) -> bool {
        self.store_ids.is_empty() || self.store_ids.contains(store_id)
    }

    /// Check if this auth context allows read operations
    pub fn can_read(&self) -> bool {
        self.permissions.read
    }

    /// Check if this auth context allows write operations
    pub fn can_write(&self) -> bool {
        self.permissions.write
    }

    /// Check if this auth context allows admin operations
    pub fn is_admin(&self) -> bool {
        self.permissions.admin
    }
}

/// Authentication error
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing authentication")]
    MissingAuth,

    #[error("invalid API key")]
    InvalidApiKey,

    #[error("invalid JWT: {0}")]
    InvalidJwt(String),

    #[error("token expired")]
    TokenExpired,

    #[error("insufficient permissions")]
    InsufficientPermissions,

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("tenant not found")]
    TenantNotFound,

    #[error("store access denied")]
    StoreAccessDenied,
}
