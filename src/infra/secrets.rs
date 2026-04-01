//! Secrets provider abstraction
//!
//! Decouples secret loading from `std::env` so implementations can be swapped
//! for HashiCorp Vault, AWS Secrets Manager, K8s secrets, or HSM-backed stores.
//!
//! The default [`EnvSecretsProvider`] preserves the existing environment-variable
//! behaviour and is used when no alternative is configured.

use std::collections::HashMap;
use uuid::Uuid;

/// Trait for loading secrets at startup.
///
/// Each method returns `Option` when the secret is not configured (disabled feature)
/// or `Err` when the secret *should* exist but could not be retrieved.
pub trait SecretsProvider: Send + Sync {
    // ── Authentication ───────────────────────────────────────────────
    /// Bootstrap admin API key (plaintext, hashed before storage)
    fn bootstrap_api_key(&self) -> Result<Option<String>, SecretsError>;

    /// HMAC secret for JWT validation
    fn jwt_secret(&self) -> Result<Option<String>, SecretsError>;

    /// JWT issuer claim
    fn jwt_issuer(&self) -> Result<String, SecretsError>;

    /// JWT audience claim
    fn jwt_audience(&self) -> Result<String, SecretsError>;

    // ── VES Sequencer ────────────────────────────────────────────────
    /// Ed25519 private key for signing sequencer receipts
    fn ves_sequencer_signing_key(&self) -> Result<Option<String>, SecretsError>;

    /// Pinned VES sequencer UUID (optional)
    fn ves_sequencer_id(&self) -> Result<Option<String>, SecretsError>;

    /// ML-DSA-65 seed for hybrid/strict receipt signing (hex, 32 bytes)
    fn ves_sequencer_ml_dsa_seed(&self) -> Result<Option<String>, SecretsError>;

    /// Security profile for sequencer receipts: "legacy", "hybrid", or "pqc-strict"
    fn ves_sequencer_security_profile(&self) -> Result<Option<String>, SecretsError>;

    // ── Payload encryption ───────────────────────────────────────────
    /// AES-256 key(s) for payload encryption at rest
    fn payload_encryption_keys(&self) -> Result<Option<Vec<String>>, SecretsError>;

    /// Per-tenant encryption key overrides (JSON map)
    fn payload_encryption_keys_by_tenant(
        &self,
    ) -> Result<Option<HashMap<Uuid, Vec<String>>>, SecretsError>;

    // ── On-chain anchoring ───────────────────────────────────────────
    /// Ethereum private key for signing anchor transactions
    fn anchor_private_key(&self) -> Result<Option<String>, SecretsError>;
}

/// Error returned when a secret cannot be retrieved
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("secret parse error: {0}")]
    Parse(String),
    #[error("provider error: {0}")]
    Provider(String),
}

// ─────────────────────────────────────────────────────────────────────
// Default implementation: reads everything from environment variables
// ─────────────────────────────────────────────────────────────────────

/// Environment-variable backed secrets provider (current default behaviour).
#[derive(Debug, Default)]
pub struct EnvSecretsProvider;

impl EnvSecretsProvider {
    pub fn new() -> Self {
        Self
    }

    fn get_opt(var: &str) -> Option<String> {
        std::env::var(var).ok().filter(|v| !v.trim().is_empty())
    }
}

impl SecretsProvider for EnvSecretsProvider {
    fn bootstrap_api_key(&self) -> Result<Option<String>, SecretsError> {
        Ok(Self::get_opt("BOOTSTRAP_ADMIN_API_KEY"))
    }

    fn jwt_secret(&self) -> Result<Option<String>, SecretsError> {
        Ok(Self::get_opt("JWT_SECRET"))
    }

    fn jwt_issuer(&self) -> Result<String, SecretsError> {
        Ok(std::env::var("JWT_ISSUER").unwrap_or_else(|_| "stateset-sequencer".into()))
    }

    fn jwt_audience(&self) -> Result<String, SecretsError> {
        Ok(std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "stateset-api".into()))
    }

    fn ves_sequencer_signing_key(&self) -> Result<Option<String>, SecretsError> {
        Ok(Self::get_opt("VES_SEQUENCER_SIGNING_KEY"))
    }

    fn ves_sequencer_ml_dsa_seed(&self) -> Result<Option<String>, SecretsError> {
        Ok(Self::get_opt("VES_SEQUENCER_ML_DSA_SEED"))
    }

    fn ves_sequencer_security_profile(&self) -> Result<Option<String>, SecretsError> {
        Ok(Self::get_opt("VES_SEQUENCER_SECURITY_PROFILE"))
    }

    fn ves_sequencer_id(&self) -> Result<Option<String>, SecretsError> {
        Ok(Self::get_opt("VES_SEQUENCER_ID"))
    }

    fn payload_encryption_keys(&self) -> Result<Option<Vec<String>>, SecretsError> {
        // Try multi-key var first, then single-key fallback
        if let Some(keys_csv) = Self::get_opt("PAYLOAD_ENCRYPTION_KEYS") {
            let keys: Vec<String> = keys_csv.split(',').map(|s| s.trim().to_string()).collect();
            return Ok(Some(keys));
        }
        if let Some(key) = Self::get_opt("PAYLOAD_ENCRYPTION_KEY") {
            return Ok(Some(vec![key]));
        }
        Ok(None)
    }

    fn payload_encryption_keys_by_tenant(
        &self,
    ) -> Result<Option<HashMap<Uuid, Vec<String>>>, SecretsError> {
        let json_str = match Self::get_opt("PAYLOAD_ENCRYPTION_KEYS_BY_TENANT") {
            Some(s) => s,
            None => return Ok(None),
        };
        serde_json::from_str(&json_str)
            .map(Some)
            .map_err(|e| SecretsError::Parse(format!("PAYLOAD_ENCRYPTION_KEYS_BY_TENANT: {e}")))
    }

    fn anchor_private_key(&self) -> Result<Option<String>, SecretsError> {
        Ok(Self::get_opt("SEQUENCER_PRIVATE_KEY"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_provider_returns_none_for_unset_vars() {
        let provider = EnvSecretsProvider::new();
        // These are unlikely to be set in the test environment
        assert!(provider.bootstrap_api_key().unwrap().is_none());
        assert!(provider.anchor_private_key().unwrap().is_none());
    }

    #[test]
    fn env_provider_defaults_for_jwt() {
        let provider = EnvSecretsProvider::new();
        assert_eq!(provider.jwt_issuer().unwrap(), "stateset-sequencer");
        assert_eq!(provider.jwt_audience().unwrap(), "stateset-api");
    }
}
