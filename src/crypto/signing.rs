//! Agent signing and verification for VES v1.0
//!
//! Provides Ed25519 signature operations for agent event signing
//! per VES specification Section 8.

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;

use crate::crypto::hash::{compute_event_signing_hash, EventSigningParams, Hash256};

/// Ed25519 signature (64 bytes)
pub type Signature64 = [u8; SIGNATURE_LENGTH];

/// Ed25519 public key (32 bytes)
pub type PublicKey32 = [u8; PUBLIC_KEY_LENGTH];

/// Ed25519 secret key (32 bytes)
pub type SecretKey32 = [u8; SECRET_KEY_LENGTH];

/// Error type for signing operations
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid signature format")]
    InvalidSignatureFormat,

    #[error("invalid public key format")]
    InvalidPublicKeyFormat,

    #[error("invalid secret key format")]
    InvalidSecretKeyFormat,

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("signing failed: {0}")]
    SigningFailed(String),
}

// ============================================================================
// Agent Signing Key
// ============================================================================

/// Agent signing keypair for Ed25519 signatures
#[derive(Clone)]
pub struct AgentSigningKey {
    signing_key: SigningKey,
}

impl AgentSigningKey {
    /// Generate a new random signing key
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from secret key bytes
    pub fn from_bytes(bytes: &SecretKey32) -> Result<Self, SigningError> {
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self { signing_key })
    }

    /// Get the secret key bytes
    pub fn to_bytes(&self) -> SecretKey32 {
        self.signing_key.to_bytes()
    }

    /// Get the public key for this signing key
    pub fn public_key(&self) -> AgentVerifyingKey {
        AgentVerifyingKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> PublicKey32 {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign an event signing hash
    ///
    /// Per VES v1.0 Section 8.3:
    /// agent_signature = Ed25519.Sign(agent_sk, event_signing_hash)
    pub fn sign(&self, event_signing_hash: &Hash256) -> Signature64 {
        let signature = self.signing_key.sign(event_signing_hash);
        signature.to_bytes()
    }

    /// Sign event parameters directly
    ///
    /// Computes the event signing hash and signs it
    pub fn sign_event(&self, params: &EventSigningParams) -> Signature64 {
        let signing_hash = compute_event_signing_hash(params);
        self.sign(&signing_hash)
    }
}

impl std::fmt::Debug for AgentSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentSigningKey")
            .field("public_key", &hex::encode(self.public_key_bytes()))
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Agent Verifying Key
// ============================================================================

/// Agent public key for Ed25519 signature verification
#[derive(Clone)]
pub struct AgentVerifyingKey {
    verifying_key: VerifyingKey,
}

impl AgentVerifyingKey {
    /// Create from public key bytes
    pub fn from_bytes(bytes: &PublicKey32) -> Result<Self, SigningError> {
        let verifying_key =
            VerifyingKey::from_bytes(bytes).map_err(|_| SigningError::InvalidPublicKeyFormat)?;
        Ok(Self { verifying_key })
    }

    /// Get the public key bytes
    pub fn to_bytes(&self) -> PublicKey32 {
        self.verifying_key.to_bytes()
    }

    /// Verify a signature over an event signing hash
    ///
    /// Per VES v1.0 Section 8.3:
    /// Verify Ed25519.Verify(agent_pk, event_signing_hash, agent_signature)
    pub fn verify(
        &self,
        event_signing_hash: &Hash256,
        signature: &Signature64,
    ) -> Result<(), SigningError> {
        let sig = Signature::from_bytes(signature);
        self.verifying_key
            .verify(event_signing_hash, &sig)
            .map_err(|_| SigningError::VerificationFailed)
    }

    /// Verify signature over event parameters
    ///
    /// Computes the event signing hash and verifies the signature
    pub fn verify_event(
        &self,
        params: &EventSigningParams,
        signature: &Signature64,
    ) -> Result<(), SigningError> {
        let signing_hash = compute_event_signing_hash(params);
        self.verify(&signing_hash, signature)
    }
}

impl std::fmt::Debug for AgentVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentVerifyingKey")
            .field("public_key", &hex::encode(self.to_bytes()))
            .finish()
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Verify a signature given raw bytes
///
/// Convenience function for signature verification without constructing key objects.
pub fn verify_signature(
    public_key: &PublicKey32,
    message: &Hash256,
    signature: &Signature64,
) -> Result<(), SigningError> {
    let verifying_key = AgentVerifyingKey::from_bytes(public_key)?;
    verifying_key.verify(message, signature)
}

/// Sign a message given raw secret key bytes
///
/// Convenience function for signing without constructing key objects.
pub fn sign_message(
    secret_key: &SecretKey32,
    message: &Hash256,
) -> Result<Signature64, SigningError> {
    let signing_key = AgentSigningKey::from_bytes(secret_key)?;
    Ok(signing_key.sign(message))
}

/// Convert signature bytes to hex string with 0x prefix
pub fn signature_to_hex(signature: &Signature64) -> String {
    format!("0x{}", hex::encode(signature))
}

/// Parse signature from hex string (with or without 0x prefix)
pub fn signature_from_hex(hex_str: &str) -> Result<Signature64, SigningError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|_| SigningError::InvalidSignatureFormat)?;
    bytes
        .try_into()
        .map_err(|_| SigningError::InvalidSignatureFormat)
}

/// Convert public key bytes to hex string with 0x prefix
pub fn public_key_to_hex(public_key: &PublicKey32) -> String {
    format!("0x{}", hex::encode(public_key))
}

/// Parse public key from hex string (with or without 0x prefix)
pub fn public_key_from_hex(hex_str: &str) -> Result<PublicKey32, SigningError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|_| SigningError::InvalidPublicKeyFormat)?;
    bytes
        .try_into()
        .map_err(|_| SigningError::InvalidPublicKeyFormat)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_key_generation() {
        let key = AgentSigningKey::generate();
        let public_key = key.public_key();

        // Keys should be valid
        assert_eq!(key.to_bytes().len(), 32);
        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let signing_key = AgentSigningKey::generate();
        let verifying_key = signing_key.public_key();

        let message = [42u8; 32];
        let signature = signing_key.sign(&message);

        // Verification should succeed
        assert!(verifying_key.verify(&message, &signature).is_ok());

        // Wrong message should fail
        let wrong_message = [0u8; 32];
        assert!(verifying_key.verify(&wrong_message, &signature).is_err());
    }

    #[test]
    fn test_sign_event() {
        let signing_key = AgentSigningKey::generate();
        let verifying_key = signing_key.public_key();

        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let event = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let plain_hash = [0u8; 32];
        let cipher_hash = [0u8; 32];

        let params = EventSigningParams {
            ves_version: 1,
            tenant_id: &tenant,
            store_id: &store,
            event_id: &event,
            source_agent_id: &agent,
            agent_key_id: 1,
            entity_type: "order",
            entity_id: "order-123",
            event_type: "order.created",
            created_at: "2025-12-20T18:31:22.123Z",
            payload_kind: 0,
            payload_plain_hash: &plain_hash,
            payload_cipher_hash: &cipher_hash,
        };

        let signature = signing_key.sign_event(&params);

        // Verification should succeed
        assert!(verifying_key.verify_event(&params, &signature).is_ok());
    }

    #[test]
    fn test_key_serialization_roundtrip() {
        let original = AgentSigningKey::generate();
        let secret_bytes = original.to_bytes();
        let public_bytes = original.public_key_bytes();

        // Reconstruct from bytes
        let restored = AgentSigningKey::from_bytes(&secret_bytes).unwrap();
        let restored_public = AgentVerifyingKey::from_bytes(&public_bytes).unwrap();

        // Should produce same public key
        assert_eq!(restored.public_key_bytes(), public_bytes);
        assert_eq!(restored_public.to_bytes(), public_bytes);
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let signing_key = AgentSigningKey::generate();
        let message = [42u8; 32];
        let signature = signing_key.sign(&message);

        let hex_str = signature_to_hex(&signature);
        assert!(hex_str.starts_with("0x"));
        assert_eq!(hex_str.len(), 2 + 128); // 0x + 64 bytes * 2

        let parsed = signature_from_hex(&hex_str).unwrap();
        assert_eq!(signature, parsed);

        // Also works without 0x prefix
        let parsed_no_prefix = signature_from_hex(&hex_str[2..]).unwrap();
        assert_eq!(signature, parsed_no_prefix);
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let signing_key = AgentSigningKey::generate();
        let public_key = signing_key.public_key_bytes();

        let hex_str = public_key_to_hex(&public_key);
        assert!(hex_str.starts_with("0x"));
        assert_eq!(hex_str.len(), 2 + 64); // 0x + 32 bytes * 2

        let parsed = public_key_from_hex(&hex_str).unwrap();
        assert_eq!(public_key, parsed);
    }

    #[test]
    fn test_deterministic_signatures() {
        // Ed25519 is deterministic - same key + message = same signature
        let signing_key = AgentSigningKey::generate();
        let message = [42u8; 32];

        let sig1 = signing_key.sign(&message);
        let sig2 = signing_key.sign(&message);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_cross_key_verification_fails() {
        let key1 = AgentSigningKey::generate();
        let key2 = AgentSigningKey::generate();

        let message = [42u8; 32];
        let signature = key1.sign(&message);

        // Signature from key1 should not verify with key2's public key
        assert!(key2.public_key().verify(&message, &signature).is_err());
    }
}
