//! Post-quantum payload encryption helpers for VES-PQC-1.
//!
//! Extends the classical HPKE-based encryption with hybrid (X25519 + ML-KEM-768)
//! and PQC-strict (ML-KEM-768 only) recipient key wrapping.
//!
//! The sequencer does NOT encrypt payloads — agents encrypt before submission.
//! This module provides:
//! - Validation of hybrid/strict encrypted payloads during ingestion
//! - Decryption for server-side audit or compliance (when key material is available)
//! - Key wrap scheme identification for routing

use crate::crypto::encrypt::EncryptionError;

/// Key wrap scheme identifiers matching the proto `KeyWrapScheme` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum KeyWrapScheme {
    /// Unspecified (legacy X25519-HKDF-SHA256 assumed).
    Unspecified = 0,
    /// Legacy X25519-HKDF-SHA256 via HPKE.
    X25519HkdfSha256 = 1,
    /// PQC-strict ML-KEM-768 only.
    MlKem768 = 2,
    /// Hybrid X25519 + ML-KEM-768.
    X25519MlKem768 = 3,
}

impl KeyWrapScheme {
    /// Parse from proto i32 value.
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => Self::X25519HkdfSha256,
            2 => Self::MlKem768,
            3 => Self::X25519MlKem768,
            _ => Self::Unspecified,
        }
    }

    /// Whether this scheme uses post-quantum key encapsulation.
    pub fn is_pqc(&self) -> bool {
        matches!(self, Self::MlKem768 | Self::X25519MlKem768)
    }

    /// Whether this scheme uses classical X25519 ECDH.
    pub fn is_classical(&self) -> bool {
        matches!(self, Self::Unspecified | Self::X25519HkdfSha256 | Self::X25519MlKem768)
    }
}

/// Hybrid recipient key wrap entry (from proto `RecipientKeyWrap`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecipientKeyWrap {
    /// Recipient key identifier.
    pub recipient_kid: u32,
    /// Wrap scheme used.
    pub wrap_scheme: i32,
    /// Classical X25519 ephemeral public key (present for hybrid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x25519_enc: Option<Vec<u8>>,
    /// ML-KEM-768 ciphertext (present for hybrid and strict).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ml_kem_ciphertext: Option<Vec<u8>>,
    /// AES-GCM nonce for DEK wrapping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap_nonce: Option<Vec<u8>>,
    /// Wrapped DEK ciphertext + tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<Vec<u8>>,
}

/// Key wrap parameters for PQC profiles (from proto `KeyWrapParams`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyWrapParams {
    /// Wrap scheme enum value.
    pub scheme: i32,
    /// KDF identifier (e.g., "HKDF-SHA256").
    pub kdf: String,
    /// AEAD identifier (e.g., "AES-256-GCM").
    pub aead: String,
}

/// Identify the key wrap scheme from an encrypted payload's metadata.
///
/// Checks `key_wrap_params.scheme` first, then falls back to inspecting
/// `recipient_wraps` for PQC material, then defaults to legacy HPKE.
pub fn detect_wrap_scheme(payload: &serde_json::Value) -> KeyWrapScheme {
    // Check explicit key_wrap_params
    if let Some(params) = payload.get("key_wrap_params").or(payload.get("keyWrapParams")) {
        if let Some(scheme) = params.get("scheme").and_then(serde_json::Value::as_i64) {
            let parsed = KeyWrapScheme::from_i32(scheme as i32);
            if parsed != KeyWrapScheme::Unspecified {
                return parsed;
            }
        }
    }

    // Check recipient_wraps for PQC material
    let wraps = payload
        .get("recipient_wraps")
        .or(payload.get("recipientWraps"))
        .and_then(serde_json::Value::as_array);
    if let Some(wraps) = wraps {
        if let Some(first) = wraps.first() {
            if let Some(scheme) = first
                .get("wrap_scheme")
                .or(first.get("wrapScheme"))
                .and_then(serde_json::Value::as_i64)
            {
                return KeyWrapScheme::from_i32(scheme as i32);
            }
            // Heuristic: if ml_kem_ciphertext is present, it's at least hybrid
            if first.get("ml_kem_ciphertext").is_some() || first.get("mlKemCiphertext").is_some() {
                if first.get("x25519_enc").is_some() || first.get("x25519Enc").is_some() {
                    return KeyWrapScheme::X25519MlKem768;
                }
                return KeyWrapScheme::MlKem768;
            }
        }
    }

    // Check legacy recipients
    if payload.get("recipients").and_then(serde_json::Value::as_array).map_or(false, |r| !r.is_empty()) {
        return KeyWrapScheme::X25519HkdfSha256;
    }

    KeyWrapScheme::Unspecified
}

/// Validate that an encrypted payload's key wrap scheme is acceptable
/// for the given security profile.
///
/// # Errors
///
/// Returns an error if the payload uses a scheme weaker than the profile requires.
pub fn validate_wrap_scheme_for_profile(
    payload: &serde_json::Value,
    profile: &str,
) -> Result<KeyWrapScheme, EncryptionError> {
    let scheme = detect_wrap_scheme(payload);

    match profile {
        "pqc-strict" => {
            if scheme != KeyWrapScheme::MlKem768 {
                return Err(EncryptionError::EncryptionFailed(
                    "pqc-strict profile requires ML-KEM-768-only key wrapping".to_string(),
                ));
            }
        }
        "hybrid" => {
            if !scheme.is_pqc() {
                return Err(EncryptionError::EncryptionFailed(
                    "hybrid profile requires X25519+ML-KEM-768 or ML-KEM-768 key wrapping".to_string(),
                ));
            }
        }
        _ => {} // Legacy accepts any scheme
    }

    Ok(scheme)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detect_legacy_hpke() {
        let payload = json!({
            "recipients": [{"recipient_kid": 1, "enc_b64u": "abc", "ct_b64u": "def"}]
        });
        assert_eq!(detect_wrap_scheme(&payload), KeyWrapScheme::X25519HkdfSha256);
    }

    #[test]
    fn detect_hybrid_from_key_wrap_params() {
        let payload = json!({
            "key_wrap_params": {"scheme": 3, "kdf": "HKDF-SHA256", "aead": "AES-256-GCM"}
        });
        assert_eq!(detect_wrap_scheme(&payload), KeyWrapScheme::X25519MlKem768);
    }

    #[test]
    fn detect_strict_from_recipient_wraps() {
        let payload = json!({
            "recipient_wraps": [{"wrap_scheme": 2, "ml_kem_ciphertext": "abc"}]
        });
        assert_eq!(detect_wrap_scheme(&payload), KeyWrapScheme::MlKem768);
    }

    #[test]
    fn detect_hybrid_from_heuristic() {
        let payload = json!({
            "recipient_wraps": [{
                "ml_kem_ciphertext": "abc",
                "x25519_enc": "def"
            }]
        });
        assert_eq!(detect_wrap_scheme(&payload), KeyWrapScheme::X25519MlKem768);
    }

    #[test]
    fn detect_empty_payload_returns_unspecified() {
        assert_eq!(detect_wrap_scheme(&json!({})), KeyWrapScheme::Unspecified);
    }

    #[test]
    fn validate_legacy_accepts_any() {
        let payload = json!({"recipients": [{"recipient_kid": 1}]});
        assert!(validate_wrap_scheme_for_profile(&payload, "legacy").is_ok());
    }

    #[test]
    fn validate_hybrid_rejects_legacy_wraps() {
        let payload = json!({"recipients": [{"recipient_kid": 1, "enc_b64u": "a", "ct_b64u": "b"}]});
        assert!(validate_wrap_scheme_for_profile(&payload, "hybrid").is_err());
    }

    #[test]
    fn validate_hybrid_accepts_hybrid_wraps() {
        let payload = json!({"key_wrap_params": {"scheme": 3}});
        assert!(validate_wrap_scheme_for_profile(&payload, "hybrid").is_ok());
    }

    #[test]
    fn validate_strict_rejects_hybrid_wraps() {
        let payload = json!({"key_wrap_params": {"scheme": 3}});
        assert!(validate_wrap_scheme_for_profile(&payload, "pqc-strict").is_err());
    }

    #[test]
    fn validate_strict_accepts_strict_wraps() {
        let payload = json!({"key_wrap_params": {"scheme": 2}});
        assert!(validate_wrap_scheme_for_profile(&payload, "pqc-strict").is_ok());
    }

    #[test]
    fn key_wrap_scheme_properties() {
        assert!(KeyWrapScheme::MlKem768.is_pqc());
        assert!(KeyWrapScheme::X25519MlKem768.is_pqc());
        assert!(!KeyWrapScheme::X25519HkdfSha256.is_pqc());
        assert!(KeyWrapScheme::X25519MlKem768.is_classical());
        assert!(!KeyWrapScheme::MlKem768.is_classical());
    }
}
