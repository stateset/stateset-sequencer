//! Post-quantum signature verification for VES-PQC-1.
//!
//! Extends the classical Ed25519 signing module with hybrid (Ed25519 + ML-DSA-65)
//! and PQC-strict (ML-DSA-65 only) signature verification.
//!
//! The sequencer verifies incoming signatures but does not sign events itself
//! (agents sign events). The sequencer signs receipts using its own key.

use crate::crypto::hash::Hash256;
use crate::crypto::signing::{AgentVerifyingKey, PublicKey32, Signature64, SigningError};

#[cfg(feature = "pqc")]
use crate::crypto::pqc_backend::{sign_ml_dsa_65, verify_ml_dsa_65};

/// Signature scheme identifier matching the proto `SignatureScheme` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SignatureScheme {
    /// Legacy Ed25519 only.
    Unspecified = 0,
    /// Ed25519 only.
    Ed25519 = 1,
    /// ML-DSA-65 only (PQC-strict).
    MlDsa65 = 2,
    /// Ed25519 + ML-DSA-65 hybrid.
    Ed25519MlDsa65 = 3,
}

impl SignatureScheme {
    /// Parse from proto i32 value.
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => Self::Ed25519,
            2 => Self::MlDsa65,
            3 => Self::Ed25519MlDsa65,
            _ => Self::Unspecified,
        }
    }

    pub fn is_pqc(&self) -> bool {
        matches!(self, Self::MlDsa65 | Self::Ed25519MlDsa65)
    }
}

/// Key algorithm identifier matching the proto `KeyAlgorithm` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum KeyAlgorithm {
    Unspecified = 0,
    Ed25519 = 1,
    X25519 = 2,
    MlDsa65 = 3,
    MlKem768 = 4,
    Ed25519MlDsa65 = 5,
    X25519MlKem768 = 6,
}

impl KeyAlgorithm {
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => Self::Ed25519,
            2 => Self::X25519,
            3 => Self::MlDsa65,
            4 => Self::MlKem768,
            5 => Self::Ed25519MlDsa65,
            6 => Self::X25519MlKem768,
            _ => Self::Unspecified,
        }
    }

    /// Whether this algorithm includes ML-DSA-65 signing material.
    pub fn has_ml_dsa(&self) -> bool {
        matches!(self, Self::MlDsa65 | Self::Ed25519MlDsa65)
    }

    /// Whether this algorithm includes Ed25519 signing material.
    pub fn has_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::Ed25519MlDsa65)
    }

    pub fn is_pqc(&self) -> bool {
        matches!(
            self,
            Self::MlDsa65 | Self::MlKem768 | Self::Ed25519MlDsa65 | Self::X25519MlKem768
        )
    }
}

pub fn validate_signature_scheme_for_profile(
    scheme: SignatureScheme,
    profile: &str,
) -> Result<(), SigningError> {
    match profile {
        "pqc-strict" if scheme != SignatureScheme::MlDsa65 => Err(SigningError::VerificationFailed),
        "hybrid" if !scheme.is_pqc() => Err(SigningError::VerificationFailed),
        _ => Ok(()),
    }
}

pub fn validate_key_algorithm_for_profile(
    algorithm: KeyAlgorithm,
    profile: &str,
) -> Result<(), SigningError> {
    match profile {
        "pqc-strict" if !matches!(algorithm, KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlKem768) => {
            Err(SigningError::VerificationFailed)
        }
        "hybrid" if !algorithm.is_pqc() => Err(SigningError::VerificationFailed),
        _ => Ok(()),
    }
}

/// Parsed public key bundle for algorithm-aware verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicKeyBundle {
    pub ed25519_public_key: Option<PublicKey32>,
    pub ml_dsa_65_public_key: Option<Vec<u8>>,
    pub x25519_public_key: Option<Vec<u8>>,
    pub ml_kem_768_public_key: Option<Vec<u8>>,
}

/// Algorithm-aware verification key.
///
/// Returned by the key registry and used by the signature verification
/// dispatch in the VES sequencer.
#[derive(Debug)]
pub enum VerificationKey {
    /// Classical Ed25519 only.
    Legacy(AgentVerifyingKey),
    /// Hybrid Ed25519 + ML-DSA-65.
    Hybrid {
        ed25519: AgentVerifyingKey,
        ml_dsa_65_public_key: Vec<u8>,
    },
    /// PQC-strict ML-DSA-65 only.
    Strict { ml_dsa_65_public_key: Vec<u8> },
}

impl VerificationKey {
    /// Build from key algorithm and raw material.
    pub fn from_key_entry(
        algorithm: KeyAlgorithm,
        public_key: &[u8],
        public_key_bundle: Option<&PublicKeyBundle>,
    ) -> Result<Self, SigningError> {
        match algorithm {
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Unspecified => {
                if public_key.len() != 32 {
                    return Err(SigningError::InvalidPublicKeyFormat);
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(public_key);
                Ok(Self::Legacy(AgentVerifyingKey::from_bytes(&pk)?))
            }
            KeyAlgorithm::Ed25519MlDsa65 => {
                let bundle = public_key_bundle.ok_or(SigningError::InvalidPublicKeyFormat)?;
                let ed25519_pk = bundle
                    .ed25519_public_key
                    .ok_or(SigningError::InvalidPublicKeyFormat)?;
                let ml_dsa_pk = bundle
                    .ml_dsa_65_public_key
                    .as_ref()
                    .ok_or(SigningError::InvalidPublicKeyFormat)?;
                Ok(Self::Hybrid {
                    ed25519: AgentVerifyingKey::from_bytes(&ed25519_pk)?,
                    ml_dsa_65_public_key: ml_dsa_pk.clone(),
                })
            }
            KeyAlgorithm::MlDsa65 => {
                let ml_dsa_pk = public_key_bundle
                    .and_then(|b| b.ml_dsa_65_public_key.as_ref())
                    .ok_or(SigningError::InvalidPublicKeyFormat)?;
                Ok(Self::Strict {
                    ml_dsa_65_public_key: ml_dsa_pk.clone(),
                })
            }
            _ => Err(SigningError::InvalidPublicKeyFormat),
        }
    }
}

/// Parsed signature bundle for multi-algorithm verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParsedSignatureBundle {
    pub ed25519_signature: Option<Vec<u8>>,
    pub ml_dsa_65_signature: Option<Vec<u8>>,
}

impl ParsedSignatureBundle {
    /// Extract Ed25519 signature as a fixed-size array, if present and valid.
    pub fn ed25519_sig_64(&self) -> Option<Signature64> {
        self.ed25519_signature.as_ref().and_then(|s| {
            if s.len() == 64 {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(s);
                Some(arr)
            } else {
                None
            }
        })
    }
}

/// Verify a signature against a verification key, dispatching by scheme.
///
/// # Errors
///
/// Returns [`SigningError::VerificationFailed`] if any required component fails.
pub fn verify_with_key(
    event_signing_hash: &Hash256,
    scheme: SignatureScheme,
    legacy_signature: &[u8],
    bundle: Option<&ParsedSignatureBundle>,
    verification_key: &VerificationKey,
) -> Result<(), SigningError> {
    match (scheme, verification_key) {
        // Legacy: Ed25519 only
        (SignatureScheme::Unspecified | SignatureScheme::Ed25519, VerificationKey::Legacy(vk)) => {
            if legacy_signature.len() != 64 {
                return Err(SigningError::InvalidSignatureFormat);
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(legacy_signature);
            vk.verify(event_signing_hash, &sig)
        }

        // Hybrid: both Ed25519 and ML-DSA-65 must verify
        (
            SignatureScheme::Ed25519MlDsa65,
            VerificationKey::Hybrid {
                ed25519,
                ml_dsa_65_public_key,
            },
        ) => {
            let sig_bundle = bundle.ok_or(SigningError::InvalidSignatureFormat)?;

            // Verify Ed25519 component
            let ed_sig = sig_bundle
                .ed25519_sig_64()
                .ok_or(SigningError::InvalidSignatureFormat)?;
            ed25519.verify(event_signing_hash, &ed_sig)?;

            // Verify ML-DSA-65 component
            #[cfg(feature = "pqc")]
            {
                let ml_dsa_sig_bytes = sig_bundle
                    .ml_dsa_65_signature
                    .as_ref()
                    .ok_or(SigningError::InvalidSignatureFormat)?;
                verify_ml_dsa_65(event_signing_hash, ml_dsa_sig_bytes, ml_dsa_65_public_key)?;
            }
            #[cfg(not(feature = "pqc"))]
            {
                let _ = ml_dsa_65_public_key;
                return Err(SigningError::SigningFailed(
                    "PQC feature not enabled".to_string(),
                ));
            }

            Ok(())
        }

        // PQC-strict: ML-DSA-65 only
        (
            SignatureScheme::MlDsa65,
            VerificationKey::Strict {
                ml_dsa_65_public_key,
            },
        ) => {
            let sig_bundle = bundle.ok_or(SigningError::InvalidSignatureFormat)?;

            #[cfg(feature = "pqc")]
            {
                let ml_dsa_sig_bytes = sig_bundle
                    .ml_dsa_65_signature
                    .as_ref()
                    .ok_or(SigningError::InvalidSignatureFormat)?;
                verify_ml_dsa_65(event_signing_hash, ml_dsa_sig_bytes, ml_dsa_65_public_key)?;
            }
            #[cfg(not(feature = "pqc"))]
            {
                let _ = (ml_dsa_65_public_key, sig_bundle);
                return Err(SigningError::SigningFailed(
                    "PQC feature not enabled".to_string(),
                ));
            }

            Ok(())
        }

        // SECURITY: Reject legacy/Ed25519-only schemes against hybrid or strict keys.
        // A hybrid key MUST require scheme=3 (Ed25519MlDsa65).
        // A strict key MUST require scheme=2 (MlDsa65).
        // Allowing scheme downgrade would let an attacker bypass ML-DSA-65 verification
        // by simply setting agent_signature_scheme=0 in the event.
        (
            SignatureScheme::Unspecified | SignatureScheme::Ed25519,
            VerificationKey::Hybrid { .. } | VerificationKey::Strict { .. },
        ) => Err(SigningError::VerificationFailed),

        _ => Err(SigningError::VerificationFailed),
    }
}

// ===========================================================================
// Sequencer receipt signing (hybrid)
// ===========================================================================

/// Sequencer signing key material for receipt signing.
#[derive(Clone)]
pub struct SequencerSigningConfig {
    /// Ed25519 signing key for legacy and hybrid receipts.
    pub ed25519_key: Option<crate::crypto::signing::AgentSigningKey>,
    /// ML-DSA-65 seed for hybrid and strict receipts.
    #[cfg(feature = "pqc")]
    pub ml_dsa_65_seed: Option<[u8; 32]>,
    /// Active signature scheme for receipts.
    pub receipt_scheme: SignatureScheme,
}

/// SECURITY: Zeroize the ML-DSA-65 seed on drop to prevent key material
/// from lingering in memory after the config is no longer needed.
impl Drop for SequencerSigningConfig {
    fn drop(&mut self) {
        #[cfg(feature = "pqc")]
        if let Some(ref mut seed) = self.ml_dsa_65_seed {
            // Volatile write to prevent compiler optimization
            for byte in seed.iter_mut() {
                unsafe { std::ptr::write_volatile(byte, 0) };
            }
        }
    }
}

impl SequencerSigningConfig {
    /// Sign a receipt hash according to the configured scheme.
    ///
    /// Returns `(scheme, legacy_signature, bundle)`.
    pub fn sign_receipt(
        &self,
        receipt_hash: &Hash256,
    ) -> Result<(SignatureScheme, Vec<u8>, Option<ParsedSignatureBundle>), SigningError> {
        match self.receipt_scheme {
            SignatureScheme::Unspecified | SignatureScheme::Ed25519 => {
                let key = self
                    .ed25519_key
                    .as_ref()
                    .ok_or(SigningError::SigningFailed(
                        "No Ed25519 signing key configured".to_string(),
                    ))?;
                let sig = key.sign(receipt_hash);
                Ok((SignatureScheme::Ed25519, sig.to_vec(), None))
            }

            #[cfg(feature = "pqc")]
            SignatureScheme::Ed25519MlDsa65 => {
                let ed_key = self
                    .ed25519_key
                    .as_ref()
                    .ok_or(SigningError::SigningFailed(
                        "No Ed25519 signing key configured".to_string(),
                    ))?;
                let ed_sig = ed_key.sign(receipt_hash);

                let ml_seed = self.ml_dsa_65_seed.ok_or(SigningError::SigningFailed(
                    "No ML-DSA-65 seed configured".to_string(),
                ))?;
                let ml_sig = sign_ml_dsa_65(&ml_seed, receipt_hash)?;

                Ok((
                    SignatureScheme::Ed25519MlDsa65,
                    ed_sig.to_vec(),
                    Some(ParsedSignatureBundle {
                        ed25519_signature: Some(ed_sig.to_vec()),
                        ml_dsa_65_signature: Some(ml_sig),
                    }),
                ))
            }

            #[cfg(feature = "pqc")]
            SignatureScheme::MlDsa65 => {
                let ml_seed = self.ml_dsa_65_seed.ok_or(SigningError::SigningFailed(
                    "No ML-DSA-65 seed configured".to_string(),
                ))?;
                let ml_sig = sign_ml_dsa_65(&ml_seed, receipt_hash)?;

                Ok((
                    SignatureScheme::MlDsa65,
                    Vec::new(),
                    Some(ParsedSignatureBundle {
                        ed25519_signature: None,
                        ml_dsa_65_signature: Some(ml_sig),
                    }),
                ))
            }

            #[cfg(not(feature = "pqc"))]
            _ => Err(SigningError::SigningFailed(
                "PQC feature not enabled for receipt signing".to_string(),
            )),
        }
    }
}

impl std::fmt::Debug for SequencerSigningConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SequencerSigningConfig")
            .field("receipt_scheme", &self.receipt_scheme)
            .finish_non_exhaustive()
    }
}

// ML-DSA Keypair trait used by SequencerSigningConfig

/// Verify a proof-of-possession bundle for a key registration.
///
/// Returns `Ok(())` if the PoP is valid for the given algorithm and key material.
pub fn verify_proof_of_possession(
    algorithm: KeyAlgorithm,
    public_key: &[u8],
    public_key_bundle: Option<&PublicKeyBundle>,
    pop: &[u8],
    pop_bundle: Option<&ParsedSignatureBundle>,
) -> Result<(), SigningError> {
    match algorithm {
        KeyAlgorithm::Ed25519 | KeyAlgorithm::Unspecified => {
            // Legacy: Ed25519 PoP = sign(public_key)
            if public_key.len() != 32 || pop.len() != 64 {
                return Err(SigningError::InvalidSignatureFormat);
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(public_key);
            let challenge = compute_pop_challenge(&pk);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(pop);
            let vk = AgentVerifyingKey::from_bytes(&pk)?;
            vk.verify(&challenge, &sig)
        }

        #[cfg(feature = "pqc")]
        KeyAlgorithm::Ed25519MlDsa65 => {
            let bundle = public_key_bundle.ok_or(SigningError::InvalidPublicKeyFormat)?;
            let pop_b = pop_bundle.ok_or(SigningError::InvalidSignatureFormat)?;

            let ed_pk = bundle
                .ed25519_public_key
                .ok_or(SigningError::InvalidPublicKeyFormat)?;
            let ml_pk = bundle
                .ml_dsa_65_public_key
                .as_ref()
                .ok_or(SigningError::InvalidPublicKeyFormat)?;

            // Challenge = SHA-256("VES_POP_V1" || ed25519_pk || ml_dsa_65_pk)
            let mut pk_bytes = Vec::with_capacity(32 + ml_pk.len());
            pk_bytes.extend_from_slice(&ed_pk);
            pk_bytes.extend_from_slice(ml_pk);
            let challenge = compute_pop_challenge(&pk_bytes);

            // Verify Ed25519 component
            let ed_sig = pop_b
                .ed25519_sig_64()
                .ok_or(SigningError::InvalidSignatureFormat)?;
            let ed_vk = AgentVerifyingKey::from_bytes(&ed_pk)?;
            ed_vk.verify(&challenge, &ed_sig)?;

            // Verify ML-DSA-65 component
            let ml_sig = pop_b
                .ml_dsa_65_signature
                .as_ref()
                .ok_or(SigningError::InvalidSignatureFormat)?;
            verify_ml_dsa_65(&challenge, ml_sig, ml_pk)?;

            Ok(())
        }

        #[cfg(feature = "pqc")]
        KeyAlgorithm::MlDsa65 => {
            let ml_pk = public_key_bundle
                .and_then(|b| b.ml_dsa_65_public_key.as_ref())
                .ok_or(SigningError::InvalidPublicKeyFormat)?;
            let challenge = compute_pop_challenge(ml_pk);
            let ml_sig_from_bundle = pop_bundle.and_then(|b| b.ml_dsa_65_signature.clone());
            let ml_sig = ml_sig_from_bundle
                .or_else(|| {
                    if pop.is_empty() {
                        None
                    } else {
                        Some(pop.to_vec())
                    }
                })
                .ok_or(SigningError::InvalidSignatureFormat)?;
            verify_ml_dsa_65(&challenge, &ml_sig, ml_pk)
        }

        _ => Err(SigningError::InvalidPublicKeyFormat),
    }
}

/// Compute PoP challenge: SHA-256("VES_POP_V1" || public_key_bytes).
fn compute_pop_challenge(public_key_bytes: &[u8]) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"VES_POP_V1");
    hasher.update(public_key_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::AgentSigningKey;

    #[test]
    fn legacy_verify_with_key_roundtrip() {
        let sk = AgentSigningKey::generate();
        let vk = VerificationKey::Legacy(sk.public_key());
        let hash = [42u8; 32];
        let sig = sk.sign(&hash);
        assert!(verify_with_key(&hash, SignatureScheme::Ed25519, &sig, None, &vk).is_ok());
    }

    #[test]
    fn legacy_verify_wrong_key_fails() {
        let sk1 = AgentSigningKey::generate();
        let sk2 = AgentSigningKey::generate();
        let vk = VerificationKey::Legacy(sk2.public_key());
        let hash = [42u8; 32];
        let sig = sk1.sign(&hash);
        assert!(verify_with_key(&hash, SignatureScheme::Ed25519, &sig, None, &vk).is_err());
    }

    #[test]
    fn signature_scheme_from_i32() {
        assert_eq!(SignatureScheme::from_i32(0), SignatureScheme::Unspecified);
        assert_eq!(SignatureScheme::from_i32(1), SignatureScheme::Ed25519);
        assert_eq!(SignatureScheme::from_i32(2), SignatureScheme::MlDsa65);
        assert_eq!(
            SignatureScheme::from_i32(3),
            SignatureScheme::Ed25519MlDsa65
        );
        assert_eq!(SignatureScheme::from_i32(99), SignatureScheme::Unspecified);
    }

    #[test]
    fn key_algorithm_from_i32() {
        assert_eq!(KeyAlgorithm::from_i32(5), KeyAlgorithm::Ed25519MlDsa65);
        assert!(KeyAlgorithm::Ed25519MlDsa65.has_ml_dsa());
        assert!(KeyAlgorithm::Ed25519MlDsa65.has_ed25519());
        assert!(!KeyAlgorithm::MlDsa65.has_ed25519());
        assert!(KeyAlgorithm::MlDsa65.has_ml_dsa());
    }

    #[test]
    fn verification_key_from_legacy() {
        let sk = AgentSigningKey::generate();
        let pk = sk.public_key_bytes();
        let vk = VerificationKey::from_key_entry(KeyAlgorithm::Ed25519, &pk, None).unwrap();
        assert!(matches!(vk, VerificationKey::Legacy(_)));
    }

    #[test]
    fn legacy_pop_challenge_deterministic() {
        let c1 = compute_pop_challenge(&[1u8; 32]);
        let c2 = compute_pop_challenge(&[1u8; 32]);
        assert_eq!(c1, c2);
        let c3 = compute_pop_challenge(&[2u8; 32]);
        assert_ne!(c1, c3);
    }

    // -----------------------------------------------------------------------
    // PQC verification dispatch tests (require `pqc` feature)
    // -----------------------------------------------------------------------

    #[cfg(feature = "pqc")]
    mod pqc_tests {
        use super::*;
        use crate::crypto::pqc_backend::ml_dsa_65_public_key_from_seed;
        use crate::crypto::signing::AgentSigningKey;
        use sha2::{Digest, Sha256};

        const TEST_VECTOR_SIGNING_SEED: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        fn generate_hybrid_keypair() -> (AgentSigningKey, [u8; 32], Vec<u8>) {
            let ed_key = AgentSigningKey::generate();
            let mut ml_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ml_seed);
            let ml_pk = ml_dsa_65_public_key_from_seed(&ml_seed);
            (ed_key, ml_seed, ml_pk)
        }

        fn hybrid_sign(
            hash: &[u8; 32],
            ed_key: &AgentSigningKey,
            ml_seed: &[u8; 32],
        ) -> (Vec<u8>, ParsedSignatureBundle) {
            let ed_sig = ed_key.sign(hash);
            let ml_sig = sign_ml_dsa_65(ml_seed, hash).unwrap();
            let legacy = ed_sig.to_vec();
            let bundle = ParsedSignatureBundle {
                ed25519_signature: Some(ed_sig.to_vec()),
                ml_dsa_65_signature: Some(ml_sig),
            };
            (legacy, bundle)
        }

        #[test]
        fn hybrid_verify_with_key_roundtrip() {
            let (ed_key, ml_seed, ml_pk) = generate_hybrid_keypair();
            let ed_pk = ed_key.public_key_bytes();
            let bundle = PublicKeyBundle {
                ed25519_public_key: Some(ed_pk),
                ml_dsa_65_public_key: Some(ml_pk),
                x25519_public_key: None,
                ml_kem_768_public_key: None,
            };
            let vk = VerificationKey::from_key_entry(
                KeyAlgorithm::Ed25519MlDsa65,
                &ed_pk,
                Some(&bundle),
            )
            .unwrap();

            let hash = [0xAAu8; 32];
            let (legacy_sig, sig_bundle) = hybrid_sign(&hash, &ed_key, &ml_seed);
            assert!(verify_with_key(
                &hash,
                SignatureScheme::Ed25519MlDsa65,
                &legacy_sig,
                Some(&sig_bundle),
                &vk,
            )
            .is_ok());
        }

        #[test]
        fn hybrid_verify_wrong_ml_dsa_key_fails() {
            let (ed_key, ml_seed, _ml_pk) = generate_hybrid_keypair();
            let (_, _, wrong_ml_pk) = generate_hybrid_keypair();
            let ed_pk = ed_key.public_key_bytes();

            let bundle = PublicKeyBundle {
                ed25519_public_key: Some(ed_pk),
                ml_dsa_65_public_key: Some(wrong_ml_pk),
                x25519_public_key: None,
                ml_kem_768_public_key: None,
            };
            let vk = VerificationKey::from_key_entry(
                KeyAlgorithm::Ed25519MlDsa65,
                &ed_pk,
                Some(&bundle),
            )
            .unwrap();

            let hash = [0xBBu8; 32];
            let (legacy_sig, sig_bundle) = hybrid_sign(&hash, &ed_key, &ml_seed);
            assert!(verify_with_key(
                &hash,
                SignatureScheme::Ed25519MlDsa65,
                &legacy_sig,
                Some(&sig_bundle),
                &vk,
            )
            .is_err());
        }

        #[test]
        fn strict_verify_with_key_roundtrip() {
            let mut ml_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ml_seed);
            let ml_pk = ml_dsa_65_public_key_from_seed(&ml_seed);

            let bundle = PublicKeyBundle {
                ed25519_public_key: None,
                ml_dsa_65_public_key: Some(ml_pk.clone()),
                x25519_public_key: None,
                ml_kem_768_public_key: None,
            };
            let vk =
                VerificationKey::from_key_entry(KeyAlgorithm::MlDsa65, &[0u8; 32], Some(&bundle))
                    .unwrap();

            let hash = [0xCCu8; 32];
            let sig_bundle = ParsedSignatureBundle {
                ed25519_signature: None,
                ml_dsa_65_signature: Some(sign_ml_dsa_65(&ml_seed, &hash).unwrap()),
            };

            assert!(
                verify_with_key(&hash, SignatureScheme::MlDsa65, &[], Some(&sig_bundle), &vk,)
                    .is_ok()
            );
        }

        #[test]
        fn strict_verify_wrong_key_fails() {
            let mut ml_seed1 = [0u8; 32];
            let mut ml_seed2 = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ml_seed1);
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ml_seed2);
            let wrong_pk = ml_dsa_65_public_key_from_seed(&ml_seed2);

            let bundle = PublicKeyBundle {
                ed25519_public_key: None,
                ml_dsa_65_public_key: Some(wrong_pk),
                x25519_public_key: None,
                ml_kem_768_public_key: None,
            };
            let vk =
                VerificationKey::from_key_entry(KeyAlgorithm::MlDsa65, &[0u8; 32], Some(&bundle))
                    .unwrap();

            let hash = [0xDDu8; 32];
            let sig_bundle = ParsedSignatureBundle {
                ed25519_signature: None,
                ml_dsa_65_signature: Some(sign_ml_dsa_65(&ml_seed1, &hash).unwrap()),
            };

            assert!(
                verify_with_key(&hash, SignatureScheme::MlDsa65, &[], Some(&sig_bundle), &vk,)
                    .is_err()
            );
        }

        #[test]
        fn hybrid_key_rejects_legacy_signature_scheme() {
            let (ed_key, _ml_seed, ml_pk) = generate_hybrid_keypair();
            let ed_pk = ed_key.public_key_bytes();
            let bundle = PublicKeyBundle {
                ed25519_public_key: Some(ed_pk),
                ml_dsa_65_public_key: Some(ml_pk),
                x25519_public_key: None,
                ml_kem_768_public_key: None,
            };
            let vk = VerificationKey::from_key_entry(
                KeyAlgorithm::Ed25519MlDsa65,
                &ed_pk,
                Some(&bundle),
            )
            .unwrap();

            // Sign with Ed25519 only (legacy scheme) — MUST be rejected
            // to prevent scheme downgrade attack
            let hash = [0xEEu8; 32];
            let ed_sig = ed_key.sign(&hash);

            assert!(
                verify_with_key(&hash, SignatureScheme::Ed25519, &ed_sig, None, &vk,).is_err(),
                "Hybrid key must reject legacy Ed25519-only signatures"
            );
        }

        #[test]
        fn strict_key_rejects_legacy_signature_scheme() {
            let mut ml_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ml_seed);
            let ml_pk = ml_dsa_65_public_key_from_seed(&ml_seed);

            let bundle = PublicKeyBundle {
                ed25519_public_key: None,
                ml_dsa_65_public_key: Some(ml_pk),
                x25519_public_key: None,
                ml_kem_768_public_key: None,
            };
            let vk =
                VerificationKey::from_key_entry(KeyAlgorithm::MlDsa65, &[0u8; 32], Some(&bundle))
                    .unwrap();

            // Strict key must reject Ed25519-only scheme
            let ed_key = AgentSigningKey::generate();
            let hash = [0xFFu8; 32];
            let ed_sig = ed_key.sign(&hash);

            assert!(
                verify_with_key(&hash, SignatureScheme::Ed25519, &ed_sig, None, &vk,).is_err(),
                "Strict key must reject Ed25519-only signatures"
            );
        }

        #[test]
        fn fixed_seed_public_key_is_deterministic() {
            let pk1 = ml_dsa_65_public_key_from_seed(&TEST_VECTOR_SIGNING_SEED);
            let pk2 = ml_dsa_65_public_key_from_seed(&TEST_VECTOR_SIGNING_SEED);
            assert_eq!(pk1, pk2);
            assert!(!pk1.is_empty());
        }

        #[test]
        fn fixed_seed_public_key_matches_known_vector_digest() {
            let public_key = ml_dsa_65_public_key_from_seed(&TEST_VECTOR_SIGNING_SEED);
            assert_eq!(public_key.len(), 1952);

            let digest = Sha256::digest(&public_key);
            assert_eq!(
                format!("0x{}", hex::encode(digest)),
                "0xe933697f7a3d671b8c294452465230d4d433d337afd25b99dba884175541a855"
            );
        }

        #[test]
        fn sequencer_signing_config_hybrid_receipt() {
            let ed_key = AgentSigningKey::generate();
            let mut ml_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ml_seed);

            let config = SequencerSigningConfig {
                ed25519_key: Some(ed_key),
                ml_dsa_65_seed: Some(ml_seed),
                receipt_scheme: SignatureScheme::Ed25519MlDsa65,
            };

            let hash = [0xFFu8; 32];
            let (scheme, legacy_sig, bundle) = config.sign_receipt(&hash).unwrap();
            assert_eq!(scheme, SignatureScheme::Ed25519MlDsa65);
            assert_eq!(legacy_sig.len(), 64);
            let bundle = bundle.expect("hybrid receipt should have bundle");
            assert!(bundle.ed25519_signature.is_some());
            assert!(bundle.ml_dsa_65_signature.is_some());
        }

        #[test]
        fn hybrid_pop_verification_roundtrip() {
            let (ed_key, ml_seed, ml_pk) = generate_hybrid_keypair();
            let ed_pk = ed_key.public_key_bytes();

            let bundle = PublicKeyBundle {
                ed25519_public_key: Some(ed_pk),
                ml_dsa_65_public_key: Some(ml_pk.clone()),
                x25519_public_key: None,
                ml_kem_768_public_key: None,
            };

            // Generate PoP: sign SHA-256("VES_POP_V1" || ed_pk || ml_pk)
            let mut pk_bytes = Vec::with_capacity(32 + ml_pk.len());
            pk_bytes.extend_from_slice(&ed_pk);
            pk_bytes.extend_from_slice(&ml_pk);
            let challenge = compute_pop_challenge(&pk_bytes);
            let (_, pop_bundle) = hybrid_sign(&challenge, &ed_key, &ml_seed);

            assert!(verify_proof_of_possession(
                KeyAlgorithm::Ed25519MlDsa65,
                &ed_pk,
                Some(&bundle),
                pop_bundle.ed25519_signature.as_ref().unwrap(),
                Some(&pop_bundle),
            )
            .is_ok());
        }
    }
}
