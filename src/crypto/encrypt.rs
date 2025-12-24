//! VES-ENC-1 Encrypted Payloads
//!
//! Per VES v1.0 Section 6, this module provides:
//! - AES-256-GCM content encryption with context-bound AAD
//! - HPKE key wrapping for recipients (X25519/HKDF-SHA256/AES-256-GCM)
//! - Deterministic ciphertext hash computation
//!
//! Key features:
//! - Sequencer can sequence and prove inclusion without decryption
//! - AAD binds ciphertext to event context (prevents substitution)
//! - Salted plaintext hash reduces guessability
//!
//! HPKE Configuration:
//! - Mode: Base (0x00)
//! - KEM: DHKEM(X25519, HKDF-SHA256) - 0x0020
//! - KDF: HKDF-SHA256 - 0x0001
//! - AEAD: AES-256-GCM - 0x0002

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR, OpModeS,
    Serializable,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::hash::{
    canonicalize_json, encode_string, payload_plain_hash_salted, u32_be, u64_be, Hash256,
    DOMAIN_PAYLOAD_AAD, DOMAIN_PAYLOAD_CIPHER, DOMAIN_RECIPIENTS,
};

/// Encryption key (32 bytes for AES-256)
pub type EncryptionKey = [u8; 32];

/// Nonce size for AES-GCM (12 bytes)
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size (16 bytes)
pub const TAG_SIZE: usize = 16;

/// Payload salt size (16 bytes)
pub const SALT_SIZE: usize = 16;

/// Error type for encryption operations
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("invalid ciphertext length")]
    InvalidCiphertext,

    #[error("invalid payload format")]
    InvalidPayloadFormat,

    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("HPKE error: {0}")]
    HpkeError(String),

    #[error("no recipients specified")]
    NoRecipients,

    #[error("recipient not found: {0}")]
    RecipientNotFound(u32),

    #[error("payload hash mismatch")]
    PayloadHashMismatch,
}

// ============================================================================
// Encrypted Payload Structure (VES v1.0 Section 7.2)
// ============================================================================

/// HPKE algorithm parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeParams {
    pub mode: String, // "base"
    pub kem: String,  // "X25519-HKDF-SHA256"
    pub kdf: String,  // "HKDF-SHA256"
    pub aead: String, // "AES-256-GCM"
}

impl Default for HpkeParams {
    fn default() -> Self {
        Self {
            mode: "base".to_string(),
            kem: "X25519-HKDF-SHA256".to_string(),
            kdf: "HKDF-SHA256".to_string(),
            aead: "AES-256-GCM".to_string(),
        }
    }
}

/// Recipient entry in encrypted payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    /// Recipient key ID in the registry
    pub recipient_kid: u32,

    /// HPKE encapsulated key (base64url encoded)
    pub enc_b64u: String,

    /// HPKE-encrypted DEK (base64url encoded)
    pub ct_b64u: String,
}

/// Encrypted payload structure per VES v1.0 Section 7.2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadEncrypted {
    /// Encryption version (must be 1)
    pub enc_version: u32,

    /// AEAD algorithm identifier
    pub aead: String,

    /// 12-byte nonce (base64url encoded)
    pub nonce_b64u: String,

    /// Encrypted payload (base64url encoded)
    pub ciphertext_b64u: String,

    /// 16-byte authentication tag (base64url encoded)
    pub tag_b64u: String,

    /// HPKE parameters
    pub hpke: HpkeParams,

    /// Recipient list (sorted by recipient_kid)
    pub recipients: Vec<Recipient>,
}

impl PayloadEncrypted {
    /// Decode nonce from base64url
    pub fn decode_nonce(&self) -> Result<[u8; NONCE_SIZE], EncryptionError> {
        let bytes = base64_url_decode(&self.nonce_b64u)?;
        bytes
            .try_into()
            .map_err(|_| EncryptionError::InvalidPayloadFormat)
    }

    /// Decode ciphertext from base64url
    pub fn decode_ciphertext(&self) -> Result<Vec<u8>, EncryptionError> {
        base64_url_decode(&self.ciphertext_b64u)
    }

    /// Decode tag from base64url
    pub fn decode_tag(&self) -> Result<[u8; TAG_SIZE], EncryptionError> {
        let bytes = base64_url_decode(&self.tag_b64u)?;
        bytes
            .try_into()
            .map_err(|_| EncryptionError::InvalidPayloadFormat)
    }
}

// ============================================================================
// Payload AAD Computation (VES v1.0 Section 6.2)
// ============================================================================

/// Parameters for computing payload AAD
pub struct PayloadAadParams<'a> {
    pub tenant_id: &'a Uuid,
    pub store_id: &'a Uuid,
    pub event_id: &'a Uuid,
    pub source_agent_id: &'a Uuid,
    pub agent_key_id: u32,
    pub entity_type: &'a str,
    pub entity_id: &'a str,
    pub event_type: &'a str,
    pub created_at: &'a str,
    pub payload_plain_hash: &'a Hash256,
}

/// Compute payload AAD per VES v1.0 Section 6.2
///
/// ```text
/// payload_aad_preimage =
///   b"VES_PAYLOAD_AAD_V1" ||
///   UUID(tenant_id) || UUID(store_id) || UUID(event_id) ||
///   UUID(source_agent_id) || U32_BE(agent_key_id) ||
///   ENC_STR(entity_type) || ENC_STR(entity_id) ||
///   ENC_STR(event_type) || ENC_STR(created_at) ||
///   payload_plain_hash(32)
///
/// payload_aad = SHA256(payload_aad_preimage)
/// ```
pub fn compute_payload_aad(params: &PayloadAadParams) -> Hash256 {
    let mut hasher = Sha256::new();

    hasher.update(DOMAIN_PAYLOAD_AAD);
    hasher.update(params.tenant_id.as_bytes());
    hasher.update(params.store_id.as_bytes());
    hasher.update(params.event_id.as_bytes());
    hasher.update(params.source_agent_id.as_bytes());
    hasher.update(u32_be(params.agent_key_id));
    hasher.update(encode_string(params.entity_type));
    hasher.update(encode_string(params.entity_id));
    hasher.update(encode_string(params.event_type));
    hasher.update(encode_string(params.created_at));
    hasher.update(params.payload_plain_hash);

    hasher.finalize().into()
}

// ============================================================================
// Recipients Hash Computation (VES v1.0 Section 6.4)
// ============================================================================

/// Compute recipients hash from sorted recipient list
///
/// ```text
/// RECIP_ENTRY(i) =
///   U32_BE(recipient_kid_i) ||
///   U32_BE(len(enc_i)) || enc_i ||
///   U32_BE(len(ct_i))  || ct_i
///
/// recipients_hash = SHA256(b"VES_RECIPIENTS_V1" || RECIP_ENTRY(0) || ... || RECIP_ENTRY(n-1))
/// ```
pub fn compute_recipients_hash(recipients: &[Recipient]) -> Result<Hash256, EncryptionError> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_RECIPIENTS);

    for recip in recipients {
        // Decode recipient data
        let enc = base64_url_decode(&recip.enc_b64u)?;
        let ct = base64_url_decode(&recip.ct_b64u)?;

        // RECIP_ENTRY encoding
        hasher.update(u32_be(recip.recipient_kid));
        hasher.update(u32_be(enc.len() as u32));
        hasher.update(&enc);
        hasher.update(u32_be(ct.len() as u32));
        hasher.update(&ct);
    }

    Ok(hasher.finalize().into())
}

// ============================================================================
// Ciphertext Hash (payload_cipher_hash) (VES v1.0 Section 6.5)
// ============================================================================

/// Compute payload_cipher_hash per VES v1.0 Section 6.5
///
/// ```text
/// cipher_preimage =
///   b"VES_PAYLOAD_CIPHER_V1" ||
///   U32_BE(1) ||                      // enc_version = 1
///   nonce(12) ||
///   payload_aad(32) ||
///   U32_BE(len(ciphertext)) || ciphertext ||
///   tag(16) ||
///   recipients_hash(32)
///
/// payload_cipher_hash = SHA256(cipher_preimage)
/// ```
pub fn compute_payload_cipher_hash(
    nonce: &[u8; NONCE_SIZE],
    payload_aad: &Hash256,
    ciphertext: &[u8],
    tag: &[u8; TAG_SIZE],
    recipients_hash: &Hash256,
) -> Hash256 {
    let mut hasher = Sha256::new();

    hasher.update(DOMAIN_PAYLOAD_CIPHER);
    hasher.update(u32_be(1)); // enc_version
    hasher.update(nonce);
    hasher.update(payload_aad);
    hasher.update(u32_be(ciphertext.len() as u32));
    hasher.update(ciphertext);
    hasher.update(tag);
    hasher.update(recipients_hash);

    hasher.finalize().into()
}

/// Compute payload_cipher_hash from PayloadEncrypted structure
pub fn compute_cipher_hash_from_encrypted(
    encrypted: &PayloadEncrypted,
    payload_aad: &Hash256,
) -> Result<Hash256, EncryptionError> {
    let nonce = encrypted.decode_nonce()?;
    let ciphertext = encrypted.decode_ciphertext()?;
    let tag = encrypted.decode_tag()?;
    let recipients_hash = compute_recipients_hash(&encrypted.recipients)?;

    Ok(compute_payload_cipher_hash(
        &nonce,
        payload_aad,
        &ciphertext,
        &tag,
        &recipients_hash,
    ))
}

// ============================================================================
// VES-ENC-1 Encryption/Decryption
// ============================================================================

/// Encryption result containing all computed values
pub struct EncryptionResult {
    /// The encrypted payload structure
    pub payload_encrypted: PayloadEncrypted,

    /// The 16-byte salt used in plaintext hashing
    pub payload_salt: [u8; SALT_SIZE],

    /// Hash of salted plaintext
    pub payload_plain_hash: Hash256,

    /// Hash of ciphertext bundle
    pub payload_cipher_hash: Hash256,
}

/// Encrypt a payload per VES-ENC-1
///
/// This function:
/// 1. Generates a random salt and computes payload_plain_hash
/// 2. Generates a random DEK and nonce
/// 3. Computes AAD from event context
/// 4. Encrypts salt || JCS(payload) with AES-256-GCM
/// 5. Wraps DEK for each recipient (simplified - real impl needs HPKE)
/// 6. Computes payload_cipher_hash
pub fn encrypt_payload_ves(
    payload: &serde_json::Value,
    aad_params: &PayloadAadParams,
    recipient_keys: &[(u32, &[u8; 32])], // (kid, X25519 public key)
) -> Result<EncryptionResult, EncryptionError> {
    if recipient_keys.is_empty() {
        return Err(EncryptionError::NoRecipients);
    }

    // Generate random salt
    let mut payload_salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut payload_salt);

    // Compute payload_plain_hash (salted)
    let payload_plain_hash = payload_plain_hash_salted(payload, &payload_salt);

    // Build AAD params with computed hash
    let aad_params_with_hash = PayloadAadParams {
        tenant_id: aad_params.tenant_id,
        store_id: aad_params.store_id,
        event_id: aad_params.event_id,
        source_agent_id: aad_params.source_agent_id,
        agent_key_id: aad_params.agent_key_id,
        entity_type: aad_params.entity_type,
        entity_id: aad_params.entity_id,
        event_type: aad_params.event_type,
        created_at: aad_params.created_at,
        payload_plain_hash: &payload_plain_hash,
    };

    // Compute AAD
    let payload_aad = compute_payload_aad(&aad_params_with_hash);

    // Generate DEK
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);

    // Generate nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Prepare plaintext: salt || JCS(payload)
    let canonical_payload = canonicalize_json(payload);
    let mut plaintext = Vec::with_capacity(SALT_SIZE + canonical_payload.len());
    plaintext.extend_from_slice(&payload_salt);
    plaintext.extend_from_slice(canonical_payload.as_bytes());

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&dek)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: &payload_aad,
            },
        )
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    // Split ciphertext and tag
    let tag_start = ciphertext_with_tag.len() - TAG_SIZE;
    let ciphertext = &ciphertext_with_tag[..tag_start];
    let tag: [u8; TAG_SIZE] = ciphertext_with_tag[tag_start..].try_into().unwrap();

    // Wrap DEK for each recipient using HPKE (X25519/HKDF-SHA256/AES-256-GCM)
    let mut recipients = Vec::with_capacity(recipient_keys.len());
    for (kid, public_key) in recipient_keys {
        let (enc, ct) = wrap_dek_hpke(&dek, public_key, &payload_aad)?;
        recipients.push(Recipient {
            recipient_kid: *kid,
            enc_b64u: base64_url_encode(&enc),
            ct_b64u: base64_url_encode(&ct),
        });
    }

    // Sort recipients by kid
    recipients.sort_by_key(|r| r.recipient_kid);

    // Compute recipients hash
    let recipients_hash = compute_recipients_hash(&recipients)?;

    // Compute payload_cipher_hash
    let payload_cipher_hash = compute_payload_cipher_hash(
        &nonce_bytes,
        &payload_aad,
        ciphertext,
        &tag,
        &recipients_hash,
    );

    // Build PayloadEncrypted
    let payload_encrypted = PayloadEncrypted {
        enc_version: 1,
        aead: "AES-256-GCM".to_string(),
        nonce_b64u: base64_url_encode(&nonce_bytes),
        ciphertext_b64u: base64_url_encode(ciphertext),
        tag_b64u: base64_url_encode(&tag),
        hpke: HpkeParams::default(),
        recipients,
    };

    Ok(EncryptionResult {
        payload_encrypted,
        payload_salt,
        payload_plain_hash,
        payload_cipher_hash,
    })
}

/// Decrypt a VES-ENC-1 payload
///
/// This function:
/// 1. Unwraps DEK using recipient's private key
/// 2. Decrypts ciphertext with AES-256-GCM and AAD
/// 3. Extracts salt and plaintext
/// 4. Verifies payload_plain_hash matches
pub fn decrypt_payload_ves(
    payload_encrypted: &PayloadEncrypted,
    payload_aad: &Hash256,
    recipient_kid: u32,
    recipient_private_key: &[u8; 32],
    expected_plain_hash: &Hash256,
) -> Result<serde_json::Value, EncryptionError> {
    // Find recipient entry
    let recip = payload_encrypted
        .recipients
        .iter()
        .find(|r| r.recipient_kid == recipient_kid)
        .ok_or(EncryptionError::RecipientNotFound(recipient_kid))?;

    // Unwrap DEK using HPKE
    let enc = base64_url_decode(&recip.enc_b64u)?;
    let ct = base64_url_decode(&recip.ct_b64u)?;
    let dek = unwrap_dek_hpke(&enc, &ct, recipient_private_key, payload_aad)?;

    // Decode encrypted payload components
    let nonce_bytes = payload_encrypted.decode_nonce()?;
    let ciphertext = payload_encrypted.decode_ciphertext()?;
    let tag = payload_encrypted.decode_tag()?;

    // Reconstruct ciphertext + tag for decryption
    let mut ciphertext_with_tag = ciphertext.clone();
    ciphertext_with_tag.extend_from_slice(&tag);

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&dek)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &ciphertext_with_tag,
                aad: payload_aad,
            },
        )
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

    // Extract salt and JSON
    if plaintext.len() < SALT_SIZE {
        return Err(EncryptionError::InvalidPayloadFormat);
    }
    let salt: [u8; SALT_SIZE] = plaintext[..SALT_SIZE].try_into().unwrap();
    let json_bytes = &plaintext[SALT_SIZE..];

    // Parse JSON
    let payload: serde_json::Value = serde_json::from_slice(json_bytes)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

    // Verify payload_plain_hash
    let computed_hash = payload_plain_hash_salted(&payload, &salt);
    if computed_hash != *expected_plain_hash {
        return Err(EncryptionError::PayloadHashMismatch);
    }

    Ok(payload)
}

// ============================================================================
// HPKE Key Wrapping (VES v1.0 compliant)
// ============================================================================

/// HPKE type aliases for clarity
type HpkeKem = X25519HkdfSha256;
type HpkeKdf = HkdfSha256;
type HpkeAead = AesGcm256;

/// HPKE recipient public key (32 bytes for X25519)
pub type HpkePublicKey = [u8; 32];

/// HPKE recipient private key (32 bytes for X25519)
pub type HpkePrivateKey = [u8; 32];

/// HPKE encapsulated key size (32 bytes for X25519)
pub const HPKE_ENC_SIZE: usize = 32;

/// Wrap DEK for a recipient using HPKE Base mode
///
/// Uses DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM
///
/// Parameters:
/// - `dek`: Data encryption key to wrap (32 bytes)
/// - `recipient_public_key`: Recipient's X25519 public key (32 bytes)
/// - `info`: Context info binding (e.g., payload_aad hash)
///
/// Returns: (enc, ct) where:
/// - `enc`: HPKE encapsulated key (32 bytes)
/// - `ct`: Wrapped DEK ciphertext (32 + 16 = 48 bytes with GCM tag)
fn wrap_dek_hpke(
    dek: &[u8; 32],
    recipient_public_key: &HpkePublicKey,
    info: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    // Parse recipient public key
    let pk = <HpkeKem as Kem>::PublicKey::from_bytes(recipient_public_key).map_err(|e| {
        EncryptionError::HpkeError(format!("invalid recipient public key: {:?}", e))
    })?;

    // Setup HPKE sender context with Base mode
    let (enc, mut sender_ctx) =
        hpke::setup_sender::<HpkeAead, HpkeKdf, HpkeKem, _>(&OpModeS::Base, &pk, info, &mut OsRng)
            .map_err(|e| EncryptionError::HpkeError(format!("HPKE setup failed: {:?}", e)))?;

    // Seal (encrypt) the DEK with empty associated data
    // The `info` parameter already provides binding; AAD here is optional
    let ct = sender_ctx
        .seal(dek, b"")
        .map_err(|e| EncryptionError::HpkeError(format!("HPKE seal failed: {:?}", e)))?;

    Ok((enc.to_bytes().to_vec(), ct))
}

/// Unwrap DEK using recipient's private key
///
/// Parameters:
/// - `enc`: HPKE encapsulated key from sender
/// - `ct`: Wrapped DEK ciphertext
/// - `recipient_private_key`: Recipient's X25519 private key
/// - `info`: Same context info used during wrapping
///
/// Returns: Unwrapped DEK (32 bytes)
fn unwrap_dek_hpke(
    enc: &[u8],
    ct: &[u8],
    recipient_private_key: &HpkePrivateKey,
    info: &[u8; 32],
) -> Result<[u8; 32], EncryptionError> {
    // Validate enc size
    if enc.len() != HPKE_ENC_SIZE {
        return Err(EncryptionError::HpkeError(format!(
            "invalid enc size: expected {}, got {}",
            HPKE_ENC_SIZE,
            enc.len()
        )));
    }

    // Parse encapsulated key
    let enc_key = <HpkeKem as Kem>::EncappedKey::from_bytes(enc)
        .map_err(|e| EncryptionError::HpkeError(format!("invalid encapped key: {:?}", e)))?;

    // Parse recipient private key
    let sk = <HpkeKem as Kem>::PrivateKey::from_bytes(recipient_private_key).map_err(|e| {
        EncryptionError::HpkeError(format!("invalid recipient private key: {:?}", e))
    })?;

    // Setup HPKE receiver context
    let mut receiver_ctx =
        hpke::setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeR::Base, &sk, &enc_key, info)
            .map_err(|e| {
                EncryptionError::HpkeError(format!("HPKE receiver setup failed: {:?}", e))
            })?;

    // Open (decrypt) the wrapped DEK
    let dek_bytes = receiver_ctx
        .open(ct, b"")
        .map_err(|e| EncryptionError::HpkeError(format!("HPKE open failed: {:?}", e)))?;

    // Convert to fixed-size array
    if dek_bytes.len() != 32 {
        return Err(EncryptionError::HpkeError(format!(
            "invalid DEK size: expected 32, got {}",
            dek_bytes.len()
        )));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);
    Ok(dek)
}

/// Generate a new HPKE key pair for a recipient
///
/// Returns: (private_key, public_key)
pub fn generate_hpke_keypair() -> (HpkePrivateKey, HpkePublicKey) {
    let (sk, pk) = HpkeKem::gen_keypair(&mut OsRng);

    let mut private_key = [0u8; 32];
    let mut public_key = [0u8; 32];

    private_key.copy_from_slice(&sk.to_bytes());
    public_key.copy_from_slice(&pk.to_bytes());

    (private_key, public_key)
}

/// Derive HPKE public key from private key
pub fn derive_hpke_public_key(
    private_key: &HpkePrivateKey,
) -> Result<HpkePublicKey, EncryptionError> {
    let sk = <HpkeKem as Kem>::PrivateKey::from_bytes(private_key)
        .map_err(|e| EncryptionError::HpkeError(format!("invalid private key: {:?}", e)))?;

    let pk = HpkeKem::sk_to_pk(&sk);

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&pk.to_bytes());
    Ok(public_key)
}

// ============================================================================
// Base64url Encoding/Decoding
// ============================================================================

/// Encode bytes as base64url without padding
pub fn base64_url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

/// Decode base64url (with or without padding)
pub fn base64_url_decode(s: &str) -> Result<Vec<u8>, EncryptionError> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s)
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, s))
        .map_err(|_| EncryptionError::InvalidPayloadFormat)
}

// ============================================================================
// Payload Encryption-at-Rest (StateSet)
// ============================================================================

/// Domain prefix for StateSet payload AAD (encryption-at-rest).
pub const DOMAIN_STATESET_PAYLOAD_ATREST_AAD_V1: &[u8] = b"STATESET_PAYLOAD_ATREST_AAD_V1";

/// Domain prefix for StateSet VES validity proof AAD (encryption-at-rest).
pub const DOMAIN_STATESET_VES_VALIDITY_PROOF_ATREST_AAD_V1: &[u8] =
    b"STATESET_VES_VALIDITY_PROOF_ATREST_AAD_V1";

/// Domain prefix for StateSet VES compliance proof AAD (encryption-at-rest).
pub const DOMAIN_STATESET_VES_COMPLIANCE_PROOF_ATREST_AAD_V1: &[u8] =
    b"STATESET_VES_COMPLIANCE_PROOF_ATREST_AAD_V1";

/// Magic prefix for encrypted payload blobs (encryption-at-rest v1).
pub const STATESET_ATREST_MAGIC_V1: &[u8; 4] = b"SSE1";

/// Compute encryption-at-rest AAD bound to immutable event metadata.
pub fn compute_payload_at_rest_aad(
    tenant_id: &Uuid,
    store_id: &Uuid,
    event_id: &Uuid,
    sequence_number: u64,
    entity_type: &str,
    entity_id: &str,
    event_type: &str,
) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_STATESET_PAYLOAD_ATREST_AAD_V1);
    hasher.update(tenant_id.as_bytes());
    hasher.update(store_id.as_bytes());
    hasher.update(event_id.as_bytes());
    hasher.update(u64_be(sequence_number));
    hasher.update(encode_string(entity_type));
    hasher.update(encode_string(entity_id));
    hasher.update(encode_string(event_type));
    hasher.finalize().into()
}

/// Compute encryption-at-rest AAD for a VES validity proof row.
pub fn compute_ves_validity_proof_at_rest_aad(
    tenant_id: &Uuid,
    store_id: &Uuid,
    batch_id: &Uuid,
    proof_id: &Uuid,
    proof_type: &str,
    proof_version: u32,
    proof_hash: &Hash256,
) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_STATESET_VES_VALIDITY_PROOF_ATREST_AAD_V1);
    hasher.update(tenant_id.as_bytes());
    hasher.update(store_id.as_bytes());
    hasher.update(batch_id.as_bytes());
    hasher.update(proof_id.as_bytes());
    hasher.update(u32_be(proof_version));
    hasher.update(encode_string(proof_type));
    hasher.update(proof_hash);
    hasher.finalize().into()
}

/// Parameters for computing compliance proof encryption-at-rest AAD.
pub struct ComplianceProofAadParams<'a> {
    pub tenant_id: &'a Uuid,
    pub store_id: &'a Uuid,
    pub event_id: &'a Uuid,
    pub proof_id: &'a Uuid,
    pub policy_hash: &'a Hash256,
    pub proof_type: &'a str,
    pub proof_version: u32,
    pub proof_hash: &'a Hash256,
}

/// Compute encryption-at-rest AAD for a VES compliance proof row.
pub fn compute_ves_compliance_proof_at_rest_aad(params: &ComplianceProofAadParams<'_>) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_STATESET_VES_COMPLIANCE_PROOF_ATREST_AAD_V1);
    hasher.update(params.tenant_id.as_bytes());
    hasher.update(params.store_id.as_bytes());
    hasher.update(params.event_id.as_bytes());
    hasher.update(params.proof_id.as_bytes());
    hasher.update(params.policy_hash);
    hasher.update(u32_be(params.proof_version));
    hasher.update(encode_string(params.proof_type));
    hasher.update(params.proof_hash);
    hasher.finalize().into()
}

pub fn is_payload_at_rest_encrypted(data: &[u8]) -> bool {
    data.len() >= STATESET_ATREST_MAGIC_V1.len()
        && &data[..STATESET_ATREST_MAGIC_V1.len()] == STATESET_ATREST_MAGIC_V1
}

/// Encrypt bytes for storage at rest.
///
/// Output format: `STATESET_ATREST_MAGIC_V1 || nonce(12) || ciphertext_with_tag`.
pub fn encrypt_payload_at_rest(
    key: &EncryptionKey,
    aad: &Hash256,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    let mut result =
        Vec::with_capacity(STATESET_ATREST_MAGIC_V1.len() + NONCE_SIZE + ciphertext_with_tag.len());
    result.extend_from_slice(STATESET_ATREST_MAGIC_V1);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext_with_tag);
    Ok(result)
}

pub fn decrypt_payload_at_rest(
    key: &EncryptionKey,
    aad: &Hash256,
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let header_len = STATESET_ATREST_MAGIC_V1.len() + NONCE_SIZE;
    if ciphertext.len() < header_len + TAG_SIZE {
        return Err(EncryptionError::InvalidCiphertext);
    }
    if !is_payload_at_rest_encrypted(ciphertext) {
        return Err(EncryptionError::InvalidPayloadFormat);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

    let nonce_start = STATESET_ATREST_MAGIC_V1.len();
    let nonce_end = nonce_start + NONCE_SIZE;
    let nonce = Nonce::from_slice(&ciphertext[nonce_start..nonce_end]);
    let actual_ciphertext = &ciphertext[nonce_end..];

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: actual_ciphertext,
                aad,
            },
        )
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

// ============================================================================
// Legacy Functions (for backward compatibility)
// ============================================================================

/// Simple payload encryption (no AAD, no HPKE)
/// Use encrypt_payload_ves() for VES-compliant encryption
pub fn encrypt_payload(key: &EncryptionKey, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Simple payload decryption (no AAD)
/// Use decrypt_payload_ves() for VES-compliant decryption
pub fn decrypt_payload(key: &EncryptionKey, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(EncryptionError::InvalidCiphertext);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
    let actual_ciphertext = &ciphertext[NONCE_SIZE..];

    cipher
        .decrypt(nonce, actual_ciphertext)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

/// Generate a new random encryption key
pub fn generate_key() -> EncryptionKey {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Key manager trait for tenant key management
#[async_trait::async_trait]
pub trait KeyManager: Send + Sync {
    /// Return a keyring (current key first) for the given tenant.
    async fn get_tenant_keys(
        &self,
        tenant_id: &Uuid,
    ) -> Result<Vec<EncryptionKey>, EncryptionError>;
    async fn rotate_tenant_key(&self, tenant_id: &Uuid) -> Result<EncryptionKey, EncryptionError>;
}

/// In-memory key manager for development
pub struct InMemoryKeyManager {
    keys: std::sync::RwLock<std::collections::HashMap<Uuid, Vec<EncryptionKey>>>,
    default_keys: Vec<EncryptionKey>,
}

impl InMemoryKeyManager {
    pub fn new() -> Self {
        let default_key = generate_key();
        Self {
            keys: std::sync::RwLock::new(std::collections::HashMap::new()),
            default_keys: vec![default_key],
        }
    }
}

impl Default for InMemoryKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Static key manager for deployments that use one key for all tenants.
pub struct StaticKeyManager {
    key: EncryptionKey,
}

impl StaticKeyManager {
    pub fn new(key: EncryptionKey) -> Self {
        Self { key }
    }
}

#[async_trait::async_trait]
impl KeyManager for InMemoryKeyManager {
    async fn get_tenant_keys(
        &self,
        tenant_id: &Uuid,
    ) -> Result<Vec<EncryptionKey>, EncryptionError> {
        let keys = self.keys.read().unwrap();
        Ok(keys
            .get(tenant_id)
            .cloned()
            .unwrap_or_else(|| self.default_keys.clone()))
    }

    async fn rotate_tenant_key(&self, tenant_id: &Uuid) -> Result<EncryptionKey, EncryptionError> {
        let new_key = generate_key();
        let mut keys = self.keys.write().unwrap();
        let entry = keys.entry(*tenant_id).or_default();
        entry.insert(0, new_key);
        Ok(new_key)
    }
}

#[async_trait::async_trait]
impl KeyManager for StaticKeyManager {
    async fn get_tenant_keys(
        &self,
        _tenant_id: &Uuid,
    ) -> Result<Vec<EncryptionKey>, EncryptionError> {
        Ok(vec![self.key])
    }

    async fn rotate_tenant_key(&self, _tenant_id: &Uuid) -> Result<EncryptionKey, EncryptionError> {
        Ok(self.key)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_base64url_roundtrip() {
        let data = [0u8, 1, 2, 255, 254, 253];
        let encoded = base64_url_encode(&data);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_payload_aad_deterministic() {
        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let event = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let plain_hash = [0u8; 32];

        let params = PayloadAadParams {
            tenant_id: &tenant,
            store_id: &store,
            event_id: &event,
            source_agent_id: &agent,
            agent_key_id: 1,
            entity_type: "order",
            entity_id: "order-123",
            event_type: "order.created",
            created_at: "2025-12-20T18:31:22.123Z",
            payload_plain_hash: &plain_hash,
        };

        let aad1 = compute_payload_aad(&params);
        let aad2 = compute_payload_aad(&params);
        assert_eq!(aad1, aad2);
    }

    #[test]
    fn test_recipients_hash_sorted() {
        let recipients = vec![
            Recipient {
                recipient_kid: 2,
                enc_b64u: base64_url_encode(&[1u8; 32]),
                ct_b64u: base64_url_encode(&[2u8; 32]),
            },
            Recipient {
                recipient_kid: 1,
                enc_b64u: base64_url_encode(&[3u8; 32]),
                ct_b64u: base64_url_encode(&[4u8; 32]),
            },
        ];

        // Should compute hash based on order provided (caller should sort)
        let hash = compute_recipients_hash(&recipients).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_ves_roundtrip() {
        let payload = json!({
            "item": "widget",
            "quantity": 10
        });

        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let event = Uuid::new_v4();
        let agent = Uuid::new_v4();

        // Use a dummy hash for AAD params (will be computed inside encrypt)
        let dummy_hash = [0u8; 32];
        let aad_params = PayloadAadParams {
            tenant_id: &tenant,
            store_id: &store,
            event_id: &event,
            source_agent_id: &agent,
            agent_key_id: 1,
            entity_type: "inventory",
            entity_id: "inv-001",
            event_type: "inventory.adjusted",
            created_at: "2025-12-20T18:31:22.123Z",
            payload_plain_hash: &dummy_hash,
        };

        // Generate recipient keys using proper HPKE keypair
        let (recipient_sk, recipient_pk) = generate_hpke_keypair();

        let recipient_keys = vec![(1u32, &recipient_pk)];

        // Encrypt
        let result = encrypt_payload_ves(&payload, &aad_params, &recipient_keys).unwrap();

        // Verify hashes are non-zero
        assert_ne!(result.payload_plain_hash, [0u8; 32]);
        assert_ne!(result.payload_cipher_hash, [0u8; 32]);

        // Compute AAD with actual plain hash for decryption
        let aad_params_decrypt = PayloadAadParams {
            payload_plain_hash: &result.payload_plain_hash,
            ..aad_params
        };
        let payload_aad = compute_payload_aad(&aad_params_decrypt);

        // Decrypt
        let decrypted = decrypt_payload_ves(
            &result.payload_encrypted,
            &payload_aad,
            1,
            &recipient_sk,
            &result.payload_plain_hash,
        )
        .unwrap();

        assert_eq!(payload, decrypted);
    }

    #[test]
    fn test_legacy_encrypt_decrypt() {
        let key = generate_key();
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt_payload(&key, plaintext).unwrap();
        let decrypted = decrypt_payload(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_at_rest_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let event_id = Uuid::new_v4();

        let aad = compute_payload_at_rest_aad(
            &tenant,
            &store,
            &event_id,
            42,
            "order",
            "order-123",
            "order.created",
        );

        let plaintext = br#"{"hello":"world"}"#;
        let ciphertext = encrypt_payload_at_rest(&key, &aad, plaintext).unwrap();
        assert!(is_payload_at_rest_encrypted(&ciphertext));

        let decrypted = decrypt_payload_at_rest(&key, &aad, &ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        let wrong_aad = [1u8; 32];
        assert!(decrypt_payload_at_rest(&key, &wrong_aad, &ciphertext).is_err());
    }
}
